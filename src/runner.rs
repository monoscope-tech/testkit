//! Executes items across surfaces: sessions, observation windows, guard, claims and step reports.
use crate::base_request::{
    header_map_to_hashmap, report_error, typed_assert, Assert, AssertionError, RequestAndResponse,
    ResponseObject,
};
use crate::browser::{loc_json, merge, response_parts, url_match, Chrome, Req, Route, Tab};
use crate::expr::eval::{self, key, render, test, to_str, Ctx};
use crate::expr::parse::{args, template, Args};
use crate::expr::*;
use crate::item::{parse_yaml, scalar_text, Item, HTTP};
use crate::term::{self, Pty};
use anyhow::{anyhow, bail, Result};
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct Config {
    pub base_url: Option<String>,
    pub headed: bool,
    pub action_ms: u64,
    pub expect_ms: u64,
    pub nav_ms: u64,
    pub fail_on: Vec<String>,
    pub ignore: Vec<String>,
    pub update_golden: bool,
    pub update_baselines: bool,
    pub frames: bool,
    pub should_log: bool,
    pub col_id: Option<String>,
    pub deterministic: bool,
    pub attach: Option<String>,
    pub secrets: Vec<String>,
}
impl Default for Config {
    fn default() -> Self {
        Config {
            base_url: None,
            headed: false,
            action_ms: 5000,
            expect_ms: 5000,
            nav_ms: 15000,
            fail_on: vec!["page errors".into(), "console errors".into()],
            ignore: vec![],
            update_golden: false,
            update_baselines: false,
            frames: false,
            should_log: false,
            col_id: None,
            deterministic: false,
            attach: None,
            secrets: vec![],
        }
    }
}

#[derive(Debug, Default, Serialize, Clone)]
pub struct StepResult {
    pub step_name: Option<String>,
    pub step_index: u32,
    pub assert_results: Vec<Result<bool, AssertionError>>,
    pub request: RequestAndResponse,
    pub step_log: String,
    pub step_error: Option<String>,
    pub verb: String,
    pub text: String,
    pub file: String,
    pub line: usize,
    pub status: String,
    pub ms: u64,
    pub claim: Option<usize>,
    pub report: Value,
    pub it: Value,
    #[serde(skip)]
    pub frame: Option<Vec<u8>>,
}
impl StepResult {
    pub fn ok(&self) -> bool {
        self.status != "fail"
    }
    pub fn line_text(&self) -> String {
        if self.text.is_empty() {
            self.verb.clone()
        } else {
            format!("{} {}", self.verb, self.text)
        }
    }
}

#[derive(Debug, Default, Serialize, Clone)]
pub struct Claim {
    pub title: String,
    pub status: String,
    pub line: usize,
    pub independent: bool,
    pub steps: Vec<usize>,
    pub evidence: Vec<String>,
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Surf {
    Http,
    Browser,
    Term,
}

#[derive(Clone, Default, Debug)]
struct Marks {
    tabs: HashMap<String, (usize, usize)>,
    api: usize,
    ptys: HashMap<String, usize>,
}

/// Called after every step (live reporting).
pub type OnStep = Box<dyn FnMut(&StepResult) + Send>;

pub struct Runner {
    pub cfg: Config,
    pub vars: Map<String, Value>,
    pub it: Value,
    legacy: Option<Value>,
    last_http: Value,
    pub file: String,
    pub dir: PathBuf,
    chrome: Option<Chrome>,
    pub tabs: BTreeMap<String, Tab>,
    pub ptys: BTreeMap<String, Pty>,
    pub cur_b: String,
    pub cur_t: Option<String>,
    pub last: Surf,
    routes: Vec<Route>,
    front: String,
    api_reqs: Vec<Req>,
    prev: Marks,
    cur: Marks,
    pub claims: Vec<Claim>,
    pub results: Vec<StepResult>,
    step_no: u32,
    pub baselines: Map<String, Value>,
    known_pages: Vec<String>,
    depth: usize,
    pub on_step: Option<OnStep>,
    trace_buf: Option<std::sync::Arc<std::sync::Mutex<Vec<Value>>>>,
}

const BROWSER_VERBS: &[&str] = &[
    "visit", "click", "dblclick", "hover", "check", "uncheck", "tap", "focus", "fill", "select",
    "upload", "drag", "route", "unroute", "trace", "profile", "heap", "throttle", "network",
    "emulate", "back", "reload",
];
/// Steps that observe without acting; they don't move the "since the last action" window.
const PASSIVE: &[&str] =
    &["expect", "wait", "extract", "snapshot", "shot", "mark", "claim", "meta"];
const TERM_VERBS: &[&str] = &["exec", "spawn", "enter", "signal", "resize"];

fn fail(msg: impl Into<String>) -> anyhow::Error {
    anyhow!(msg.into())
}
fn dur(v: &Value) -> Option<u64> {
    match v {
        Value::Number(n) => n.as_f64().map(|s| (s * 1000.0) as u64),
        Value::String(s) => crate::expr::parse::value(s).ok().and_then(|e| {
            if let Expr::Lit(v) = e {
                v.as_f64().map(|f| f as u64)
            } else {
                None
            }
        }),
        _ => None,
    }
}

impl Runner {
    pub fn new(cfg: Config) -> Self {
        Runner {
            cfg,
            vars: Map::new(),
            it: Value::Null,
            legacy: None,
            last_http: Value::Null,
            file: "inline".into(),
            dir: PathBuf::from("."),
            chrome: None,
            tabs: BTreeMap::new(),
            ptys: BTreeMap::new(),
            cur_b: "default".into(),
            cur_t: None,
            last: Surf::Http,
            routes: vec![],
            front: "default".into(),
            api_reqs: vec![],
            prev: Marks::default(),
            cur: Marks::default(),
            claims: vec![],
            results: vec![],
            step_no: 0,
            baselines: Map::new(),
            known_pages: vec![],
            depth: 0,
            on_step: None,
            trace_buf: None,
        }
    }

    pub async fn run_file(&mut self, path: &std::path::Path) -> Result<Vec<StepResult>> {
        let src = std::fs::read_to_string(path)
            .map_err(|e| anyhow!("cannot read {}: {e}", path.display()))?;
        self.dir = path.parent().map(|p| p.to_path_buf()).unwrap_or_default();
        self.run_src(&path.to_string_lossy(), &src).await
    }
    pub async fn run_src(&mut self, file: &str, src: &str) -> Result<Vec<StepResult>> {
        self.file = file.into();
        let items = parse_yaml(src).map_err(|e| anyhow!("{file}: {e}"))?;
        Ok(self.run_items(&items).await)
    }

    /// Runs items with claim semantics (spec §10): setup, fail-fast per claim, `independent` re-runs setup.
    pub async fn run_items(&mut self, items: &[Item]) -> Vec<StepResult> {
        let start = self.results.len();
        let mut setup: Vec<Item> = vec![];
        let (mut in_claim, mut halted, mut claim_failed) = (false, false, false);
        let mut setup_failed = false;
        for item in items {
            if item.verb == "meta" {
                self.apply_meta(&item.raw);
                continue;
            }
            if item.verb == "claim" || item.opts.claim.is_some() {
                let title = item.opts.claim.clone().unwrap_or_else(|| item.text.clone());
                let independent = item.opts.independent.unwrap_or(false);
                if in_claim {
                    self.close_claim()
                }
                let skip = setup_failed || (claim_failed && !independent);
                if claim_failed && independent && !setup_failed {
                    for s in setup.clone() {
                        self.run_one(&s).await;
                    }
                }
                self.claims.push(Claim {
                    title,
                    status: if skip { "skip".into() } else { "pass".into() },
                    line: item.line,
                    independent,
                    steps: vec![],
                    evidence: item.opts.evidence.clone().unwrap_or_default(),
                });
                in_claim = true;
                halted = skip;
                if item.verb == "claim" {
                    continue;
                }
            }
            if halted {
                let r = StepResult {
                    verb: item.verb.clone(),
                    text: item.text.clone(),
                    file: self.file.clone(),
                    line: item.line,
                    status: "skip".into(),
                    step_name: item.opts.title.clone(),
                    claim: in_claim.then(|| self.claims.len() - 1),
                    ..Default::default()
                };
                self.push(r);
                continue;
            }
            if !in_claim && self.depth == 0 {
                setup.push(item.clone())
            }
            let ok = self.run_one(item).await;
            if !ok {
                let soft = HTTP.contains(&item.verb.as_str())
                    || item.opts.asserts.is_some() && item.verb != "expect";
                if in_claim {
                    claim_failed = true;
                    if let Some(c) = self.claims.last_mut() {
                        c.status = "fail".into()
                    }
                    halted = !soft;
                } else if !soft {
                    halted = true;
                    setup_failed = self.depth == 0;
                }
            }
        }
        if in_claim {
            self.close_claim()
        }
        if setup_failed {
            self.claims.iter_mut().for_each(|c| {
                if c.status == "pass" && c.steps.is_empty() {
                    c.status = "skip".into()
                }
            })
        }
        self.results[start..].to_vec()
    }
    fn close_claim(&mut self) {
        let res = &self.results;
        if let Some(c) = self.claims.last_mut() {
            if c.status == "pass" && c.steps.iter().any(|&i| res[i].status == "fail") {
                c.status = "fail".into()
            }
        }
    }
    fn push(&mut self, mut r: StepResult) {
        r.step_index = self.results.len() as u32;
        if let Some(c) = r.claim.and_then(|i| self.claims.get_mut(i)) {
            c.steps.push(self.results.len())
        }
        if let Some(cb) = self.on_step.as_mut() {
            cb(&r)
        }
        self.results.push(r);
    }

    /// Runs one item (with iterations); returns whether it passed.
    pub async fn run_one(&mut self, item: &Item) -> bool {
        let iters: Vec<Map<String, Value>> = match &item.opts.iterations {
            Some(Value::Array(a)) => {
                a.iter().map(|v| v.as_object().cloned().unwrap_or_default()).collect()
            }
            Some(Value::Number(n)) => (0..n.as_u64().unwrap_or(1))
                .map(|i| Map::from_iter([("iteration".to_string(), json!(i))]))
                .collect(),
            _ => vec![Map::new()],
        };
        let mut ok = true;
        let heap0 = if item.opts.measure.as_ref().and_then(Value::as_str) == Some("heap") {
            self.heap().await.ok()
        } else {
            None
        };
        for (i, it) in iters.iter().enumerate() {
            self.vars.extend(it.clone());
            let mut r = self.step(item).await;
            if iters.len() > 1 {
                r.step_name = Some(format!(
                    "{} (iteration {})",
                    r.step_name.clone().unwrap_or_else(|| r.line_text()),
                    i + 1
                ))
            }
            ok &= r.ok();
            self.push(r);
        }
        if let Some(h0) = heap0 {
            if let Ok(h1) = self.heap().await {
                self.it = json!({"heap_before": h0, "heap_after": h1, "heap_growth": h1 - h0})
            }
        }
        ok
    }

    fn apply_meta(&mut self, raw: &Value) {
        let Some(m) = raw.as_object() else { return };
        for (k, v) in m {
            match k.as_str() {
                "base_url" => {
                    self.vars.insert("base_url".into(), v.clone()).map(|_| ()).unwrap_or(())
                }
                "timeout" => {
                    if let Some(ms) = dur(v) {
                        self.cfg.expect_ms = ms;
                        self.cfg.action_ms = ms
                    }
                }
                "fail_on" => {
                    self.cfg.fail_on = v
                        .as_array()
                        .map(|a| a.iter().map(scalar_text).collect())
                        .unwrap_or_default()
                }
                "ignore" => {
                    self.cfg.ignore = v
                        .as_array()
                        .map(|a| a.iter().map(scalar_text).collect())
                        .unwrap_or_else(|| vec![scalar_text(v)])
                }
                "deterministic" => self.cfg.deterministic = v.as_bool().unwrap_or(false),
                "headed" => self.cfg.headed = v.as_bool().unwrap_or(false),
                "secret" | "secrets" => self.cfg.secrets.extend(
                    v.as_array()
                        .map(|a| a.iter().map(scalar_text).collect())
                        .unwrap_or_else(|| vec![scalar_text(v)]),
                ),
                "vars" => {
                    if let Some(o) = v.as_object() {
                        self.vars.extend(o.clone())
                    }
                }
                _ => {
                    self.vars.insert(k.clone(), v.clone());
                }
            }
        }
    }

    fn surface(&self, verb: &str, loc: Option<&Locator>) -> Surf {
        if HTTP.contains(&verb) {
            return Surf::Http;
        }
        if BROWSER_VERBS.contains(&verb) {
            return Surf::Browser;
        }
        if TERM_VERBS.contains(&verb) {
            return Surf::Term;
        }
        if let Some(l) = loc {
            if matches!(l.head, Head::Line(_) | Head::LastLine) {
                return Surf::Term;
            }
            if l.scope.iter().any(|s| matches!(s, Scope::Session(n) if self.ptys.contains_key(n))) {
                return Surf::Term;
            }
            if l.scope.iter().any(|s| matches!(s, Scope::Session(n) if self.tabs.contains_key(n))) {
                return Surf::Browser;
            }
        }
        self.last
    }

    fn marks(&self) -> Marks {
        Marks {
            tabs: self
                .tabs
                .iter()
                .map(|(k, t)| {
                    let l = t.log.lock().unwrap();
                    (k.clone(), (l.reqs.len(), l.console.len()))
                })
                .collect(),
            api: self.api_reqs.len(),
            ptys: self.ptys.iter().map(|(k, p)| (k.clone(), p.mark())).collect(),
        }
    }

    fn render_shell(&self, s: &str) -> Result<String> {
        let segs = crate::expr::parse::shell_template(s).map_err(|e| anyhow!("{e}"))?;
        render(&segs, &self.ctx()).map_err(|e| anyhow!(e))
    }
    pub fn render(&self, s: &str) -> Result<String> {
        let segs = template(s).map_err(|e| anyhow!("{e}"))?;
        render(&segs, &self.ctx()).map_err(|e| anyhow!(e))
    }
    fn ctx(&self) -> Ctx<'_> {
        let mut c = Ctx::new(&self.vars, &self.it);
        c.legacy = self.legacy.as_ref();
        c
    }
    fn url(&self, s: &str) -> Result<String> {
        let u = self.render(s)?;
        if u.starts_with('/') {
            let base = self.vars.get("base_url").map(|b| self.render(&scalar_text(b))).transpose()?.or_else(|| self.cfg.base_url.clone())
                .ok_or_else(|| fail(format!("relative URL `{u}` needs a base_url (meta: {{ base_url: … }} or --base-url)")))?;
            return Ok(format!("{}{u}", base.trim_end_matches('/')));
        }
        Ok(u)
    }

    // ---------- sessions ----------
    async fn chrome(&mut self) -> Result<&Chrome> {
        if self.chrome.is_none() {
            let c = match &self.cfg.attach {
                Some(ws) => Chrome::connect(ws).await?,
                None => Chrome::launch(self.cfg.headed).await?,
            };
            for p in c.browser.pages().await.unwrap_or_default() {
                self.known_pages.push(p.target_id().inner().clone())
            }
            self.chrome = Some(c);
        }
        Ok(self.chrome.as_ref().unwrap())
    }
    pub async fn tab(&mut self, name: Option<&str>) -> Result<&Tab> {
        let name = name.map(String::from).unwrap_or_else(|| self.cur_b.clone());
        if !self.tabs.contains_key(&name) {
            let isolated = self.cfg.attach.is_none();
            let t = self.chrome().await?.tab(isolated).await?;
            if self.cfg.deterministic {
                deterministic(&t).await.ok();
            }
            *t.routes.lock().unwrap() = self.routes.clone();
            t.sync_routes().await?;
            self.known_pages.push(t.page.target_id().inner().clone());
            if !self.tabs.is_empty() {
                t.page.bring_to_front().await.ok();
            }
            self.front = name.clone();
            self.tabs.insert(name.clone(), t);
        }
        Ok(&self.tabs[&name])
    }
    fn pty(&mut self, name: Option<&str>) -> Result<&mut Pty> {
        let n = name
            .map(String::from)
            .or_else(|| self.cur_t.clone())
            .ok_or_else(|| fail("no terminal session; start one with `spawn: <command>`"))?;
        self.ptys.get_mut(&n).ok_or_else(|| fail(format!("no terminal session named `{n}`")))
    }
    fn use_session(&mut self, s: &str, verb: &str) {
        if self.ptys.contains_key(s) {
            self.cur_t = Some(s.into());
            self.last = Surf::Term
        } else if self.tabs.contains_key(s) || BROWSER_VERBS.contains(&verb) {
            self.cur_b = s.into();
            self.last = Surf::Browser
        } else if TERM_VERBS.contains(&verb) {
            self.cur_t = Some(s.into());
            self.last = Surf::Term
        }
    }

    /// Renders `${…}` in locator names (recursively through scopes and filters).
    pub fn bind(&self, l: &Locator) -> Result<Locator> {
        let mut l = l.clone();
        let fix = |n: &mut Option<Name>| -> Result<()> {
            if let Some(Name::Tmpl(segs)) = n {
                *n = Some(Name::Sub(render(segs, &self.ctx()).map_err(|e| anyhow!(e))?))
            }
            Ok(())
        };
        fix(&mut l.name)?;
        for f in l.filters.iter_mut() {
            match f {
                Filter::Text(n) => {
                    let mut o = Some(n.clone());
                    fix(&mut o)?;
                    *n = o.unwrap()
                }
                Filter::Has(b) => **b = self.bind(b)?,
            }
        }
        for s in l.scope.iter_mut() {
            if let Scope::Loc(x) = s {
                *x = self.bind(x)?
            }
        }
        if let Head::Closest(a, b) = &mut l.head {
            **a = self.bind(a)?;
            **b = self.bind(b)?
        }
        Ok(l)
    }

    // ---------- the step pipeline ----------
    pub async fn step(&mut self, item: &Item) -> StepResult {
        self.step_no += 1;
        let t0 = Instant::now();
        if let Some(s) = &item.opts.session {
            self.use_session(s, &item.verb)
        }
        self.cur = self.marks();
        if !PASSIVE.contains(&item.verb.as_str()) {
            self.prev = self.cur.clone()
        }
        let mut r = StepResult {
            verb: item.verb.clone(),
            text: item.text.clone(),
            file: self.file.clone(),
            line: item.line,
            step_name: item.opts.title.clone(),
            claim: (!self.claims.is_empty()
                && self.claims.last().is_some_and(|c| c.status != "skip"))
            .then(|| self.claims.len() - 1),
            ..Default::default()
        };
        let surf = self.surface(
            &item.verb,
            match &item.args {
                Args::Loc(l) | Args::LocVal(l, _) => Some(l),
                _ => None,
            },
        );
        let before = if surf == Surf::Browser
            && !["visit", "route", "unroute"].contains(&item.verb.as_str())
        {
            self.summary().await
        } else {
            None
        };
        if let Some(d) = &item.opts.dialog {
            if let Ok(t) = self.tab(None).await {
                *t.dialog.lock().unwrap() = (
                    d.trim().starts_with("accept"),
                    d.split_once(" with ").map(|(_, t)| t.trim().trim_matches('"').to_string()),
                )
            }
        }
        log::debug!(target: "testkit", "{} before-summary {}ms", item.verb, t0.elapsed().as_millis());
        let outcome = Box::pin(self.exec(item, &mut r)).await;
        log::debug!(target: "testkit", "{} exec {}ms", item.verb, t0.elapsed().as_millis());
        if item.opts.dialog.is_some() {
            if let Some(t) = self.tabs.get(&self.cur_b) {
                *t.dialog.lock().unwrap() = (false, None)
            }
        }
        let keep_it = matches!(
            item.verb.as_str(),
            "expect" | "claim" | "mark" | "route" | "unroute" | "snapshot" | "shot"
        );
        let prev_it = self.it.clone();
        match outcome {
            Ok(it) => {
                self.it = it.clone();
                r.it = it
            }
            Err(e) => r.step_error = Some(e.to_string()),
        }
        if r.step_error.is_none() && item.opts.request.disabled != Some(true) {
            self.post(item, &mut r).await
        }
        if keep_it {
            self.it = prev_it
        }
        if [Surf::Browser].contains(&surf) || self.last == Surf::Browser {
            if r.verb != "snapshot" {
                self.report(&mut r, before).await
            }
            log::debug!(target: "testkit", "{} report {}ms", item.verb, t0.elapsed().as_millis());
            if r.step_error.is_none() {
                self.guard(item, &mut r)
            }
            if self.cfg.frames && self.tabs.contains_key(&self.cur_b) {
                r.frame = self.tabs[&self.cur_b].screenshot(0.5).await.ok()
            }
        }
        if item.verb == "exec"
            && (r.step_error.is_some() || r.assert_results.iter().any(|a| !matches!(a, Ok(true))))
        {
            let tail = |s: &str| {
                s.lines()
                    .rev()
                    .take(8)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect::<Vec<_>>()
                    .join("\n    ")
            };
            for k in ["stdout", "stderr"] {
                if let Some(s) = r.it[k].as_str().filter(|s| !s.is_empty()) {
                    r.step_log.push_str(&format!("{k} (exit {}):\n    {}\n", r.it["exit"], tail(s)))
                }
            }
        }
        r.ms = t0.elapsed().as_millis() as u64;
        r.status =
            if r.step_error.is_some() || r.assert_results.iter().any(|a| !matches!(a, Ok(true))) {
                "fail".into()
            } else {
                "pass".into()
            };
        if let Some(e) = &r.step_error {
            r.step_log.push_str(e)
        }
        r
    }

    async fn post(&mut self, item: &Item, r: &mut StepResult) {
        for a in item.opts.asserts.iter().flatten() {
            let res = match a {
                Assert::IsOk(e) => self.assert_expr(e).await,
                a => {
                    let body = self.legacy.clone().unwrap_or_else(|| self.it.clone());
                    typed_assert(&self.file, a, &body, &self.ctx())
                        .unwrap_or(Ok(("", true)))
                        .map(|(l, b)| (l.to_string(), b, None))
                }
            };
            match res {
                Ok((label, ok, actual)) => {
                    let txt = assert_text(a);
                    r.step_log.push_str(&format!(
                        "{} {label: <12} ⮕ {txt}{}\n",
                        if ok { "✅" } else { "❌" },
                        actual
                            .filter(|_| !ok)
                            .map(|a| format!("   (actual: {a})"))
                            .unwrap_or_default()
                    ));
                    r.assert_results.push(Ok(ok));
                }
                Err(e) => {
                    if matches!(a, Assert::IsOk(_)) {
                        r.step_log.push_str(&format!(
                            "❌ OK           ⮕ {}\n   E_ASSERT {}\n",
                            assert_text(a),
                            e.advice.clone().unwrap_or_default()
                        ))
                    } else {
                        r.step_log.push_str(&report_error(&e))
                    }
                    r.assert_results.push(Err(e))
                }
            }
        }
        if let Some(ex) = &item.opts.exports {
            if item.verb == "call" {
                return;
            }
            for (k, v) in ex.as_object().cloned().unwrap_or_default() {
                let s = scalar_text(&v);
                let val = if let Some(h) = s.strip_prefix("$.res.header.") {
                    self.it["headers"]
                        .get(h)
                        .cloned()
                        .map(|h| match h {
                            Value::Array(a) => Value::String(a.iter().map(scalar_text).collect()),
                            v => v,
                        })
                        .unwrap_or(Value::Null)
                } else if s.starts_with("$.res.status") {
                    self.it["status"].clone()
                } else {
                    match crate::expr::parse::value(&s) {
                        Ok(e) => self.value(&e).await.unwrap_or(Value::Null),
                        Err(e) => {
                            r.step_error = Some(format!("exports.{k}: {e}"));
                            Value::Null
                        }
                    }
                };
                self.vars.insert(k, val);
            }
        }
    }
    async fn assert_expr(
        &mut self,
        e: &str,
    ) -> Result<(String, bool, Option<String>), AssertionError> {
        let c = crate::expr::parse::cond(e).map_err(|err| AssertionError {
            advice: Some(err.msg.clone()),
            src: miette::NamedSource::new(&self.file, e.to_string()),
            bad_bit: (err.offset, 1).into(),
        })?;
        match self.check(&c).await {
            Ok((ok, actual)) => Ok(("OK".into(), ok, actual)),
            Err(err) => Err(AssertionError {
                advice: Some(err.to_string()),
                src: miette::NamedSource::new(&self.file, e.to_string()),
                bad_bit: (0, e.len()).into(),
            }),
        }
    }

    fn guard(&mut self, item: &Item, r: &mut StepResult) {
        let allow = item.opts.allow.as_ref().map(|v| v.to_string()).unwrap_or_default();
        let Some(t) = self.tabs.get(&self.cur_b) else { return };
        let since = self.cur.tabs.get(&self.cur_b).map(|m| m.1).unwrap_or(0);
        let l = t.log.lock().unwrap();
        let ign: Vec<regex::Regex> = self
            .cfg
            .ignore
            .iter()
            .filter_map(|p| {
                regex::Regex::new(p.trim_start_matches("console").trim().trim_matches('/')).ok()
            })
            .collect();
        let bad: Vec<String> = l
            .console
            .iter()
            .skip(since)
            .filter(|m| {
                (m.level == "pageerror"
                    && self.cfg.fail_on.iter().any(|f| f.contains("page"))
                    && !allow.contains("page errors"))
                    || (m.level == "error"
                        && self.cfg.fail_on.iter().any(|f| f.contains("console"))
                        && !allow.contains("console errors"))
            })
            .filter(|m| !ign.iter().any(|re| re.is_match(&m.text)))
            .map(|m| {
                format!(
                    "{}: {} ({})",
                    if m.level == "error" { "console.error" } else { "uncaught" },
                    m.text,
                    m.source
                )
            })
            .collect();
        if !bad.is_empty() {
            r.step_error = Some(format!("E_GUARD this step introduced {} error{}:\n  {}\n  (allow it with `allow: [console errors]`, or `ignore:` in meta)", bad.len(), if bad.len() > 1 { "s" } else { "" }, bad.join("\n  ")));
        }
    }

    async fn summary(&mut self) -> Option<(Vec<String>, String)> {
        let t = self.tabs.get(&self.cur_b)?;
        let s = t.tk("summary", &[]).await.ok()?;
        Some((s.as_array()?.iter().map(scalar_text).collect(), t.url().await))
    }
    async fn report(&mut self, r: &mut StepResult, before: Option<(Vec<String>, String)>) {
        if !self.tabs.contains_key(&self.cur_b) {
            return;
        }
        let (rq, cn) = self.cur.tabs.get(&self.cur_b).copied().unwrap_or((0, 0));
        let mut rep = json!({});
        let after = self.summary().await;
        if let (Some((b, burl)), Some((a, aurl))) = (before, after) {
            if burl != aurl {
                rep["url"] = json!([path_of(&burl), path_of(&aurl)])
            }
            let app: Vec<&String> = a.iter().filter(|x| !b.contains(x)).take(8).collect();
            let gone: Vec<&String> = b.iter().filter(|x| !a.contains(x)).take(8).collect();
            if !app.is_empty() {
                rep["appeared"] = json!(app)
            }
            if !gone.is_empty() {
                rep["gone"] = json!(gone)
            }
        }
        let t = &self.tabs[&self.cur_b];
        let (net, con) = {
            let l = t.log.lock().unwrap();
            let net: Vec<String> = l
                .reqs
                .iter()
                .skip(rq)
                .filter(|q| {
                    ["fetch", "xhr", "document"].contains(&q.kind.as_str())
                        || q.failed.is_some()
                        || q.status.is_some_and(|s| s >= 400)
                })
                .take(10)
                .map(|q| {
                    format!(
                        "{} {} {}{}",
                        q.method,
                        path_of(&q.url),
                        q.status.map(|s| s.to_string()).or(q.failed.clone()).unwrap_or("…".into()),
                        if q.done { format!(" {}ms", q.ms) } else { String::new() }
                    )
                })
                .collect();
            let mut con: Vec<String> = vec![];
            for m in
                l.console.iter().skip(cn).filter(|m| {
                    m.level == "error" || m.level == "pageerror" || m.level == "warning"
                })
            {
                let s = format!("{}: {} ({})", m.level, m.text, m.source);
                if !con.contains(&s) {
                    con.push(s)
                }
            }
            (net, con)
        };
        if !net.is_empty() {
            rep["network"] = json!(net)
        }
        if !con.is_empty() {
            rep["console"] = json!(con)
        }
        let navigated = r.verb == "visit" || rep.get("url").is_some();
        if navigated
            && (self.file.starts_with("session:") || self.file.starts_with("mcp:"))
            && r.step_error.is_none()
        {
            if let Ok(v) = t
                .tk("snapshot", &[Value::Null, json!({"all": false, "refs": true, "max": 60})])
                .await
            {
                rep["snapshot"] = v["yaml"].clone()
            }
        }
        r.report = rep;
    }

    // ---------- verbs ----------
    async fn exec(&mut self, item: &Item, r: &mut StepResult) -> Result<Value> {
        let v = item.verb.as_str();
        let timeout = item.opts.timeout.as_ref().and_then(dur);
        if HTTP.contains(&v) {
            self.last = Surf::Http;
            return self.http(item, r).await;
        }
        match (&item.args, v) {
            (Args::Tmpl(_), "visit") => {
                let url = self.url(&item.text)?;
                self.last = Surf::Browser;
                let t = self.tab(None).await?;
                t.goto(&url).await?;
                Ok(t.page_state().await)
            }
            (_, "back" | "reload") => {
                self.last = Surf::Browser;
                let t = self.tab(None).await?;
                t.eval_raw(if v == "back" { "history.back()" } else { "location.reload()" })
                    .await?;
                tokio::time::sleep(Duration::from_millis(150)).await;
                t.wait_load().await;
                Ok(t.page_state().await)
            }
            (Args::Loc(l), _) => {
                self.last = self.surface(v, Some(l));
                self.act(v, l, None, timeout, item).await
            }
            (Args::LocVal(l, e), _) => {
                let val = self.value(e).await?;
                self.last = Surf::Browser;
                self.act(v, l, Some(val), timeout, item).await
            }
            (Args::Drag(a, b), _) => self.drag(a, b, timeout).await,
            (Args::Type(e, l), "type") => {
                let s = to_str(&self.value(e).await?);
                if let Some(l) = l {
                    self.act("focus", l, None, timeout, item).await?;
                }
                match self.surface(v, l.as_ref()) {
                    Surf::Term => {
                        self.pty(None)?.write(&s)?;
                        Ok(Value::String(s))
                    }
                    _ => {
                        self.tab(None).await?.type_text(&s).await?;
                        Ok(Value::String(s))
                    }
                }
            }
            (Args::Type(e, _), "enter") => {
                let s = to_str(&self.value(e).await?);
                self.last = Surf::Term;
                let p = self.pty(None)?;
                let at = p.mark();
                p.write(&format!("{s}\r"))?;
                self.settle_term(timeout.unwrap_or(self.cfg.action_ms), at).await
            }
            (Args::Press(keys, n, l), _) => {
                if let Some(l) = l {
                    self.act("focus", l, None, timeout, item).await?;
                }
                match self.surface(v, l.as_ref()) {
                    Surf::Term => {
                        let p = self.pty(None)?;
                        for _ in 0..*n {
                            for k in keys {
                                p.key(k)?;
                            }
                        }
                    }
                    _ => {
                        let t = self.tab(None).await?;
                        for _ in 0..*n {
                            for k in keys {
                                t.key(k).await?;
                            }
                        }
                        tokio::time::sleep(Duration::from_millis(30)).await;
                        t.wait_load().await;
                    }
                }
                Ok(json!(keys))
            }
            (Args::Wait(evs), _) => self.wait(evs, timeout).await,
            (Args::Expect(c, within), _) => {
                self.expect(item, c, within.map(|w| w as u64).or(timeout)).await
            }
            (Args::Extract(e, name), _) => {
                let v = self.value(e).await?;
                self.vars.insert(name.clone(), v.clone());
                Ok(v)
            }
            (Args::Route(m, p), "route") => {
                let delay_ms = item.opts.delay.as_ref().and_then(dur).unwrap_or(0);
                let abort =
                    item.opts.abort.as_ref().filter(|a| a != &&Value::Bool(false)).map(|a| {
                        if a == &Value::Bool(true) {
                            "failed".into()
                        } else {
                            scalar_text(a)
                        }
                    });
                let respond = item.opts.respond.clone().map(|r| match r {
                    Value::String(s) => Value::String(self.dir.join(s).to_string_lossy().into()),
                    r => r,
                });
                self.routes.push(Route {
                    method: m.clone(),
                    pat: self.render(p)?,
                    respond,
                    modify: item.opts.modify.clone(),
                    abort,
                    delay_ms,
                    times: item.opts.times,
                    hits: 0,
                });
                self.sync_routes().await?;
                Ok(json!({"route": item.text}))
            }
            (Args::Route(m, p), "unroute") => {
                let p = self.render(p)?;
                self.routes.retain(|r| !(r.pat == p && (m.is_none() || r.method == *m)));
                self.sync_routes().await?;
                Ok(Value::Null)
            }
            (Args::Tmpl(_), "call") => self.call(item, r).await,
            (Args::Shot(path, l), _) => self.shot(path.as_ref(), l.as_ref()).await,
            (Args::Snapshot(l), _) => {
                let s = self.snapshot(l.as_ref(), false).await?;
                r.report = json!({"snapshot": s});
                Ok(Value::String(s))
            }
            (Args::Tmpl(_), "exec") => {
                self.last = Surf::Term;
                let cmd = self.render_shell(&item.text)?;
                let env = self.env(item)?;
                let cwd = Some(self.cwd(item)?);
                let out = term::exec(
                    &cmd,
                    cwd.as_deref(),
                    &env,
                    Duration::from_millis(timeout.unwrap_or(120_000)),
                )
                .await?;
                let allowed =
                    item.opts.allow.as_ref().is_some_and(|a| a.to_string().contains("exit"));
                if out["exit"] != 0 && item.opts.asserts.is_none() && !allowed {
                    let err: Vec<&str> =
                        out["stderr"].as_str().unwrap_or("").lines().rev().take(6).collect();
                    bail!("E_EXIT `{cmd}` exited with code {}{}\n  (add `asserts:` or `allow: [exit]` when a non-zero exit is expected)", out["exit"],
                        if err.is_empty() { String::new() } else { format!("\n  stderr: {}", err.into_iter().rev().collect::<Vec<_>>().join("\n          ")) });
                }
                Ok(out)
            }
            (Args::Tmpl(_), "spawn") => self.spawn(item).await,
            (Args::Signal(sig, to), _) => {
                self.pty(to.as_deref())?.signal(sig)?;
                Ok(json!(sig))
            }
            (Args::Resize(w, h), _) => match self.last {
                Surf::Term => {
                    self.pty(None)?.resize(*w, *h)?;
                    Ok(json!([w, h]))
                }
                _ => {
                    self.tab(None).await?.emulate(&format!("{w}x{h}")).await?;
                    Ok(json!([w, h]))
                }
            },
            (_, "throttle") => {
                self.tab(None).await?.throttle(&item.text).await?;
                Ok(Value::Null)
            }
            (_, "network") => {
                self.tab(None).await?.network(&item.text).await?;
                Ok(Value::Null)
            }
            (_, "emulate") => {
                self.tab(None).await?.emulate(&item.text).await?;
                Ok(Value::Null)
            }
            (Args::Toggle(on, into), "trace" | "profile" | "heap") => {
                self.devtools(v, *on, into.clone()).await
            }
            (_, "mark") => Ok(json!({"mark": item.text})),
            (a, v) => bail!("`{v}` does not take `{}` ({a:?})", item.text),
        }
    }

    /// Commands run in the test file's directory unless `cwd:` says otherwise.
    fn cwd(&self, item: &Item) -> Result<String> {
        let d = match &item.opts.cwd {
            Some(c) => self.dir.join(self.render(c)?),
            None => self.dir.clone(),
        };
        let d = if d.as_os_str().is_empty() { PathBuf::from(".") } else { d };
        Ok(d.to_string_lossy().to_string())
    }
    fn env(&self, item: &Item) -> Result<Vec<(String, String)>> {
        item.opts
            .env
            .iter()
            .flatten()
            .map(|(k, v)| Ok((k.clone(), self.render(&scalar_text(v))?)))
            .collect()
    }

    async fn spawn(&mut self, item: &Item) -> Result<Value> {
        let cmd = self.render_shell(&item.text)?;
        let name = item.opts.session.clone().unwrap_or_else(|| {
            cmd.split_whitespace()
                .next()
                .unwrap_or("term")
                .rsplit('/')
                .next()
                .unwrap_or("term")
                .to_string()
        });
        let size = item
            .opts
            .size
            .as_deref()
            .and_then(|s| s.split_once('x'))
            .and_then(|(c, r)| Some((c.trim().parse().ok()?, r.trim().parse().ok()?)))
            .unwrap_or((120, 40));
        let cwd = Some(self.cwd(item)?);
        let env = self.env(item)?;
        let p = Pty::spawn(&cmd, cwd.as_deref(), &env, size, item.opts.prompt.as_deref())?;
        self.ptys.insert(name.clone(), p);
        self.cur_t = Some(name.clone());
        self.last = Surf::Term;
        self.cur.ptys.insert(name.clone(), 0);
        if let Some(ready) = &item.opts.ready {
            let evs = match args("wait", ready).map_err(|e| anyhow!("ready: {e}"))? {
                Args::Wait(e) => e,
                _ => vec![],
            };
            let t = Instant::now();
            let v = Box::pin(self.wait(&evs, Some(60_000))).await.map_err(|e| {
                anyhow!("`{cmd}` never became ready: {e}\n{}", self.ptys[&name].screen())
            })?;
            return Ok(
                json!({"session": name, "startup": t.elapsed().as_millis() as u64, "match": v["match"], "text": v["text"]}),
            );
        }
        Ok(json!({"session": name}))
    }
    async fn settle_term(&mut self, timeout: u64, at: usize) -> Result<Value> {
        let t = Instant::now();
        loop {
            tokio::time::sleep(Duration::from_millis(40)).await;
            let p = self.pty(None)?;
            let out = p.output_since(at);
            let prompt_hit = p.prompt.as_ref().is_some_and(|re| {
                out.lines().last().is_some_and(|l| re.is_match(l)) && !out.is_empty()
            });
            if prompt_hit
                || p.exit().is_some()
                || (p.prompt.is_none()
                    && p.quiet_for() > Duration::from_millis(300)
                    && t.elapsed() > Duration::from_millis(300))
                || t.elapsed().as_millis() as u64 > timeout
            {
                return Ok(Value::String(out));
            }
        }
    }

    async fn sync_routes(&mut self) -> Result<()> {
        for t in self.tabs.values() {
            *t.routes.lock().unwrap() = self.routes.clone();
            t.sync_routes().await?;
        }
        Ok(())
    }

    /// Resolves, waits for actionability (spec §4) and performs a browser or terminal action.
    async fn act(
        &mut self,
        verb: &str,
        loc: &Locator,
        val: Option<Value>,
        timeout: Option<u64>,
        item: &Item,
    ) -> Result<Value> {
        let loc = &self.bind(loc)?;
        let session = loc.scope.iter().find_map(|s| {
            if let Scope::Session(n) = s {
                Some(n.clone())
            } else {
                None
            }
        });
        if self.surface(verb, Some(loc)) == Surf::Term {
            bail!("`{verb}` acts on browser elements; use `type:`/`press:`/`enter:` for terminals")
        }
        let checks: &[&str] = match verb {
            "click" | "dblclick" | "check" | "uncheck" | "tap" => {
                &["visible", "stable", "receives", "enabled"]
            }
            "hover" => &["visible", "stable", "receives"],
            "fill" => &["visible", "enabled", "editable"],
            "select" => &["visible", "enabled"],
            _ => &[],
        };
        let deadline =
            Instant::now() + Duration::from_millis(timeout.unwrap_or(self.cfg.action_ms));
        let dir = self.dir.clone();
        let want = session.clone().unwrap_or(self.cur_b.clone());
        if self.front != want {
            if let Ok(t) = self.tab(Some(&want)).await {
                t.page.bring_to_front().await.ok();
            }
            self.front = want;
        }
        let t = self.tab(session.as_deref()).await?;
        let mut why = String::from("no element matches");
        let el = loop {
            let els = t.resolve(loc).await?;
            match els.len() {
                1 => {
                    let a = t.tk("actionable", &[els[0]["ref"].clone(), json!(checks)]).await?;
                    if a["ok"] == true {
                        break (
                            els[0].clone(),
                            a["x"].as_f64().unwrap_or(0.0),
                            a["y"].as_f64().unwrap_or(0.0),
                        );
                    }
                    why = format!("element is {}", scalar_text(&a["reason"]));
                    if let Some(c) = a["cover"].as_str() {
                        why.push_str(&format!(
                            "\n  try dismissing it first, e.g. `click: button \"Accept\" in {c}`"
                        ))
                    }
                }
                0 => {}
                n => {
                    let mut cands = vec![];
                    for e in els.iter().take(8) {
                        if let Some(s) = t.locator_for(e["ref"].as_i64().unwrap_or(0)).await {
                            cands.push(s)
                        }
                    }
                    bail!(
                        "E_AMBIGUOUS `{verb} {loc}` matches {n} elements; use one of:\n    {}",
                        cands.join("\n    ")
                    );
                }
            }
            if Instant::now() > deadline {
                if why.starts_with("no element") {
                    let needle = match &loc.name {
                        Some(Name::Sub(s) | Name::Exact(s)) => s.clone(),
                        _ => String::new(),
                    };
                    let near = t
                        .tk("find", &[json!(needle.split_whitespace().next().unwrap_or(""))])
                        .await
                        .ok()
                        .and_then(|v| v.as_array().cloned())
                        .unwrap_or_default();
                    let near: Vec<String> = near
                        .iter()
                        .filter_map(|n| n["locator"].as_str().map(String::from))
                        .take(5)
                        .collect();
                    bail!(
                        "E_NOT_FOUND `{loc}` matched nothing within {}ms{}",
                        timeout.unwrap_or(self.cfg.action_ms),
                        if near.is_empty() {
                            "\n  (run `testkit snapshot` to see the page)".to_string()
                        } else {
                            format!("; did you mean:\n    {}", near.join("\n    "))
                        }
                    );
                }
                bail!("E_NOT_ACTIONABLE `{verb} {loc}`: {why}");
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        let (el, x, y) = el;
        log::debug!(target: "testkit", "{verb} actionable after {}ms", (deadline - Instant::now()).as_millis());
        let rf = el["ref"].clone();
        let measure = item.opts.measure.as_ref().is_some_and(|m| {
            m == &Value::Bool(true) || m.as_str().is_some_and(|s| s.starts_with("until"))
        });
        if measure {
            t.tk("measureStart", &[]).await?;
        }
        let t_act = Instant::now();
        let (rq0, _) = {
            let l = t.log.lock().unwrap();
            (l.reqs.len(), 0)
        };
        use chromiumoxide::cdp::browser_protocol::input::MouseButton;
        match verb {
            "click" | "tap" => t.click_at(x, y, 1, MouseButton::Left).await?,
            "dblclick" => t.click_at(x, y, 2, MouseButton::Left).await?,
            "check" | "uncheck" => {
                if el["checked"].as_bool() != Some(verb == "check") {
                    t.click_at(x, y, 1, MouseButton::Left).await?
                }
            }
            "hover" => {
                t.page.move_mouse(chromiumoxide::layout::Point { x, y }).await?;
            }
            "focus" => {
                t.tk("focusSelect", std::slice::from_ref(&rf)).await?;
            }
            "fill" => {
                let s = to_str(val.as_ref().unwrap_or(&Value::Null));
                if el["tag"] == "select" {
                    return self.select(&rf, &s).await;
                }
                t.tk("focusSelect", std::slice::from_ref(&rf)).await?;
                t.key("Delete").await?;
                if !s.is_empty() {
                    t.insert_text(&s).await?
                }
            }
            "select" => {
                return self.select(&rf, &to_str(val.as_ref().unwrap_or(&Value::Null))).await
            }
            "upload" => {
                let files: Vec<String> = match val {
                    Some(Value::Array(a)) => a.iter().map(to_str).collect(),
                    v => vec![to_str(&v.unwrap_or_default())],
                };
                let dir = dir.clone();
                let files = files
                    .into_iter()
                    .map(|f| {
                        std::fs::canonicalize(dir.join(&f))
                            .unwrap_or_else(|_| f.into())
                            .to_string_lossy()
                            .to_string()
                    })
                    .collect();
                t.set_files(rf.as_i64().unwrap_or(0), files).await?;
            }
            v => bail!("unknown action {v}"),
        }
        log::debug!(target: "testkit", "{verb} input dispatched {}ms", t_act.elapsed().as_millis());
        tokio::time::sleep(Duration::from_millis(40)).await;
        t.wait_load().await;
        log::debug!(target: "testkit", "{verb} loaded {}ms", t_act.elapsed().as_millis());
        if measure {
            return self.measure(t_act, rq0, item).await;
        }
        Ok(el)
    }
    async fn select(&mut self, rf: &Value, label: &str) -> Result<Value> {
        let t = self.tab(None).await?;
        let r = t.tk("selectOption", &[rf.clone(), json!(label)]).await?;
        if r["ok"] != true {
            bail!("E_NOT_FOUND option `{label}`; options are: {}", r["options"])
        }
        Ok(r)
    }
    async fn drag(&mut self, a: &Locator, b: &Locator, timeout: Option<u64>) -> Result<Value> {
        let t = self.tab(None).await?;
        let mut pts = vec![];
        for l in [a, b] {
            let els = t.resolve(l).await?;
            let e = els.first().ok_or_else(|| fail(format!("E_NOT_FOUND `{l}`")))?;
            let p = t.tk("actionable", &[e["ref"].clone(), json!(["visible"])]).await?;
            pts.push((p["x"].as_f64().unwrap_or(0.0), p["y"].as_f64().unwrap_or(0.0)));
        }
        let _ = timeout;
        use chromiumoxide::cdp::browser_protocol::input::*;
        let mouse = |ty, (x, y): (f64, f64)| {
            DispatchMouseEventParams::builder()
                .r#type(ty)
                .x(x)
                .y(y)
                .button(MouseButton::Left)
                .buttons(1)
                .click_count(1)
                .build()
                .unwrap()
        };
        t.page.execute(mouse(DispatchMouseEventType::MouseMoved, pts[0])).await?;
        t.page.execute(mouse(DispatchMouseEventType::MousePressed, pts[0])).await?;
        for i in 1..=10 {
            let f = i as f64 / 10.0;
            t.page
                .execute(mouse(
                    DispatchMouseEventType::MouseMoved,
                    (pts[0].0 + (pts[1].0 - pts[0].0) * f, pts[0].1 + (pts[1].1 - pts[0].1) * f),
                ))
                .await?;
        }
        t.page.execute(mouse(DispatchMouseEventType::MouseReleased, pts[1])).await?;
        Ok(json!({"from": pts[0], "to": pts[1]}))
    }

    async fn measure(&mut self, t_act: Instant, rq0: usize, item: &Item) -> Result<Value> {
        let until = item
            .opts
            .measure
            .as_ref()
            .and_then(Value::as_str)
            .and_then(|s| s.strip_prefix("until"))
            .map(|s| crate::expr::parse::cond(s.trim()))
            .transpose()
            .map_err(|e| anyhow!("{e}"))?;
        let (mut net_ms, mut quiet_since) = (0u64, None::<Instant>);
        let (mut custom, mut offset) = (None, 0.0f64);
        loop {
            tokio::time::sleep(Duration::from_millis(25)).await;
            let t = self.tab(None).await?;
            let pending = {
                let l = t.log.lock().unwrap();
                l.reqs[rq0.min(l.reqs.len())..]
                    .iter()
                    .filter(|r| !r.done && !r.kind.contains("ping"))
                    .count()
            };
            if pending == 0 && net_ms == 0 {
                net_ms = t_act.elapsed().as_millis() as u64
            }
            if pending > 0 {
                net_ms = 0
            }
            let mut m = t.tk("measureRead", &[]).await?;
            if m.get("t0").is_none() {
                offset = t_act.elapsed().as_secs_f64() * 1000.0;
                t.tk("measureStart", &[]).await?;
                m = t.tk("measureRead", &[]).await?;
                m["dom"] = json!(0.0);
            }
            let dom = m["dom"].as_f64().unwrap_or(0.0) + offset;
            let now = m["now"].as_f64().unwrap_or(0.0) + offset;
            if pending == 0 && now - dom > 100.0 {
                quiet_since.get_or_insert(Instant::now());
            } else {
                quiet_since = None
            }
            if custom.is_none() {
                if let Some(c) = &until {
                    let mut c2 = c.clone();
                    if self.check_once(&mut c2).await.map(|x| x.0).unwrap_or(false) {
                        custom = Some(t_act.elapsed().as_millis() as u64)
                    }
                }
            }
            let done = quiet_since.is_some_and(|q| q.elapsed() > Duration::from_millis(150))
                && (until.is_none() || custom.is_some());
            if done || t_act.elapsed() > Duration::from_secs(15) {
                let shift = m["shift"].as_f64().unwrap_or(0.0) + offset;
                let visual = (dom.max(shift) + 33.0).round() as u64;
                let dom_ms = (dom + 100.0).round() as u64;
                let duration = custom.unwrap_or(visual);
                return Ok(
                    json!({"duration": duration, "visual": visual, "network": net_ms, "dom": dom_ms, "until": custom}),
                );
            }
        }
    }
    async fn heap(&mut self) -> Result<f64> {
        let t = self.tab(None).await?;
        t.page.execute(chromiumoxide::cdp::js_protocol::heap_profiler::CollectGarbageParams::default()).await.ok();
        let m = t.page.metrics().await?;
        Ok(m.iter().find(|m| m.name == "JSHeapUsedSize").map(|m| m.value).unwrap_or(0.0))
    }
    async fn devtools(&mut self, what: &str, on: bool, into: Option<String>) -> Result<Value> {
        use chromiumoxide::cdp::js_protocol::profiler;
        let t = self.tab(None).await?;
        let dir = PathBuf::from(".testkit/devtools");
        std::fs::create_dir_all(&dir).ok();
        match (what, on) {
            ("profile", true) => {
                t.page.execute(profiler::EnableParams::default()).await?;
                t.page.execute(profiler::StartParams::default()).await?;
                Ok(Value::Null)
            }
            ("profile", false) => {
                let p = t.page.execute(profiler::StopParams::default()).await?;
                let path =
                    dir.join(format!("{}.cpuprofile", into.unwrap_or_else(|| "profile".into())));
                std::fs::write(&path, serde_json::to_vec(&p.profile)?)?;
                let path = std::fs::canonicalize(&path)?;
                Ok(json!({"file": path, "nodes": p.profile.nodes.len()}))
            }
            ("trace", true) => {
                use chromiumoxide::cdp::browser_protocol::tracing as tr;
                let mut s = t.page.event_listener::<tr::EventDataCollected>().await?;
                let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::<Value>::new()));
                let b2 = buf.clone();
                tokio::spawn(async move {
                    use futures_util::StreamExt;
                    while let Some(e) = s.next().await {
                        b2.lock().unwrap().extend(e.value.iter().cloned())
                    }
                });
                let cfg = tr::TraceConfig::builder()
                    .included_categories(
                        [
                            "devtools.timeline",
                            "v8.execute",
                            "disabled-by-default-devtools.timeline",
                            "blink.user_timing",
                            "loading",
                        ]
                        .map(String::from)
                        .to_vec(),
                    )
                    .build();
                t.page.execute(tr::StartParams::builder().trace_config(cfg).build()).await?;
                self.trace_buf = Some(buf);
                Ok(Value::Null)
            }
            ("trace", false) => {
                use chromiumoxide::cdp::browser_protocol::tracing as tr;
                t.page.execute(tr::EndParams::default()).await?;
                tokio::time::sleep(Duration::from_millis(700)).await;
                let buf = self
                    .trace_buf
                    .take()
                    .ok_or_else(|| fail("trace: stop without trace: start"))?;
                let events = buf.lock().unwrap().clone();
                let path =
                    dir.join(format!("{}.trace.json", into.unwrap_or_else(|| "trace".into())));
                std::fs::write(&path, serde_json::to_vec(&json!({"traceEvents": events}))?)?;
                let path = std::fs::canonicalize(&path)?;
                Ok(json!({"file": path, "events": events.len()}))
            }
            ("heap", _) => {
                let h = self.heap().await?;
                if let Some(n) = into {
                    self.vars.insert(n, json!(h));
                }
                Ok(json!(h))
            }
            _ => bail!("unknown devtools command"),
        }
    }

    async fn shot(&mut self, path: Option<&Vec<Seg>>, loc: Option<&Locator>) -> Result<Value> {
        let path = match path {
            Some(p) => render(p, &self.ctx()).map_err(|e| anyhow!(e))?,
            None => format!("shot-{}.png", self.step_no),
        };
        let path = PathBuf::from(".testkit/shots").join(path);
        std::fs::create_dir_all(path.parent().unwrap_or(&PathBuf::from("."))).ok();
        if self.last == Surf::Term && loc.is_none() {
            let s = self.pty(None)?.screen();
            let p = path.with_extension("txt");
            std::fs::write(&p, &s)?;
            return Ok(json!({"file": p}));
        }
        let t = self.tab(None).await?;
        if let Some(l) = loc {
            if let Some(e) = t.resolve(l).await?.first() {
                t.tk("actionable", &[e["ref"].clone(), json!([])]).await?;
            }
        }
        std::fs::write(&path, t.screenshot(1.0).await?)?;
        Ok(json!({"file": std::fs::canonicalize(&path)?}))
    }
    pub async fn snapshot(&mut self, loc: Option<&Locator>, all: bool) -> Result<String> {
        if self.last == Surf::Term
            || loc.is_some_and(|l| self.surface("snapshot", Some(l)) == Surf::Term)
        {
            return Ok(self.pty(None)?.snapshot(all));
        }
        let t = self.tab(None).await?;
        let v = t
            .tk(
                "snapshot",
                &[loc.map(loc_json).unwrap_or(Value::Null), json!({"all": all, "refs": true})],
            )
            .await?;
        let page = t.page_state().await;
        Ok(format!(
            "# {} — {}\n{}",
            scalar_text(&page["title"]),
            scalar_text(&page["url"]),
            scalar_text(&v["yaml"])
        ))
    }

    async fn call(&mut self, item: &Item, r: &mut StepResult) -> Result<Value> {
        let path = self.dir.join(self.render(&item.text)?);
        let src = std::fs::read_to_string(&path)
            .map_err(|e| anyhow!("call: cannot read {}: {e}", path.display()))?;
        if self.depth > 20 {
            bail!("call: include cycle at {}", path.display())
        }
        let items = parse_yaml(&src).map_err(|e| anyhow!("{}: {e}", path.display()))?;
        let mut params = Map::new();
        for (k, v) in item.opts.with.clone().unwrap_or_default() {
            params.insert(
                k,
                match v {
                    Value::String(s) => Value::String(self.render(&s)?),
                    v => v,
                },
            );
        }
        if let Some(b) = self.vars.get("base_url").map(scalar_text) {
            if let Ok(b) = self.render(&b) {
                params.entry("base_url").or_insert(Value::String(b));
            }
        }
        let saved = (
            std::mem::replace(&mut self.vars, params),
            std::mem::replace(&mut self.file, path.to_string_lossy().into()),
            std::mem::replace(
                &mut self.dir,
                path.parent().map(|p| p.to_path_buf()).unwrap_or_default(),
            ),
        );
        self.depth += 1;
        let claims_before = self.claims.len();
        let name = path
            .file_stem()
            .map(|s| s.to_string_lossy().trim_end_matches(".tk").to_string())
            .unwrap_or_default();
        let sub = Box::pin(self.run_items(&items)).await;
        self.depth -= 1;
        let callee_vars = std::mem::replace(&mut self.vars, saved.0);
        self.file = saved.1;
        self.dir = saved.2;
        let base = self.results.len() - sub.len();
        for (i, s) in sub.iter().enumerate() {
            let rr = &mut self.results[base + i];
            rr.step_name =
                Some(format!("{name} › {}", s.step_name.clone().unwrap_or_else(|| s.line_text())));
        }
        let _ = claims_before;
        for n in item.opts.exports.iter().flat_map(|e| e.as_array().cloned().unwrap_or_default()) {
            let n = scalar_text(&n);
            self.vars.insert(
                n.clone(),
                callee_vars.get(&n).cloned().ok_or_else(|| {
                    fail(format!("call: `{n}` was not set by {}", path.display()))
                })?,
            );
        }
        let failed: Vec<String> = sub
            .iter()
            .filter(|s| s.status == "fail")
            .map(|s| {
                format!(
                    "{}:{} {}",
                    s.file,
                    s.line,
                    s.step_error.clone().unwrap_or_else(|| "assertion failed".into())
                )
            })
            .collect();
        r.report = json!({"steps": sub.len()});
        if !failed.is_empty() {
            bail!("call {name}: {} step(s) failed\n  {}", failed.len(), failed.join("\n  "))
        }
        Ok(self.it.clone())
    }

    // ---------- HTTP ----------
    async fn http(&mut self, item: &Item, r: &mut StepResult) -> Result<Value> {
        let rc = &item.opts.request;
        if rc.disabled.unwrap_or(false) {
            r.step_log = "Step disabled, skipping".into();
            r.assert_results = item.opts.asserts.iter().flatten().map(|_| Ok(true)).collect();
            return Ok(Value::Null);
        }
        let method = reqwest::Method::from_bytes(item.verb.as_bytes())?;
        let url = self.url(&item.text)?;
        if let Some(h) = &rc.pre_request_hook {
            if let Ok(v) = rhai::Engine::new().eval_expression::<String>(h) {
                r.step_log.push_str(&format!("pre-hook: {v}\n"))
            }
        }
        let mut c = reqwest::Client::builder().connection_verbose(true);
        if rc.http_version.as_deref() == Some("http-2") {
            c = c.http2_prior_knowledge()
        }
        c = c.timeout(Duration::from_millis(
            item.opts
                .timeout
                .as_ref()
                .and_then(dur)
                .or(rc.timeout.map(|s| s * 1000))
                .unwrap_or(30_000),
        ));
        if let Some(f) = rc.follow_redirects {
            c = c.redirect(if f {
                reqwest::redirect::Policy::limited(10)
            } else {
                reqwest::redirect::Policy::none()
            })
        }
        if rc.ignore_ssl_errors.unwrap_or(false) {
            c = c.danger_accept_invalid_certs(true)
        }
        let client = c.build()?;
        let mut b = client.request(method.clone(), &url).header("X-Testkit-Run", "true");
        let mut sent_headers = Map::new();
        if let Some(col) = &self.cfg.col_id {
            b = b.header("X-Testkit-Collection-ID", col);
            sent_headers.insert("X-Testkit-Collection-ID".into(), col.clone().into());
        }
        if let Some(p) = &rc.params {
            let q: Vec<(String, String)> = p
                .iter()
                .map(|(k, v)| Ok((self.render(k)?, self.render(v)?)))
                .collect::<Result<_>>()?;
            b = b.query(&q);
        }
        for (k, v) in rc.headers.iter().flatten() {
            let v = self.render(v)?;
            sent_headers.insert(k.clone(), v.clone().into());
            b = b.header(k, v);
        }
        if let Some(from) = &item.opts.cookies {
            let s = from.trim().trim_start_matches("from").trim().to_string();
            let t = self.tab(Some(&s)).await?;
            let cookies = t
                .page
                .get_cookies()
                .await?
                .iter()
                .map(|c| format!("{}={}", c.name, c.value))
                .collect::<Vec<_>>()
                .join("; ");
            b = b.header("Cookie", cookies);
        }
        let mut body_json = Value::Null;
        if let Some(j) = &rc.json {
            body_json = match j {
                Value::String(s) => {
                    serde_json::from_str(&self.render(s)?).unwrap_or(Value::String(self.render(s)?))
                }
                j => self.render_json(j)?,
            };
            b = b.json(&body_json);
        } else if let Some(rb) = &rc.request_body {
            let m: Map<String, Value> = rb
                .iter()
                .map(|(k, v)| Ok((k.clone(), Value::String(self.render(v)?))))
                .collect::<Result<_>>()?;
            b = b.body(serde_json::to_string(&m)?);
        } else if let Some(raw) = &rc.raw {
            b = b.body(self.render(raw)?)
        }
        let mut req_cfg = rc.clone();
        req_cfg.http_method =
            serde_json::from_value(json!({ item.verb.clone(): url.clone() })).unwrap_or_default();
        if !sent_headers.is_empty() {
            req_cfg.headers =
                Some(sent_headers.iter().map(|(k, v)| (k.clone(), scalar_text(v))).collect())
        }
        let base = self
            .vars
            .get("base_url")
            .map(scalar_text)
            .or(self.cfg.base_url.clone())
            .unwrap_or_default();
        let t0 = Instant::now();
        let route = self
            .routes
            .iter_mut()
            .rev()
            .find(|rt| rt.modify.is_none() && rt.matches(method.as_str(), &url, &base))
            .map(|rt| {
                rt.hits += 1;
                rt.clone()
            });
        let (status, headers, raw, mocked) = if let Some(rt) = route {
            if rt.delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(rt.delay_ms)).await
            }
            if rt.abort.is_some() {
                bail!("request to {url} failed: aborted by route `{}`", rt.pat)
            }
            let (s, body, hs) = response_parts(rt.respond.as_ref().unwrap_or(&json!({})));
            (
                s as u16,
                json!(hs.into_iter().map(|(k, v)| (k, json!([v]))).collect::<Map<_, _>>()),
                body,
                true,
            )
        } else {
            let resp = b.send().await.map_err(|e| anyhow!("request to {url} failed: {e}"))?;
            let status = resp.status().as_u16();
            let headers = json!(header_map_to_hashmap(resp.headers()));
            (status, headers, resp.text().await.unwrap_or_default(), false)
        };
        let mut json_body: Value = serde_json::from_str(&raw).unwrap_or(Value::Object(Map::new()));
        let base_ = base.clone();
        if let Some(rt) = self
            .routes
            .iter()
            .rev()
            .find(|rt| rt.modify.is_some() && rt.matches(method.as_str(), &url, &base_))
        {
            if let Some(p) = rt.modify.as_ref().and_then(|m| m.get("json")) {
                merge(&mut json_body, p)
            }
        }
        let ms = t0.elapsed().as_millis() as u64;
        if let Some(h) = &rc.post_response_hook {
            if let Ok(v) = rhai::Engine::new().eval_expression::<String>(h) {
                r.step_log.push_str(&format!("post-hook: {v}\n"))
            }
        }
        let rr = RequestAndResponse {
            req: req_cfg,
            resp: ResponseObject {
                status,
                headers: headers.clone(),
                json: json_body.clone(),
                raw: raw.clone(),
            },
        };
        let legacy = json!(&rr);
        if item.opts.dump.unwrap_or(false) {
            let d = format!(
                "💡 DUMP jsonpath request response context:\n {}",
                colored_json::to_colored_json_auto(&legacy).unwrap_or_else(|_| legacy.to_string())
            );
            println!("{d}");
            r.step_log.push_str(&d);
        }
        r.request = rr;
        self.legacy = Some(legacy);
        let it = json!({"status": status, "json": json_body, "headers": headers, "raw": raw, "duration": ms, "ms": ms, "url": url, "method": method.as_str(), "mocked": mocked, "body": body_json});
        self.api_reqs.push(Req {
            seq: self.api_reqs.len() as u64,
            method: method.to_string(),
            url: url.clone(),
            status: Some(status as i64),
            ms: ms as f64,
            mocked,
            kind: "api".into(),
            req: json!({"body": body_json}),
            headers: it["headers"].clone(),
            done: true,
            size: raw.len() as f64,
            ..Default::default()
        });
        self.last_http = it.clone();
        r.report = json!({"network": [format!("{} {} {status} {ms}ms{}", method, path_of(&url), if mocked { " (mocked)" } else { "" })]});
        Ok(it)
    }
    fn render_json(&self, v: &Value) -> Result<Value> {
        Ok(match v {
            Value::String(s) => {
                let segs = template(s).map_err(|e| anyhow!("{e}"))?;
                match segs.as_slice() {
                    [Seg::Expr(e)] => eval::eval(e, &self.ctx()).map_err(|e| anyhow!(e))?,
                    _ => Value::String(render(&segs, &self.ctx()).map_err(|e| anyhow!(e))?),
                }
            }
            Value::Array(a) => {
                Value::Array(a.iter().map(|x| self.render_json(x)).collect::<Result<_>>()?)
            }
            Value::Object(o) => Value::Object(
                o.iter()
                    .map(|(k, x)| Ok((k.clone(), self.render_json(x)?)))
                    .collect::<Result<_>>()?,
            ),
            v => v.clone(),
        })
    }

    // ---------- expressions ----------
    pub async fn value(&mut self, e: &Expr) -> Result<Value> {
        let mut qs = vec![];
        eval::queries(e, &self.vars, &mut qs);
        let resolved = self.resolve_all(&qs).await?;
        let mut c = self.ctx();
        c.resolved = resolved;
        eval::eval(e, &c).map_err(|e| anyhow!(e))
    }
    async fn resolve_all(&mut self, qs: &[Expr]) -> Result<HashMap<String, Value>> {
        let mut out = HashMap::new();
        for q in qs {
            if let Some(v) = Box::pin(self.resolve(q, None)).await? {
                out.insert(key(q), v);
            }
        }
        Ok(out)
    }
    /// One evaluation of a condition: (passed, actual value of the left side).
    async fn check_once(&mut self, c: &mut Cond) -> Result<(bool, Option<String>)> {
        let mut qs = vec![];
        eval::queries_cond(c, &self.vars, &mut qs);
        let resolved = self.resolve_all(&qs).await?;
        let mut ctx = self.ctx();
        ctx.resolved = resolved;
        let ok = test(c, &ctx).map_err(|e| anyhow!(e))?;
        Ok((ok, if ok { None } else { why(c, &ctx) }))
    }
    pub async fn check(&mut self, c: &Cond) -> Result<(bool, Option<String>)> {
        self.check_once(&mut c.clone()).await
    }

    async fn expect(&mut self, item: &Item, c: &Cond, within: Option<u64>) -> Result<Value> {
        if let Some(m) = &item.opts.matches {
            let Cond::Truthy(subject) = c else {
                bail!("`matches:` needs a bare subject or locator, e.g. `expect: table \"Orders\"`")
            };
            return self.structural(subject, m, within).await;
        }
        if self.cfg.update_baselines {
            if let Cond::Cmp { lhs, op: Op::Baseline(_, n), .. } = c {
                let v = self.value(lhs).await?;
                self.baselines.insert(n.clone(), v.clone());
                return Ok(json!({"baseline": n, "value": v}));
            }
        }
        let mut qs = vec![];
        eval::queries_cond(c, &self.vars, &mut qs);
        let timeout = within.unwrap_or(self.cfg.expect_ms);
        let t = Instant::now();
        let mut last = (false, None);
        loop {
            match self.check(c).await {
                Ok(r) => last = r,
                Err(e) if qs.is_empty() || t.elapsed().as_millis() as u64 >= timeout => {
                    bail!("E_ASSERT {e}")
                }
                Err(_) => {}
            }
            if last.0 || qs.is_empty() || t.elapsed().as_millis() as u64 >= timeout {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        if let Some((ok, note)) = self.sample_gate(c).await? {
            last = (ok, Some(note.clone()));
            log::info!(target: "testkit", "{note}");
        }
        let lhs = match c {
            Cond::Cmp { lhs, .. } | Cond::No(lhs) | Cond::Some(lhs) | Cond::Truthy(lhs) => {
                Some(lhs.clone())
            }
            _ => None,
        };
        let subj = match &lhs {
            Some(l) => self.value(l).await.unwrap_or(Value::Null),
            None => Value::Null,
        };
        if !last.0 {
            if let (Some(Expr::Loc(l)), Value::Array(a)) = (&lhs, &subj) {
                if a.is_empty() && self.tabs.contains_key(&self.cur_b) {
                    let needle = match &l.name {
                        Some(Name::Sub(s) | Name::Exact(s)) => {
                            s.split_whitespace().next().unwrap_or("").to_string()
                        }
                        _ => String::new(),
                    };
                    let near = self.tabs[&self.cur_b]
                        .tk("find", &[json!(needle)])
                        .await
                        .ok()
                        .and_then(|v| v.as_array().cloned())
                        .unwrap_or_default();
                    let near: Vec<String> = near
                        .iter()
                        .filter_map(|n| n["locator"].as_str().map(String::from))
                        .take(5)
                        .collect();
                    if !needle.is_empty() && !near.is_empty() {
                        bail!("E_ASSERT expected `{}` within {timeout}ms\n    actual    `{l}` matches nothing; nearby: {}", item.text, near.join(" · "));
                    }
                }
            }
            bail!(
                "E_ASSERT expected `{}`{}\n    actual    {}",
                item.text,
                if qs.is_empty() { String::new() } else { format!(" within {timeout}ms") },
                last.1.unwrap_or_else(|| "(no value)".into())
            );
        }
        Ok(subj)
    }

    /// Perf gate (spec §11): a web-vital comparison within 10% of its threshold is re-sampled
    /// (page reloads) up to 5 times and decided on the median.
    async fn sample_gate(&mut self, c: &Cond) -> Result<Option<(bool, String)>> {
        let Cond::Cmp { lhs, op, rhs, neg, .. } = c else { return Ok(None) };
        let Expr::Prop(base, Prop::Name(metric)) = lhs else { return Ok(None) };
        if !matches!(&**base, Expr::Subj(Subject::Page))
            || !["lcp", "cls", "inp", "fcp", "ttfb"].contains(&metric.as_str())
        {
            return Ok(None);
        }
        let limit = match (op, rhs) {
            (Op::Lt | Op::Le | Op::Gt | Op::Ge, Some(r)) => eval::num(&self.value(r).await?),
            (Op::Baseline(pct, n), _) => {
                load_baselines().get(n).and_then(eval::num).map(|b| b * (1.0 + pct / 100.0))
            }
            _ => None,
        };
        let (Some(limit), Some(first)) = (limit, eval::num(&self.value(lhs).await?)) else {
            return Ok(None);
        };
        if limit == 0.0 || ((first - limit) / limit).abs() > 0.1 {
            return Ok(None);
        }
        let mut xs = vec![first];
        for _ in 0..4 {
            let t = self.tab(None).await?;
            t.eval_raw("location.reload()").await.ok();
            tokio::time::sleep(Duration::from_millis(100)).await;
            t.wait_load().await;
            if let Some(v) = eval::num(&self.value(lhs).await?) {
                xs.push(v)
            }
        }
        xs.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let med = xs[xs.len() / 2];
        let pass = match op {
            Op::Lt => med < limit,
            Op::Le | Op::Baseline(..) => med <= limit,
            Op::Gt => med > limit,
            _ => med >= limit,
        } ^ neg;
        Ok(Some((pass, format!("median {metric} {med:.3} of {} samples (limit {limit:.3}); near the threshold, so re-sampled", xs.len()))))
    }

    async fn structural(
        &mut self,
        subject: &Expr,
        m: &Value,
        within: Option<u64>,
    ) -> Result<Value> {
        let timeout = within.unwrap_or(self.cfg.expect_ms);
        let t = Instant::now();
        loop {
            let res = self.structural_once(subject, m).await;
            match res {
                Ok(v) => return Ok(v),
                Err(e) if t.elapsed().as_millis() as u64 >= timeout => return Err(e),
                Err(_) => tokio::time::sleep(Duration::from_millis(150)).await,
            }
        }
    }
    async fn structural_once(&mut self, subject: &Expr, m: &Value) -> Result<Value> {
        let subject = &match subject {
            Expr::Loc(l) => Expr::Loc(self.bind(l)?),
            e => e.clone(),
        };
        let is_browser_tree = matches!(subject, Expr::Loc(l) if self.surface("expect", Some(l)) == Surf::Browser)
            || (matches!(subject, Expr::Subj(Subject::Page)));
        if is_browser_tree && m.is_array() {
            let t = self.tab(None).await?;
            let loc = if let Expr::Loc(l) = subject { loc_json(l) } else { Value::Null };
            let snap =
                t.tk("snapshot", &[loc, json!({"all": true, "refs": false, "max": 400})]).await?;
            let tree = snap["tree"].as_array().cloned().unwrap_or_default();
            return match aria_match(m.as_array().unwrap(), &tree) {
                Ok(()) => Ok(json!(snap["yaml"])),
                Err(miss) => bail!(
                    "E_ASSERT structure does not match: missing {miss}\n  actual:\n{}",
                    indent(&scalar_text(&snap["yaml"]), 4)
                ),
            };
        }
        let actual = self.value(subject).await?;
        if let Value::String(path) = m {
            let golden = self.dir.join(path);
            let text = match &actual {
                Value::Object(o) if o.contains_key("text") => scalar_text(&o["text"]),
                v => to_str(v),
            };
            if self.cfg.update_golden || !golden.exists() {
                if let Some(p) = golden.parent() {
                    std::fs::create_dir_all(p).ok();
                }
                std::fs::write(&golden, &text)?;
                return Ok(json!({"golden": path, "updated": true}));
            }
            let want = std::fs::read_to_string(&golden)?;
            if want.trim_end() == text.trim_end() {
                return Ok(json!({"golden": path}));
            }
            bail!(
                "E_ASSERT does not match golden {path} (refresh with --update-golden)\n{}",
                line_diff(&want, &text)
            );
        }
        if let (Value::Array(lines), false) = (
            m,
            actual.is_array()
                || (actual.is_object()
                    && actual.get("screen").is_none()
                    && actual.get("text").is_none()),
        ) {
            let text = match &actual {
                Value::Object(o) if o.contains_key("screen") => scalar_text(&o["screen"]),
                v => to_str(v),
            };
            let mut it = text.lines();
            for want in lines {
                let w = scalar_text(want);
                let re = w
                    .strip_prefix('/')
                    .and_then(|s| s.rsplit_once('/'))
                    .map(|(r, f)| {
                        regex::RegexBuilder::new(r).case_insensitive(f.contains('i')).build()
                    })
                    .transpose()?;
                if !it.by_ref().any(|l| re.as_ref().map_or(l.contains(&w), |re| re.is_match(l))) {
                    bail!(
                        "E_ASSERT line not found (in order): {w}\n  actual:\n{}",
                        indent(&text, 4)
                    );
                }
            }
            return Ok(Value::String(text));
        }
        if shape_match(&actual, m) {
            Ok(actual)
        } else {
            bail!("E_ASSERT shape does not match\n  expected {}\n  actual   {}", m, short(&actual))
        }
    }

    async fn wait(&mut self, evs: &[Event], timeout: Option<u64>) -> Result<Value> {
        if let [Event::Dur(d)] = evs {
            tokio::time::sleep(Duration::from_millis(*d as u64)).await;
            return Ok(json!(d));
        }
        let limit = evs
            .iter()
            .find_map(|e| if let Event::Dur(d) = e { Some(*d as u64) } else { None })
            .or(timeout)
            .unwrap_or(self.cfg.nav_ms);
        let start_url = match self.tabs.get(&self.cur_b) {
            Some(t) => t.url().await,
            None => String::new(),
        };
        let marks = self.prev.clone();
        let t0 = Instant::now();
        loop {
            for e in evs {
                if let Some(v) = self.event_hit(e, &marks, &start_url).await? {
                    return Ok(v);
                }
            }
            if t0.elapsed().as_millis() as u64 >= limit {
                let what: Vec<String> = evs
                    .iter()
                    .filter(|e| !matches!(e, Event::Dur(_)))
                    .map(|e| format!("{e:?}"))
                    .collect();
                let ctx = match self.last {
                    Surf::Term => self
                        .pty(None)
                        .map(|p| format!("\n  screen:\n{}", indent(&p.screen(), 4)))
                        .unwrap_or_default(),
                    _ => String::new(),
                };
                bail!("E_TIMEOUT waited {limit}ms for {}{ctx}", what.join(" or "));
            }
            tokio::time::sleep(Duration::from_millis(80)).await;
        }
    }
    async fn event_hit(
        &mut self,
        e: &Event,
        marks: &Marks,
        start_url: &str,
    ) -> Result<Option<Value>> {
        let tab_since = |name: &str| marks.tabs.get(name).copied().unwrap_or((0, 0));
        Ok(match e {
            Event::Dur(_) => None,
            Event::Cond(c) => self.check(c).await.ok().filter(|r| r.0).map(|_| json!(true)),
            Event::Navigation => {
                let t = self.tab(None).await?;
                let u = t.url().await;
                (u != start_url
                    && t.eval_raw("document.readyState").await.ok() == Some(json!("complete")))
                .then(|| json!({"url": u}))
            }
            Event::Dialog => self
                .tabs
                .get(&self.cur_b)
                .and_then(|t| t.log.lock().unwrap().dialogs.last().cloned())
                .map(|d| json!({"message": d})),
            Event::Download(into) => {
                let dir = std::env::current_dir().unwrap_or_default().join(".testkit/downloads");
                let newest = std::fs::read_dir(&dir).ok().and_then(|d| {
                    d.filter_map(|e| e.ok())
                        .filter(|e| !e.file_name().to_string_lossy().ends_with(".crdownload"))
                        .filter_map(|e| Some((e.metadata().ok()?.modified().ok()?, e.path())))
                        .max_by_key(|x| x.0)
                });
                let d = newest
                    .filter(|(t, _)| {
                        t.elapsed().map(|e| e < Duration::from_secs(60)).unwrap_or(false)
                    })
                    .map(|(_, p)| p.to_string_lossy().to_string());
                if let (Some(d), Some(n)) = (&d, into) {
                    self.vars.insert(n.clone(), json!(d));
                }
                d.map(|d| json!({"file": d}))
            }
            Event::Popup(into) => {
                use chromiumoxide::cdp::browser_protocol::target as tg;
                let me = self.tab(None).await?.page.target_id().clone();
                let infos = self
                    .chrome()
                    .await?
                    .browser
                    .execute(tg::GetTargetsParams::default())
                    .await?
                    .target_infos
                    .clone();
                let ctx = infos
                    .iter()
                    .find(|t| t.target_id == me)
                    .and_then(|t| t.browser_context_id.clone());
                let fresh = infos.into_iter().find(|t| {
                    t.r#type == "page"
                        && t.browser_context_id == ctx
                        && t.target_id != me
                        && !self.known_pages.contains(t.target_id.inner())
                });
                match fresh {
                    Some(t) => {
                        let id = t.target_id.clone();
                        self.known_pages.push(id.inner().clone());
                        let tab = self.chrome().await?.adopt(id).await?;
                        tab.wait_load().await;
                        let name = into.clone().unwrap_or_else(|| "popup".into());
                        let st = tab.page_state().await;
                        self.tabs.insert(name.clone(), tab);
                        self.cur_b = name.clone();
                        self.front = name.clone();
                        Some(json!({"session": name, "page": st}))
                    }
                    None => None,
                }
            }
            Event::Request(m, p) | Event::Response(m, p) => {
                let want_resp = matches!(e, Event::Response(..));
                let base = self.base();
                let (since, _) = tab_since(&self.cur_b);
                let t = self.tabs.get(&self.cur_b);
                let hit = t.and_then(|t| {
                    t.log
                        .lock()
                        .unwrap()
                        .reqs
                        .iter()
                        .skip(since)
                        .find(|r| {
                            m.as_deref().is_none_or(|m| m.eq_ignore_ascii_case(&r.method))
                                && url_match(p, &r.url, &base)
                                && (!want_resp || r.done)
                        })
                        .cloned()
                });
                hit.map(|r| serde_json::to_value(r).unwrap_or_default())
            }
            Event::Console(n) => {
                let (_, since) = tab_since(&self.cur_b);
                self.tabs.get(&self.cur_b).and_then(|t| {
                    t.log
                        .lock()
                        .unwrap()
                        .console
                        .iter()
                        .skip(since)
                        .find(|m| name_match(n, &m.text))
                        .map(|m| json!({"text": m.text, "level": m.level}))
                })
            }
            Event::Text(n, sess) => {
                let n = &match n {
                    Name::Tmpl(segs) => {
                        Name::Sub(render(segs, &self.ctx()).map_err(|e| anyhow!(e))?)
                    }
                    n => n.clone(),
                };
                let is_term =
                    sess.as_ref().map_or(self.last == Surf::Term, |s| self.ptys.contains_key(s));
                if is_term {
                    let name = sess.clone().or(self.cur_t.clone()).unwrap_or_default();
                    let since = marks.ptys.get(&name).copied().unwrap_or(0);
                    let p = self.pty(Some(&name))?;
                    let out = p.output_since(since);
                    let hit = text_hit(n, &out);
                    if hit.is_none() {
                        if let Some(code) = p.exit() {
                            bail!("`{}` exited with code {code} before printing {}", p.cmd, n)
                        }
                    }
                    hit
                } else {
                    let l =
                        Locator { head: Head::Text, name: Some(n.clone()), ..Default::default() };
                    let t = self.tab(sess.as_deref()).await?;
                    let els = t.resolve(&l).await?;
                    els.first().map(|e| json!({"text": e["text"], "match": regex_groups(n, &scalar_text(&e["text"]))}))
                }
            }
        })
    }
    fn base(&self) -> String {
        self.vars.get("base_url").map(scalar_text).or(self.cfg.base_url.clone()).unwrap_or_default()
    }

    /// Resolves a subject/locator/session query (spec §3.3 windows: since the previous step).
    async fn resolve(&mut self, q: &Expr, session: Option<String>) -> Result<Option<Value>> {
        Ok(Some(match q {
            Expr::In(e, s) => return Box::pin(self.resolve(e, Some(s.clone()))).await,
            Expr::Var(v) => {
                if let Some(n) = v.strip_prefix("baseline:") {
                    if self.baselines.is_empty() {
                        self.baselines = load_baselines();
                    }
                    return Ok(self.baselines.get(n).cloned());
                }
                if let Some(p) = self.ptys.get(v) {
                    p.state()
                } else if let Some(t) = self.tabs.get(v) {
                    t.page_state().await
                } else {
                    return Ok(None);
                }
            }
            Expr::Loc(l) => {
                let l = &self.bind(l)?;
                let sess = session.or_else(|| {
                    l.scope.iter().find_map(|s| {
                        if let Scope::Session(n) = s {
                            Some(n.clone())
                        } else {
                            None
                        }
                    })
                });
                let term =
                    sess.as_ref().map_or(self.surface("expect", Some(l)) == Surf::Term, |s| {
                        self.ptys.contains_key(s)
                    });
                if term {
                    let p = self.pty(sess.as_deref())?;
                    match &l.head {
                        Head::Line(n) => json!([p.line(*n)]),
                        Head::LastLine => json!([p.line(-1)]),
                        _ => {
                            let nm = l.name.clone();
                            json!(p.find(&|line: &str| nm
                                .as_ref()
                                .is_none_or(|n| name_match(n, line))))
                        }
                    }
                } else {
                    let t = self.tab(sess.as_deref()).await?;
                    Value::Array(t.resolve(l).await?)
                }
            }
            Expr::Subj(s) => {
                match s {
                    Subject::Json => {
                        if self.it.get("json").is_some() {
                            self.it["json"].clone()
                        } else {
                            self.last_http["json"].clone()
                        }
                    }
                    Subject::Status => {
                        if self.it.get("status").is_some() {
                            self.it["status"].clone()
                        } else {
                            self.last_http["status"].clone()
                        }
                    }
                    Subject::Headers => self.last_http["headers"].clone(),
                    Subject::Response => self.last_http.clone(),
                    Subject::Stdout | Subject::Stderr | Subject::Exit
                        if session.is_none()
                            && self.it.get("exit").is_some()
                            && self.it.get("stdout").is_some() =>
                    {
                        self.it[match s {
                            Subject::Stdout => "stdout",
                            Subject::Stderr => "stderr",
                            _ => "exit",
                        }]
                        .clone()
                    }
                    Subject::Exit => json!(self.pty(session.as_deref())?.exit()),
                    Subject::Stderr | Subject::Stdout => {
                        let p = self.pty(session.as_deref())?;
                        json!(p.output_since(0))
                    }
                    Subject::Screen => {
                        json!({"screen": self.pty(session.as_deref())?.screen(), "text": self.pty(session.as_deref())?.screen()})
                    }
                    Subject::Cursor => self.pty(session.as_deref())?.cursor(),
                    Subject::Output(all) => {
                        let name = session.clone().or(self.cur_t.clone()).unwrap_or_default();
                        let since =
                            if *all { 0 } else { self.prev.ptys.get(&name).copied().unwrap_or(0) };
                        json!(self.pty(Some(&name))?.output_since(since))
                    }
                    Subject::File(e) => {
                        let p = to_str(&self.value(e).await?);
                        let path = self.dir.join(&p);
                        match std::fs::read(&path) {
                            Ok(bytes) => {
                                let text = String::from_utf8_lossy(&bytes).to_string();
                                json!({"path": p, "exists": true, "size": bytes.len(), "json": serde_json::from_str::<Value>(&text).unwrap_or(Value::Null), "text": text})
                            }
                            Err(_) => return Ok(Some(Value::Null)),
                        }
                    }
                    Subject::Files(e) => {
                        let rel = to_str(&self.value(e).await?);
                        let p = self.dir.join(rel);
                        json!(std::fs::read_dir(p)
                            .map(|d| d
                                .filter_map(|e| e.ok())
                                .map(|e| e.file_name().to_string_lossy().to_string())
                                .collect::<Vec<_>>())
                            .unwrap_or_default())
                    }
                    Subject::Page => {
                        let t = self.tab(session.as_deref()).await?;
                        let mut p = t.page_state().await;
                        let v = stable_vitals(t).await;
                        if let Some(o) = v.as_object() {
                            for (k, x) in o {
                                p[k] = x.clone()
                            }
                        }
                        if let Ok(m) = t.page.metrics().await {
                            for (n, k) in [
                                ("JSHeapUsedSize", "heap"),
                                ("Nodes", "nodes"),
                                ("LayoutCount", "layouts"),
                                ("ScriptDuration", "script"),
                            ] {
                                if let Some(x) = m.iter().find(|x| x.name == n) {
                                    p[k] = json!(if k == "script" {
                                        x.value * 1000.0
                                    } else {
                                        x.value
                                    })
                                }
                            }
                        }
                        p
                    }
                    Subject::Focused => {
                        let t = self.tab(session.as_deref()).await?;
                        t.eval_raw("window.__tk && document.activeElement ? window.__tk.describe(document.activeElement) : null").await?
                    }
                    Subject::Cookie(n) => {
                        let t = self.tab(session.as_deref()).await?;
                        t.page
                            .get_cookies()
                            .await?
                            .into_iter()
                            .find(|c| &c.name == n)
                            .map(|c| json!(c.value))
                            .unwrap_or(Value::Null)
                    }
                    Subject::LongTasks(over) => {
                        let t = self.tab(session.as_deref()).await?;
                        let v = t.tk("vitals", &[]).await?;
                        json!(v["long"]
                            .as_array()
                            .cloned()
                            .unwrap_or_default()
                            .into_iter()
                            .filter(|d| d.as_f64().unwrap_or(0.0) > over.unwrap_or(50.0))
                            .collect::<Vec<_>>())
                    }
                    Subject::A11y => {
                        let t = self.tab(session.as_deref()).await?;
                        t.tk("a11y", &[Value::Null]).await?
                    }
                    Subject::Console(all, level) => {
                        let name = session.clone().unwrap_or(self.cur_b.clone());
                        let since = if *all {
                            0
                        } else {
                            self.prev.tabs.get(&name).map(|m| m.1).unwrap_or(0)
                        };
                        match self.tabs.get(&name) {
                        Some(t) => json!(t.log.lock().unwrap().console.iter().skip(since).filter(|m| match level.as_deref() {
                            Some("error") => m.level == "error" || m.level == "pageerror", Some("warning") => m.level == "warning", _ => true,
                        }).map(|m| json!({"level": m.level, "text": m.text, "source": m.source})).collect::<Vec<_>>()),
                        None => json!([]),
                    }
                    }
                    Subject::Request(pos, m, pat) => {
                        self.requests(pos, m.as_deref(), pat, session).await?
                    }
                }
            }
            _ => return Ok(None),
        }))
    }
    async fn requests(
        &mut self,
        pos: &Pos,
        m: Option<&str>,
        pat: &str,
        session: Option<String>,
    ) -> Result<Value> {
        let base = self.base();
        let pat = self.render(pat)?;
        let name = session.unwrap_or(self.cur_b.clone());
        let windowed = *pos == Pos::Latest;
        let (since_tab, since_api) = if windowed {
            (self.prev.tabs.get(&name).map(|m| m.0).unwrap_or(0), self.prev.api)
        } else {
            (0, 0)
        };
        let mut all: Vec<(Req, bool)> =
            self.api_reqs.iter().skip(since_api).cloned().map(|r| (r, false)).collect();
        if let Some(t) = self.tabs.get(&name) {
            all.extend(
                t.log.lock().unwrap().reqs.iter().skip(since_tab).cloned().map(|r| (r, true)),
            );
        }
        let hits: Vec<(Req, bool)> = all
            .into_iter()
            .filter(|(r, _)| {
                m.is_none_or(|m| m.eq_ignore_ascii_case(&r.method))
                    && url_match(&pat, &r.url, &base)
            })
            .collect();
        let pick = match pos {
            Pos::First => hits.first().cloned().into_iter().collect(),
            Pos::Latest | Pos::Last => hits.last().cloned().into_iter().collect(),
            _ => hits,
        };
        let mut out = vec![];
        for (r, browser) in pick {
            let mut v = json!({"method": r.method, "url": r.url, "path": path_of(&r.url), "status": r.status, "ms": r.ms, "duration": r.ms, "size": r.size, "mocked": r.mocked, "failed": r.failed, "headers": r.headers, "request": r.req});
            if browser && r.done && r.failed.is_none() {
                let mut body = r.body.clone();
                if body.is_none() {
                    if let Some(t) = self.tabs.get(&name) {
                        if let Ok(b) = t.page.execute(chromiumoxide::cdp::browser_protocol::network::GetResponseBodyParams::new(r.id.clone())).await {
                            use base64::Engine;
                            body = Some(if b.base64_encoded { String::from_utf8_lossy(&base64::engine::general_purpose::STANDARD.decode(&b.body).unwrap_or_default()).to_string() } else { b.body.clone() });
                        }
                    }
                }
                if let Some(body) = body {
                    v["json"] = serde_json::from_str(&body).unwrap_or(Value::Null);
                    v["raw"] = json!(body.chars().take(20_000).collect::<String>());
                }
            } else if !browser {
                v["json"] = self
                    .api_reqs
                    .iter()
                    .find(|a| a.seq == r.seq)
                    .map(|_| self.last_http["json"].clone())
                    .unwrap_or_default();
            }
            out.push(v);
        }
        Ok(match pos {
            Pos::Every | Pos::All => Value::Array(out),
            _ => out.into_iter().next().unwrap_or(Value::Null),
        })
    }

    pub async fn close(&mut self) {
        self.tabs.clear();
        self.ptys.clear();
        if let Some(c) = self.chrome.take() {
            c.close().await
        }
    }
}

/// The failing part of a condition and its actual value, for E_ASSERT messages.
fn why(c: &Cond, ctx: &Ctx) -> Option<String> {
    match c {
        Cond::All(cs) => cs.iter().find(|x| test(x, ctx).ok() == Some(false)).and_then(|x| {
            why(x, ctx).map(|w| {
                if matches!(x, Cond::All(_) | Cond::Any(_)) {
                    w
                } else {
                    format!("{w}   (in the failing part `{}`)", cond_text(x))
                }
            })
        }),
        Cond::Any(cs) => Some(cs.iter().filter_map(|x| why(x, ctx)).collect::<Vec<_>>().join("; ")),
        Cond::Not(x) => why(x, ctx).or(Some("the negated condition held".into())),
        Cond::Cmp { lhs, .. } | Cond::No(lhs) | Cond::Some(lhs) | Cond::Truthy(lhs) => {
            eval::eval(lhs, ctx).ok().map(|v| short(&v))
        }
    }
}
fn cond_text(c: &Cond) -> String {
    match c {
        Cond::Cmp { lhs, op, .. } => format!("{} {:?}", expr_text(lhs), op),
        c => format!("{c:?}").chars().take(80).collect(),
    }
}
fn expr_text(e: &Expr) -> String {
    match e {
        Expr::Var(v) => v.clone(),
        Expr::Loc(l) => l.to_string(),
        Expr::Prop(b, Prop::Name(n)) => format!("the {n} of {}", expr_text(b)),
        e => format!("{e:?}").chars().take(60).collect(),
    }
}

async fn stable_vitals(t: &Tab) -> Value {
    let start = Instant::now();
    loop {
        let v = t.tk("vitals", &[]).await.unwrap_or_default();
        let ready = v["ready"] == "complete"
            && (v["lcp"].is_null() || v["lcpAge"].as_f64().unwrap_or(0.0) > 1000.0);
        if ready || start.elapsed() > Duration::from_secs(4) {
            return json!({"lcp": v["lcp"], "cls": v["cls"], "inp": v["inp"], "fcp": v["fcp"], "ttfb": v["ttfb"]});
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
}

async fn deterministic(t: &Tab) -> Result<()> {
    use chromiumoxide::cdp::browser_protocol::emulation;
    t.page.execute(emulation::SetTimezoneOverrideParams::new("UTC")).await?;
    t.page.execute(emulation::SetLocaleOverrideParams::builder().locale("en-US").build()).await?;
    t.emulate("reduced-motion").await?;
    t.page.execute(chromiumoxide::cdp::browser_protocol::page::AddScriptToEvaluateOnNewDocumentParams::new(
        "(()=>{let s=42;Math.random=()=>((s=Math.imul(48271,s)%2147483647)&2147483647)/2147483647;const D=Date;const T0=new D('2026-01-01T09:00:00Z').getTime();const p0=performance.now();globalThis.Date=class extends D{constructor(...a){super(...(a.length?a:[T0+performance.now()-p0]))}static now(){return T0+performance.now()-p0}};addEventListener('DOMContentLoaded',()=>{const st=document.createElement('style');st.textContent='*,*::before,*::after{transition:none!important;animation:none!important;caret-color:transparent!important}';document.head.appendChild(st)})})()",
    )).await?;
    Ok(())
}

pub fn load_baselines() -> Map<String, Value> {
    std::fs::read_to_string(".testkit/baselines.json")
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn name_match(n: &Name, s: &str) -> bool {
    match n {
        Name::Sub(x) => s.to_lowercase().contains(&x.to_lowercase()),
        Name::Exact(x) => s.trim() == x.trim(),
        Name::Re(r, f) => regex::RegexBuilder::new(r)
            .case_insensitive(f.contains('i'))
            .build()
            .is_ok_and(|re| re.is_match(s)),
        Name::Tmpl(_) => false,
    }
}
fn regex_groups(n: &Name, s: &str) -> Value {
    if let Name::Re(r, f) = n {
        if let Ok(re) = regex::RegexBuilder::new(r).case_insensitive(f.contains('i')).build() {
            if let Some(c) = re.captures(s) {
                return json!(c
                    .iter()
                    .map(|m| m.map(|m| m.as_str().to_string()))
                    .collect::<Vec<_>>());
            }
        }
    }
    json!([s])
}
fn text_hit(n: &Name, out: &str) -> Option<Value> {
    out.lines()
        .find(|l| name_match(n, l))
        .map(|l| json!({"text": l.trim(), "match": regex_groups(n, l)}))
}
pub fn path_of(url: &str) -> String {
    url.split_once("://")
        .map(|(_, r)| r.find('/').map_or("/".to_string(), |i| r[i..].to_string()))
        .unwrap_or_else(|| url.to_string())
}
pub fn short(v: &Value) -> String {
    let s = match v {
        Value::String(s) => format!("{s:?}"),
        v => v.to_string(),
    };
    if s.chars().count() > 300 {
        format!("{}…", s.chars().take(300).collect::<String>())
    } else {
        s
    }
}
fn indent(s: &str, n: usize) -> String {
    s.lines().map(|l| format!("{}{l}", " ".repeat(n))).collect::<Vec<_>>().join("\n")
}
fn assert_text(a: &Assert) -> String {
    serde_json::to_value(a)
        .ok()
        .and_then(|v| v.as_object().and_then(|o| o.values().next().map(scalar_text)))
        .unwrap_or_default()
}
fn line_diff(want: &str, got: &str) -> String {
    let (w, g): (Vec<&str>, Vec<&str>) = (want.lines().collect(), got.lines().collect());
    let mut out = vec![];
    for i in 0..w.len().max(g.len()) {
        match (w.get(i), g.get(i)) {
            (Some(a), Some(b)) if a == b => {}
            (a, b) => {
                if let Some(a) = a {
                    out.push(format!("  - {a}"))
                }
                if let Some(b) = b {
                    out.push(format!("  + {b}"))
                }
            }
        }
        if out.len() > 30 {
            break;
        }
    }
    out.join("\n")
}

/// Partial, in-order JSON shape match: objects are subsets, arrays match items in order.
///
/// ```
/// use testkit::runner::shape_match;
/// use serde_json::json;
/// assert!(shape_match(&json!({"orders": [{"id": 1, "status": "paid"}, {"id": 2}], "n": 2}), &json!({"orders": [{"status": "paid"}]})));
/// assert!(!shape_match(&json!({"orders": []}), &json!({"orders": [{"status": "paid"}]})));
/// ```
pub fn shape_match(actual: &Value, want: &Value) -> bool {
    match (actual, want) {
        (Value::Object(a), Value::Object(w)) => {
            w.iter().all(|(k, wv)| a.get(k).is_some_and(|av| shape_match(av, wv)))
        }
        (Value::Array(a), Value::Array(w)) => {
            let mut it = a.iter();
            w.iter().all(|wv| it.any(|av| shape_match(av, wv)))
        }
        (a, Value::String(w)) if w.starts_with('/') && w.len() > 2 && w.ends_with('/') => {
            regex::Regex::new(&w[1..w.len() - 1]).is_ok_and(|r| r.is_match(&scalar_text(a)))
        }
        (a, w) => {
            a == w
                || (a.as_f64().is_some() && a.as_f64() == w.as_f64())
                || scalar_text(a) == scalar_text(w)
        }
    }
}

/// Playwright-style partial aria-snapshot matching (spec §8). Returns the first missing node on failure.
pub fn aria_match(want: &[Value], actual: &[Value]) -> Result<(), String> {
    let strict = want.iter().any(|w| w.get("/children").and_then(Value::as_str) == Some("equal"));
    let want: Vec<&Value> = want.iter().filter(|w| w.get("/children").is_none()).collect();
    if strict {
        if want.len() != actual.len() {
            return Err(format!("exactly {} children, found {}", want.len(), actual.len()));
        }
        for (w, a) in want.iter().zip(actual) {
            node_match(w, a)?
        }
        return Ok(());
    }
    fn flat<'a>(ns: &'a [Value], out: &mut Vec<&'a Value>) {
        for n in ns {
            out.push(n);
            flat(n["children"].as_array().map(|v| v.as_slice()).unwrap_or(&[]), out)
        }
    }
    let mut all = vec![];
    flat(actual, &mut all);
    let mut pos = 0;
    for w in want {
        let found = all[pos..].iter().position(|a| node_match(w, a).is_ok());
        match found {
            Some(i) => pos += i + 1,
            None => {
                let deepest = all[pos..]
                    .iter()
                    .filter_map(|a| node_match(w, a).err().filter(|e| e.contains(" > ")))
                    .next();
                return Err(deepest.unwrap_or_else(|| spec_text(w)));
            }
        }
    }
    Ok(())
}
fn spec_text(w: &Value) -> String {
    match w {
        Value::String(s) => s.clone(),
        Value::Object(o) => o.keys().next().cloned().unwrap_or_default(),
        v => v.to_string(),
    }
}
fn node_match(w: &Value, a: &Value) -> Result<(), String> {
    let (line, kids, value) = match w {
        Value::String(s) => (s.clone(), None, None),
        Value::Object(o) if o.len() == 1 => {
            let (k, v) = o.iter().next().unwrap();
            match v {
                Value::Array(c) => (k.clone(), Some(c.clone()), None),
                v => (k.clone(), None, Some(scalar_text(v))),
            }
        }
        _ => return Err(w.to_string()),
    };
    let (role, name, states) =
        crate::expr::parse::aria_line(&line).map_err(|e| format!("{line} ({e})"))?;
    let ar = scalar_text(&a["role"]);
    if role == "text" {
        let t = format!("{}{}", scalar_text(&a["text"]), scalar_text(&a["name"]));
        let want = value
            .clone()
            .or(name.as_ref().map(|n| n.to_string().trim_matches('"').to_string()))
            .unwrap_or_default();
        return if ar == "text" || !t.is_empty() {
            if t.to_lowercase().contains(&want.to_lowercase())
                || name.as_ref().is_some_and(|n| name_match(n, &t))
            {
                Ok(())
            } else {
                Err(line)
            }
        } else {
            Err(line)
        };
    }
    if ar != role {
        return Err(line);
    }
    if let Some(n) = &name {
        if !name_match(n, &scalar_text(&a["name"])) {
            return Err(line);
        }
    }
    let have: Vec<String> =
        a["states"].as_array().map(|s| s.iter().map(scalar_text).collect()).unwrap_or_default();
    if let Some(s) = states.iter().find(|s| !have.contains(s)) {
        return Err(format!("{line} (not {s})"));
    }
    if let Some(v) = value {
        let got = format!("{}{}", scalar_text(&a["value"]), scalar_text(&a["text"]));
        if !got.contains(&v) {
            return Err(format!("{line}: {v}"));
        }
    }
    if let Some(k) = kids {
        aria_match(&k, a["children"].as_array().map(|v| v.as_slice()).unwrap_or(&[]))
            .map_err(|e| format!("{line} > {e}"))?
    }
    Ok(())
}
