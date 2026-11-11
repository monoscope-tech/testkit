//! Executes items across surfaces: sessions, observation windows, guard, claims and step reports.
//! Verbs live in `steps`, expressions/waits/subjects in `resolve`, step reports and the guard in `report`.
mod device;
mod report;
mod resolve;
mod steps;
use crate::base_request::{
    curl, header_map_to_hashmap, report_error, typed_assert, Assert, AssertionError,
    RequestAndResponse, ResponseObject,
};
use crate::browser::{loc_json, merge, response_parts, url_match, Chrome, Req, Route, Tab};
use crate::expr::eval::{self, key, render, test, to_str, Ctx};
use crate::expr::parse::{args, template, Args};
use crate::expr::*;
use crate::item::{parse_yaml, scalar_text, Item, HTTP};
use crate::term::{self, Pty};
use anyhow::{anyhow, bail, Result};
pub(crate) use report::*;
pub use report::{path_of, short};
pub use resolve::{aria_match, load_baselines, name_match, shape_match};
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct Config {
    pub base_url: Option<String>,
    pub headed: bool,
    /// Drive Firefox over WebDriver BiDi instead of Chromium.
    pub firefox: bool,
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
    pub policy: Option<crate::policy::Policy>,
    /// Approximate tokens per step reply.
    pub budget: usize,
}
impl Default for Config {
    fn default() -> Self {
        Config {
            base_url: None,
            headed: false,
            firefox: false,
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
            policy: None,
            budget: 2000,
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
    Mobile,
}

#[derive(Clone, Default, Debug)]
pub(crate) struct Marks {
    tabs: HashMap<String, (usize, usize)>,
    api: usize,
    ptys: HashMap<String, usize>,
}

/// Called after every step (live reporting).
pub type OnStep = Box<dyn FnMut(&StepResult) + Send>;
/// One Chrome shared by every file of a run; each file gets its own browser contexts.
pub type SharedChrome = std::sync::Arc<tokio::sync::OnceCell<Chrome>>;

pub struct Runner {
    pub cfg: Config,
    pub vars: Map<String, Value>,
    pub it: Value,
    legacy: Option<Value>,
    last_http: Value,
    pub file: String,
    pub dir: PathBuf,
    chrome: Option<Chrome>,
    shared: Option<SharedChrome>,
    pub tabs: BTreeMap<String, Tab>,
    pub ptys: BTreeMap<String, Pty>,
    pub cur_b: String,
    pub cur_t: Option<String>,
    pub last: Surf,
    routes: Vec<Route>,
    front: String,
    pub(crate) api_reqs: Vec<Req>,
    /// URL before the last action, so `wait: for navigation` sees navigations that action caused.
    pub(crate) nav_from: String,
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
    /// Accumulated coverage: script url → used-byte bitmap; css rules → used.
    pub(crate) coverage: Option<Coverage>,
    pub(crate) device: Option<crate::mobile::Device>,
    firefox: Option<std::sync::Arc<crate::bidi::Bidi>>,
}

const BROWSER_VERBS: &[&str] = &[
    "visit", "click", "dblclick", "hover", "check", "uncheck", "tap", "focus", "fill", "upload",
    "drag", "route", "unroute", "trace", "profile", "heap", "coverage", "throttle", "network",
    "emulate", "back", "reload",
];
/// Steps that observe without acting; they don't move the "since the last action" window.
const PASSIVE: &[&str] =
    &["expect", "wait", "extract", "snapshot", "shot", "mark", "claim", "meta"];
const TERM_VERBS: &[&str] = &["exec", "spawn", "signal", "resize"];
const MOBILE_VERBS: &[&str] = &["launch", "swipe", "home", "deeplink"];
/// Verbs that act on the device once a `launch:` made mobile the current surface.
const MOBILE_SHARED: &[&str] =
    &["click", "tap", "dblclick", "check", "uncheck", "focus", "fill", "type", "press", "back"];

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
            shared: None,
            tabs: BTreeMap::new(),
            ptys: BTreeMap::new(),
            cur_b: "default".into(),
            cur_t: None,
            last: Surf::Http,
            routes: vec![],
            front: "default".into(),
            api_reqs: vec![],
            nav_from: String::new(),
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
            coverage: None,
            device: None,
            firefox: None,
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
                "policy" => self.cfg.policy = serde_json::from_value(v.clone()).ok(),
                "headed" => self.cfg.headed = v.as_bool().unwrap_or(false),
                "browser" => self.cfg.firefox = scalar_text(v).eq_ignore_ascii_case("firefox"),
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
        if MOBILE_VERBS.contains(&verb)
            || self.last == Surf::Mobile && MOBILE_SHARED.contains(&verb)
        {
            return Surf::Mobile;
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
    /// Snapshot lines that fit the budget (~15 tokens a line).
    pub(crate) fn snapshot_lines(&self, share: f64) -> usize {
        ((self.cfg.budget as f64 * share / 15.0) as usize).clamp(8, 1000)
    }
    pub(crate) fn policy(&self) -> crate::policy::Policy {
        self.cfg.policy.clone().unwrap_or_default()
    }
    /// Use a Chrome shared with other runners instead of launching one.
    pub fn share(&mut self, c: SharedChrome) {
        self.shared = Some(c)
    }
    async fn chrome(&mut self) -> Result<&Chrome> {
        if let (Some(cell), None) = (&self.shared, &self.cfg.attach) {
            let headed = self.cfg.headed;
            return cell.get_or_try_init(|| Chrome::launch(headed)).await;
        }
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
            let t = if self.cfg.firefox {
                if self.firefox.is_none() {
                    self.firefox = Some(crate::bidi::Bidi::launch(self.cfg.headed).await?)
                }
                self.firefox.as_ref().unwrap().tab().await?
            } else {
                self.chrome().await?.tab(isolated).await?
            };
            if self.cfg.deterministic {
                deterministic(&t).await.ok();
            }
            *t.routes.lock().unwrap() = self.routes.clone();
            t.sync_routes().await?;
            if let Some(p) = &t.page {
                self.known_pages.push(p.target_id().inner().clone());
                if !self.tabs.is_empty() {
                    p.bring_to_front().await.ok();
                }
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
            self.prev = self.cur.clone();
            self.nav_from = match self.tabs.get(&self.cur_b) {
                Some(t) => t.url().await,
                None => String::new(),
            };
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
        let outcome = Box::pin(self.exec(item, &mut r)).await;
        if item.opts.dialog.is_some() {
            if let Some(t) = self.tabs.get(&self.cur_b) {
                *t.dialog.lock().unwrap() = (false, None)
            }
        }
        let keep_it = matches!(
            item.verb.as_str(),
            "expect" | "claim" | "mark" | "route" | "unroute" | "snapshot"
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
            if r.step_error.is_none() {
                self.guard(item, &mut r)
            }
            if self.cfg.frames && self.tabs.contains_key(&self.cur_b) {
                r.frame = self.tabs[&self.cur_b].screenshot(0.5).await.ok()
            }
        }
        if self.last == Surf::Mobile && self.cfg.frames {
            r.frame = self.device.as_ref().and_then(|d| d.screenshot().ok())
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
        match self.retry(&c, self.cfg.expect_ms).await {
            Ok(((ok, actual), _)) => Ok(("OK".into(), ok, actual)),
            Err(err) => Err(AssertionError {
                advice: Some(err.to_string().trim_start_matches("E_ASSERT ").into()),
                src: miette::NamedSource::new(&self.file, e.to_string()),
                bad_bit: (0, e.len()).into(),
            }),
        }
    }

    pub async fn close(&mut self) {
        let tabs = std::mem::take(&mut self.tabs);
        self.ptys.clear();
        if let Some(cell) = self.shared.clone() {
            if let Some(c) = cell.get() {
                for (_, t) in tabs {
                    c.release(t).await
                }
            }
        } else {
            drop(tabs);
        }
        if let Some(c) = self.chrome.take() {
            c.close().await
        }
    }
}
#[derive(Default)]
pub(crate) struct Coverage {
    pub js: HashMap<String, Vec<bool>>,
    pub css: HashMap<(String, i64, i64), bool>,
    /// stylesheet id → length, from CSS.styleSheetAdded (rule usage only lists matched rules)
    pub sheets: std::sync::Arc<std::sync::Mutex<HashMap<String, f64>>>,
    pub listener: Option<tokio::task::JoinHandle<()>>,
}
impl Drop for Coverage {
    fn drop(&mut self) {
        if let Some(h) = self.listener.take() {
            h.abort()
        }
    }
}

/// While alive, scripts on the tab run inside a cross-origin frame's isolated world.
pub(crate) struct FrameGuard<'a>(&'a Tab);
impl Drop for FrameGuard<'_> {
    fn drop(&mut self) {
        *self.0.eval_ctx.lock().unwrap() = None
    }
}
/// Routes `… in frame "x"` into a cross-origin frame: returns the locator without the frame
/// scope, the frame's viewport offset and a guard. Same-origin frames are left to the page script.
pub(crate) async fn enter_frame<'a>(
    t: &'a Tab,
    loc: &Locator,
) -> Result<(Locator, (f64, f64), FrameGuard<'a>)> {
    let spec =
        loc.scope.iter().find_map(|s| if let Scope::Frame(f) = s { Some(f.clone()) } else { None });
    if let Some(spec) = spec {
        if let Some((ctx, x, y)) = t.cross_frame(&spec).await? {
            *t.eval_ctx.lock().unwrap() = Some(ctx);
            let mut l = loc.clone();
            l.scope.retain(|s| !matches!(s, Scope::Frame(_)));
            return Ok((l, (x, y), FrameGuard(t)));
        }
    }
    Ok((loc.clone(), (0.0, 0.0), FrameGuard(t)))
}

async fn deterministic(t: &Tab) -> Result<()> {
    use chromiumoxide::cdp::browser_protocol::emulation;
    t.cdp()?.execute(emulation::SetTimezoneOverrideParams::new("UTC")).await?;
    t.cdp()?.execute(emulation::SetLocaleOverrideParams::builder().locale("en-US").build()).await?;
    t.emulate("reduced-motion").await?;
    t.cdp()?.execute(chromiumoxide::cdp::browser_protocol::page::AddScriptToEvaluateOnNewDocumentParams::new(
        "(()=>{let s=42;Math.random=()=>((s=Math.imul(48271,s)%2147483647)&2147483647)/2147483647;const D=Date;const T0=new D('2026-01-01T09:00:00Z').getTime();const p0=performance.now();globalThis.Date=class extends D{constructor(...a){super(...(a.length?a:[T0+performance.now()-p0]))}static now(){return T0+performance.now()-p0}};addEventListener('DOMContentLoaded',()=>{const st=document.createElement('style');st.textContent='*,*::before,*::after{transition:none!important;animation:none!important;caret-color:transparent!important}';document.head.appendChild(st)})})()",
    )).await?;
    Ok(())
}
