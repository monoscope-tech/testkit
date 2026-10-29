//! Expressions against live surfaces: subject/locator resolution, expect/wait retries, perf gate and structural matching.
use super::*;

impl Runner {
    // ---------- expressions ----------
    pub async fn value(&mut self, e: &Expr) -> Result<Value> {
        let mut qs = vec![];
        eval::queries(e, &self.vars, &mut qs);
        let resolved = self.resolve_all(&qs).await?;
        let mut c = self.ctx();
        c.resolved = resolved;
        eval::eval(e, &c).map_err(|e| anyhow!(e))
    }
    pub(crate) async fn resolve_all(&mut self, qs: &[Expr]) -> Result<HashMap<String, Value>> {
        let mut out = HashMap::new();
        for q in qs {
            if let Some(v) = Box::pin(self.resolve(q, None)).await? {
                out.insert(key(q), v);
            }
        }
        Ok(out)
    }
    /// One evaluation of a condition: (passed, actual value of the left side).
    pub(crate) async fn check_once(&mut self, c: &mut Cond) -> Result<(bool, Option<String>)> {
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

    pub(crate) async fn expect(
        &mut self,
        item: &Item,
        c: &Cond,
        within: Option<u64>,
    ) -> Result<Value> {
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
    pub(crate) async fn sample_gate(&mut self, c: &Cond) -> Result<Option<(bool, String)>> {
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

    pub(crate) async fn structural(
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
    pub(crate) async fn structural_once(&mut self, subject: &Expr, m: &Value) -> Result<Value> {
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

    pub(crate) async fn wait(&mut self, evs: &[Event], timeout: Option<u64>) -> Result<Value> {
        if let [Event::Dur(d)] = evs {
            tokio::time::sleep(Duration::from_millis(*d as u64)).await;
            return Ok(json!(d));
        }
        let limit = evs
            .iter()
            .find_map(|e| if let Event::Dur(d) = e { Some(*d as u64) } else { None })
            .or(timeout)
            .unwrap_or(self.cfg.nav_ms);
        let start_url = self.nav_from.clone();
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
    pub(crate) async fn event_hit(
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
                let me = self.tab(None).await?.cdp()?.target_id().clone();
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
    pub(crate) fn base(&self) -> String {
        self.vars.get("base_url").map(scalar_text).or(self.cfg.base_url.clone()).unwrap_or_default()
    }

    /// Resolves a subject/locator/session query (spec §3.3 windows: since the previous step).
    pub(crate) async fn resolve(
        &mut self,
        q: &Expr,
        session: Option<String>,
    ) -> Result<Option<Value>> {
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
                if sess.is_none() && self.last == Surf::Mobile {
                    return Ok(Some(Value::Array(self.device_find(l)?)));
                }
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
                    let (fl, _, _frame) = enter_frame(t, l).await?;
                    Value::Array(t.resolve(&fl).await?)
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
                        let mets = match &t.page {
                            Some(pg) => pg.metrics().await.map_err(|e| anyhow!(e)),
                            None => Err(anyhow!("no metrics")),
                        };
                        if self.coverage.is_some() {
                            if let Ok(c) = self.coverage_read().await {
                                for k in ["unused_js", "unused_css"] {
                                    p[k] = c[k].clone()
                                }
                            }
                        }
                        if let Ok(m) = mets {
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
                        t.cookies()
                            .await?
                            .into_iter()
                            .find(|c| &c.0 == n)
                            .map(|c| json!(c.1))
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
    pub(crate) async fn requests(
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
                    if let Some((b, _, _)) = self.tabs.get(&name).and_then(|t| t.bidi.clone()) {
                        body = b.body(&r.id).await
                    } else if let Some(t) = self.tabs.get(&name) {
                        if let Some(Ok(b)) = match &t.page { Some(p) => Some(p.execute(chromiumoxide::cdp::browser_protocol::network::GetResponseBodyParams::new(r.id.clone())).await), None => None } {
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
}
/// The failing part of a condition and its actual value, for E_ASSERT messages.
pub(crate) fn why(c: &Cond, ctx: &Ctx) -> Option<String> {
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
pub(crate) fn cond_text(c: &Cond) -> String {
    match c {
        Cond::Cmp { lhs, op, .. } => format!("{} {:?}", expr_text(lhs), op),
        c => format!("{c:?}").chars().take(80).collect(),
    }
}
pub(crate) fn expr_text(e: &Expr) -> String {
    match e {
        Expr::Var(v) => v.clone(),
        Expr::Loc(l) => l.to_string(),
        Expr::Prop(b, Prop::Name(n)) => format!("the {n} of {}", expr_text(b)),
        e => format!("{e:?}").chars().take(60).collect(),
    }
}

pub(crate) async fn stable_vitals(t: &Tab) -> Value {
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

pub fn load_baselines() -> Map<String, Value> {
    std::fs::read_to_string(".testkit/baselines.json")
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn name_match(n: &Name, s: &str) -> bool {
    // typographic dashes and non-breaking spaces compare as their ASCII forms
    let fold = |s: &str| {
        s.to_lowercase()
            .replace(['\u{2010}', '\u{2011}', '\u{2012}', '\u{2013}'], "-")
            .replace('\u{a0}', " ")
    };
    match n {
        Name::Sub(x) => fold(s).contains(&fold(x)),
        Name::Exact(x) => s.trim() == x.trim(),
        Name::Re(r, f) => regex::RegexBuilder::new(r)
            .case_insensitive(f.contains('i'))
            .build()
            .is_ok_and(|re| re.is_match(s)),
        Name::Tmpl(_) => false,
    }
}
pub(crate) fn regex_groups(n: &Name, s: &str) -> Value {
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
pub(crate) fn text_hit(n: &Name, out: &str) -> Option<Value> {
    out.lines()
        .find(|l| name_match(n, l))
        .map(|l| json!({"text": l.trim(), "match": regex_groups(n, l)}))
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
    pub(crate) fn flat<'a>(ns: &'a [Value], out: &mut Vec<&'a Value>) {
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
pub(crate) fn spec_text(w: &Value) -> String {
    match w {
        Value::String(s) => s.clone(),
        Value::Object(o) => o.keys().next().cloned().unwrap_or_default(),
        v => v.to_string(),
    }
}
pub(crate) fn node_match(w: &Value, a: &Value) -> Result<(), String> {
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
