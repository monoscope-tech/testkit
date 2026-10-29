//! Verbs: browser actions, terminal commands, HTTP, composition, devtools and evidence.
use super::*;

impl Runner {
    // ---------- verbs ----------
    pub(crate) async fn exec(&mut self, item: &Item, r: &mut StepResult) -> Result<Value> {
        let v = item.verb.as_str();
        let timeout = item.opts.timeout.as_ref().and_then(dur);
        if HTTP.contains(&v) {
            self.last = Surf::Http;
            return self.http(item, r).await;
        }
        match (&item.args, v) {
            (Args::Tmpl(_), "visit") => {
                let url = self.url(&item.text)?;
                self.policy().navigate(&url)?;
                self.last = Surf::Browser;
                let cov = self.coverage.is_some();
                let t = self.tab(None).await?;
                t.goto(&url).await?;
                if cov {
                    // CSS rule tracking is per document
                    use chromiumoxide::cdp::browser_protocol::{css, dom};
                    t.page.execute(dom::EnableParams::default()).await.ok();
                    t.page.execute(css::EnableParams::default()).await.ok();
                    t.page.execute(css::StartRuleUsageTrackingParams::default()).await.ok();
                }
                Ok(t.page_state().await)
            }
            (_, "act") => self.act_steps(item).await,
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
                let mut respond = item.opts.respond.clone().map(|r| match r {
                    Value::String(s) => Value::String(self.dir.join(s).to_string_lossy().into()),
                    r => r,
                });
                // record: replay the fixture when present, otherwise capture the real response into it
                let mut record = None;
                if let Some(f) = &item.opts.record {
                    let path = self.dir.join(self.render(f)?).to_string_lossy().to_string();
                    if std::path::Path::new(&path).exists() && !self.cfg.update_golden {
                        respond = Some(Value::String(path))
                    } else {
                        record = Some(path)
                    }
                }
                self.routes.push(Route {
                    record,
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
                self.policy().command(&cmd)?;
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
            (Args::Toggle(on, into), "trace" | "profile" | "heap" | "coverage") => {
                self.devtools(v, *on, into.clone()).await
            }
            (_, "mark") => Ok(json!({"mark": item.text})),
            (a, v) => bail!("`{v}` does not take `{}` ({a:?})", item.text),
        }
    }

    /// Commands run in the test file's directory unless `cwd:` says otherwise.
    pub(crate) fn cwd(&self, item: &Item) -> Result<String> {
        let d = match &item.opts.cwd {
            Some(c) => self.dir.join(self.render(c)?),
            None => self.dir.clone(),
        };
        let d = if d.as_os_str().is_empty() { PathBuf::from(".") } else { d };
        Ok(d.to_string_lossy().to_string())
    }
    pub(crate) fn env(&self, item: &Item) -> Result<Vec<(String, String)>> {
        item.opts
            .env
            .iter()
            .flatten()
            .map(|(k, v)| Ok((k.clone(), self.render(&scalar_text(v))?)))
            .collect()
    }

    pub(crate) async fn spawn(&mut self, item: &Item) -> Result<Value> {
        let cmd = self.render_shell(&item.text)?;
        self.policy().command(&cmd)?;
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
    pub(crate) async fn settle_term(&mut self, timeout: u64, at: usize) -> Result<Value> {
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

    pub(crate) async fn sync_routes(&mut self) -> Result<()> {
        for t in self.tabs.values() {
            *t.routes.lock().unwrap() = self.routes.clone();
            t.sync_routes().await?;
        }
        Ok(())
    }

    /// Resolves, waits for actionability (spec §4) and performs a browser or terminal action.
    pub(crate) async fn act(
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
        self.tab(session.as_deref()).await?;
        let action_ms = self.cfg.action_ms;
        let t = &self.tabs[&session.clone().unwrap_or(self.cur_b.clone())];
        let (floc, off, frame) = enter_frame(t, loc).await?;
        let mut why = String::from("no element matches");
        let el = loop {
            let els = t.resolve(&floc).await?;
            match els.len() {
                1 => {
                    let a = t.tk("actionable", &[els[0]["ref"].clone(), json!(checks)]).await?;
                    if a["ok"] == true {
                        break (
                            els[0].clone(),
                            a["x"].as_f64().unwrap_or(0.0) + off.0,
                            a["y"].as_f64().unwrap_or(0.0) + off.1,
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
                        timeout.unwrap_or(action_ms),
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
                    return select(t, &rf, &s).await;
                }
                t.tk("focusSelect", std::slice::from_ref(&rf)).await?;
                t.key("Delete").await?;
                if !s.is_empty() {
                    t.insert_text(&s).await?;
                    // widgets that ignore insertText get real keystrokes instead
                    let r = rf.as_i64().unwrap_or(0);
                    let now = t.eval_raw(&format!("(e => e ? (e.value ?? e.textContent ?? '') : '')(window.__tk.refs.get({r}))")).await?;
                    if scalar_text(&now).trim().is_empty() {
                        t.tk("focusSelect", std::slice::from_ref(&rf)).await?;
                        t.type_text(&s).await?;
                    }
                }
            }
            "select" => return select(t, &rf, &to_str(val.as_ref().unwrap_or(&Value::Null))).await,
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
        tokio::time::sleep(Duration::from_millis(40)).await;
        t.wait_load().await;
        // `it` is the element after the action (checked state, new value), when it still exists
        let r = rf.as_i64().unwrap_or(0);
        let after = t.eval_raw(&format!("(e => e && e.isConnected ? window.__tk.describe(e) : null)(window.__tk && window.__tk.refs.get({r}))")).await.unwrap_or(Value::Null);
        drop(frame);
        if measure {
            return self.measure(t_act, rq0, item).await;
        }
        Ok(if after.is_null() { el } else { after })
    }
    pub(crate) async fn drag(
        &mut self,
        a: &Locator,
        b: &Locator,
        timeout: Option<u64>,
    ) -> Result<Value> {
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

    pub(crate) async fn measure(
        &mut self,
        t_act: Instant,
        rq0: usize,
        item: &Item,
    ) -> Result<Value> {
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
    pub(crate) async fn heap(&mut self) -> Result<f64> {
        let t = self.tab(None).await?;
        t.page.execute(chromiumoxide::cdp::js_protocol::heap_profiler::CollectGarbageParams::default()).await.ok();
        let m = t.page.metrics().await?;
        Ok(m.iter().find(|m| m.name == "JSHeapUsedSize").map(|m| m.value).unwrap_or(0.0))
    }
    pub(crate) async fn devtools(
        &mut self,
        what: &str,
        on: bool,
        into: Option<String>,
    ) -> Result<Value> {
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
            ("coverage", true) => {
                use chromiumoxide::cdp::browser_protocol::{css, dom};
                t.page.execute(profiler::EnableParams::default()).await?;
                t.page
                    .execute(
                        profiler::StartPreciseCoverageParams::builder()
                            .call_count(true)
                            .detailed(true)
                            .build(),
                    )
                    .await?;
                let mut cov = Coverage::default();
                let mut added = t.page.event_listener::<css::EventStyleSheetAdded>().await?;
                let sheets = cov.sheets.clone();
                cov.listener = Some(tokio::spawn(async move {
                    use futures_util::StreamExt;
                    while let Some(e) = added.next().await {
                        sheets
                            .lock()
                            .unwrap()
                            .insert(e.header.style_sheet_id.inner().clone(), e.header.length);
                    }
                }));
                t.page.execute(dom::EnableParams::default()).await?;
                t.page.execute(css::EnableParams::default()).await?;
                t.page.execute(css::StartRuleUsageTrackingParams::default()).await?;
                self.coverage = Some(cov);
                Ok(Value::Null)
            }
            ("coverage", false) => {
                let v = self.coverage_read().await?;
                self.coverage = None;
                Ok(v)
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

    pub(crate) async fn shot(
        &mut self,
        path: Option<&Vec<Seg>>,
        loc: Option<&Locator>,
    ) -> Result<Value> {
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
        let lines = self.snapshot_lines(0.9);
        let t = self.tab(None).await?;
        let v = t
            .tk(
                "snapshot",
                &[
                    loc.map(loc_json).unwrap_or(Value::Null),
                    json!({"all": all, "refs": true, "max": lines}),
                ],
            )
            .await?;
        if v["missing"] == true {
            let l = loc.map(|l| l.to_string()).unwrap_or_default();
            let roles = t.eval_raw("[...new Set([...document.querySelectorAll('*')].map(e => window.__tk.role(e)).filter(r => ['main','navigation','banner','contentinfo','region','form','dialog','list','table','complementary'].includes(r)))].join(', ')").await.map(|v| scalar_text(&v)).unwrap_or_default();
            bail!(
                "E_NOT_FOUND `snapshot {l}`: nothing on the page matches it{}",
                if roles.is_empty() { String::new() } else { format!("; landmarks here: {roles}") }
            );
        }
        let page = t.page_state().await;
        Ok(format!(
            "# {} — {}\n{}",
            scalar_text(&page["title"]),
            scalar_text(&page["url"]),
            scalar_text(&v["yaml"])
        ))
    }

    /// `act: <instruction>`: resolve to concrete steps (cached per instruction and page path), run them,
    /// and re-resolve with the failure when they don't work.
    pub(crate) async fn act_steps(&mut self, item: &Item) -> Result<Value> {
        let goal = self.render(&item.text)?;
        let url = match self.tabs.get(&self.cur_b) {
            Some(t) => t.url().await,
            None => String::new(),
        };
        let path = url.split_once("://").map_or("", |(_, r)| r.find('/').map_or("/", |i| &r[i..]));
        let path = path.split(['?', '#']).next().unwrap_or("");
        let digest = <sha2::Sha256 as sha2::Digest>::digest(format!("{goal}\n{path}").as_bytes());
        let cache =
            PathBuf::from(".testkit/act").join(format!("{}.yaml", &format!("{digest:x}")[..16]));
        let mut cached = std::fs::read_to_string(&cache).ok();
        let mut error: Option<String> = None;
        for _ in 0..3 {
            let (reply, by) = match cached.take() {
                Some(y) => (y, "cache"),
                None => {
                    let ctx = self.act_context().await;
                    (crate::act::resolve(&goal, &ctx, error.as_deref()).await?, "model")
                }
            };
            let items = match crate::act::steps(&reply) {
                Ok(i) => i,
                Err(e) => {
                    error = Some(format!("{e}\nreply was:\n{reply}"));
                    continue;
                }
            };
            let start = self.results.len();
            self.depth += 1;
            let sub = Box::pin(self.run_items(&items)).await;
            self.depth -= 1;
            if let Some(f) = sub.iter().find(|s| !s.ok()) {
                error = Some(format!("step `{}` failed:\n{}", f.line_text(), f.step_log.trim()));
                self.results.truncate(start);
                continue;
            }
            for rr in &mut self.results[start..] {
                rr.step_name = Some(format!("act › {}", rr.line_text()))
            }
            std::fs::create_dir_all(".testkit/act")?;
            std::fs::write(&cache, &reply)?;
            let lines: Vec<String> = sub.iter().map(|s| s.line_text()).collect();
            return Ok(json!({"steps": lines, "yaml": reply, "by": by}));
        }
        bail!("E_ACT could not carry out `{goal}`; last attempt: {}", error.unwrap_or_default())
    }
    async fn act_context(&mut self) -> String {
        let vars: Vec<String> = self.vars.keys().filter(|k| !k.starts_with('_')).cloned().collect();
        let base = self.cfg.base_url.clone().unwrap_or_default();
        let state = if !self.tabs.is_empty() || !self.ptys.is_empty() {
            self.snapshot(None, false).await.unwrap_or_else(|e| e.to_string())
        } else {
            "nothing is open yet".into()
        };
        format!("base_url: {base}\nvariables: {vars:?}\n{state}")
    }

    pub(crate) async fn call(&mut self, item: &Item, r: &mut StepResult) -> Result<Value> {
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
    pub(crate) async fn http(&mut self, item: &Item, r: &mut StepResult) -> Result<Value> {
        let rc = &item.opts.request;
        if rc.disabled.unwrap_or(false) {
            r.step_log = "Step disabled, skipping".into();
            r.assert_results = item.opts.asserts.iter().flatten().map(|_| Ok(true)).collect();
            return Ok(Value::Null);
        }
        let method = reqwest::Method::from_bytes(item.verb.as_bytes())?;
        let url = self.url(&item.text)?;
        self.policy().request(method.as_str(), &url, &self.base())?;
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
            .find(|rt| !rt.at_response() && rt.matches(method.as_str(), &url, &base))
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
        if !mocked {
            if let Some(path) = self
                .routes
                .iter()
                .rev()
                .find(|rt| rt.record.is_some() && rt.matches(method.as_str(), &url, &base_))
                .and_then(|rt| rt.record.clone())
            {
                if let Some(d) = std::path::Path::new(&path).parent() {
                    std::fs::create_dir_all(d).ok();
                }
                std::fs::write(&path, crate::browser::pretty(raw.as_bytes()))?;
                r.step_log.push_str(&format!("recorded fixture → {path}\n"));
            }
        }
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
            body: Some(raw.clone()),
            ..Default::default()
        });
        self.last_http = it.clone();
        r.report = json!({"network": [format!("{} {} {status} {ms}ms{}", method, path_of(&url), if mocked { " (mocked)" } else { "" })]});
        Ok(it)
    }
    pub(crate) fn render_json(&self, v: &Value) -> Result<Value> {
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
}

async fn select(t: &Tab, rf: &Value, label: &str) -> Result<Value> {
    let r = t.tk("selectOption", &[rf.clone(), json!(label)]).await?;
    if r["ok"] != true {
        bail!("E_NOT_FOUND option `{label}`; options are: {}", r["options"])
    }
    Ok(r)
}

impl Runner {
    /// Unused JS/CSS bytes (percent) since `coverage: start`, accumulated across reads.
    pub(crate) async fn coverage_read(&mut self) -> Result<Value> {
        use chromiumoxide::cdp::browser_protocol::css;
        use chromiumoxide::cdp::js_protocol::profiler;
        if self.coverage.is_none() {
            return Ok(json!({"unused_js": null, "unused_css": null}));
        }
        let t = self.tab(None).await?;
        let js = t
            .page
            .execute(profiler::TakePreciseCoverageParams::default())
            .await?
            .result
            .result
            .clone();
        let rules = t
            .page
            .execute(css::StopRuleUsageTrackingParams::default())
            .await
            .map(|r| r.result.rule_usage.clone())
            .unwrap_or_default();
        t.page.execute(css::StartRuleUsageTrackingParams::default()).await.ok();
        let cov = self.coverage.as_mut().unwrap();
        for s in js.iter().filter(|s| !s.url.is_empty() && !s.url.starts_with("chrome")) {
            let len = s
                .functions
                .iter()
                .flat_map(|f| f.ranges.iter())
                .map(|r| r.end_offset)
                .max()
                .unwrap_or(0)
                .max(0) as usize;
            let used = cov.js.entry(s.url.clone()).or_insert_with(|| vec![false; len]);
            if used.len() < len {
                used.resize(len, false)
            }
            let mut now = vec![false; len];
            for f in &s.functions {
                for r in &f.ranges {
                    let (a, b) =
                        (r.start_offset.max(0) as usize, (r.end_offset.max(0) as usize).min(len));
                    now[a..b].iter_mut().for_each(|x| *x = r.count > 0);
                }
            }
            used.iter_mut().zip(now).for_each(|(u, n)| *u |= n);
        }
        for r in rules {
            let e = cov
                .css
                .entry((
                    r.style_sheet_id.inner().clone(),
                    r.start_offset as i64,
                    r.end_offset as i64,
                ))
                .or_insert(false);
            *e |= r.used;
        }
        let (jt, ju) = cov.js.values().fold((0usize, 0usize), |(t, u), v| {
            (t + v.len(), u + v.iter().filter(|x| **x).count())
        });
        let sheets = cov.sheets.lock().unwrap().clone();
        let ct = sheets.values().sum::<f64>() as i64;
        let cu = cov
            .css
            .iter()
            .filter(|((id, ..), used)| **used && sheets.contains_key(id))
            .map(|((_, a, b), _)| b - a)
            .sum::<i64>()
            .min(ct);
        let pct = |total: f64, used: f64| {
            if total > 0.0 {
                ((total - used) / total * 1000.0).round() / 10.0
            } else {
                0.0
            }
        };
        Ok(
            json!({"unused_js": pct(jt as f64, ju as f64), "unused_css": pct(ct as f64, cu as f64), "js_bytes": jt, "css_bytes": ct}),
        )
    }
}
