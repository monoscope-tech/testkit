//! Step reports (semantic diffs), the run-wide error guard and text helpers.
use super::*;

impl Runner {
    /// Every request of the run (browser sessions and API steps) as a HAR 1.2 log.
    pub fn har(&self) -> Value {
        let now = chrono::Utc::now().to_rfc3339();
        let hdrs = |v: &Value| -> Value {
            json!(v.as_object().map(|o| o.iter().map(|(k, v)| json!({"name": k, "value": match v { Value::Array(a) => a.iter().map(scalar_text).collect::<Vec<_>>().join(", "), v => scalar_text(v) }})).collect::<Vec<_>>()).unwrap_or_default())
        };
        let entry = |q: &Req, page: &str| {
            json!({
                "pageref": page, "startedDateTime": now, "time": q.ms,
                "request": {"method": q.method, "url": q.url, "httpVersion": "HTTP/1.1", "headers": hdrs(&q.req["headers"]), "queryString": [], "cookies": [], "headersSize": -1, "bodySize": -1},
                "response": {"status": q.status.unwrap_or(0), "statusText": q.failed.clone().unwrap_or_default(), "httpVersion": "HTTP/1.1", "headers": hdrs(&q.headers), "cookies": [],
                    "content": {"size": q.size, "mimeType": q.headers.get("content-type").map(scalar_text).unwrap_or_default(), "text": q.body.clone().unwrap_or_default()}, "redirectURL": "", "headersSize": -1, "bodySize": q.size},
                "cache": {}, "timings": {"send": 0, "wait": q.ms, "receive": 0}, "_mocked": q.mocked,
            })
        };
        let mut entries: Vec<Value> = self.api_reqs.iter().map(|q| entry(q, "api")).collect();
        for (name, t) in &self.tabs {
            entries.extend(t.log.lock().unwrap().reqs.iter().map(|q| entry(q, name)))
        }
        let mut pages: Vec<Value> = self
            .tabs
            .keys()
            .map(|n| json!({"id": n, "title": n, "startedDateTime": now, "pageTimings": {}}))
            .collect();
        pages.push(
            json!({"id": "api", "title": "API steps", "startedDateTime": now, "pageTimings": {}}),
        );
        json!({"log": {"version": "1.2", "creator": {"name": "testkit", "version": env!("CARGO_PKG_VERSION")}, "pages": pages, "entries": entries}})
    }
    pub(crate) fn guard(&mut self, item: &Item, r: &mut StepResult) {
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
            let kinds = match (
                bad.iter().any(|b| b.starts_with("uncaught")),
                bad.iter().any(|b| b.starts_with("console")),
            ) {
                (true, true) => "console errors, page errors",
                (true, false) => "page errors",
                _ => "console errors",
            };
            r.step_error = Some(format!("E_GUARD this step introduced {} error{}:\n  {}\n  (allow it with `allow: [{kinds}]`, or `ignore:` in meta)", bad.len(), if bad.len() > 1 { "s" } else { "" }, bad.join("\n  ")));
        }
    }

    pub(crate) async fn summary(&mut self) -> Option<(Vec<String>, String)> {
        let t = self.tabs.get(&self.cur_b)?;
        let s = t.tk("summary", &[]).await.ok()?;
        Some((s.as_array()?.iter().map(scalar_text).collect(), t.url().await))
    }
    pub(crate) async fn report(
        &mut self,
        r: &mut StepResult,
        before: Option<(Vec<String>, String)>,
    ) {
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
pub(crate) fn indent(s: &str, n: usize) -> String {
    s.lines().map(|l| format!("{}{l}", " ".repeat(n))).collect::<Vec<_>>().join("\n")
}
pub(crate) fn assert_text(a: &Assert) -> String {
    serde_json::to_value(a)
        .ok()
        .and_then(|v| v.as_object().and_then(|o| o.values().next().map(scalar_text)))
        .unwrap_or_default()
}
pub(crate) fn line_diff(want: &str, got: &str) -> String {
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
