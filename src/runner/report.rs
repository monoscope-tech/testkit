//! Step reports (semantic diffs), the run-wide error guard and text helpers.
use super::*;

impl Runner {
    /// Where a literal used by the current step came from: an earlier response (before this step
    /// started). Returns an `extract:` expression and a variable name for the recorder.
    pub(crate) fn provenance(&self, value: &str) -> Option<(String, String)> {
        let tab_reqs: Vec<Req> = self
            .tabs
            .get(&self.cur_b)
            .map(|t| {
                let upto = self.cur.tabs.get(&self.cur_b).map(|m| m.0).unwrap_or(usize::MAX);
                t.log.lock().unwrap().reqs.iter().take(upto).cloned().collect()
            })
            .unwrap_or_default();
        let reqs = self.api_reqs.iter().take(self.cur.api).cloned().chain(tab_reqs);
        let mut best: Option<((usize, bool), String, String)> = None;
        for q in reqs {
            let Some(body) = &q.body else { continue };
            let Ok(j) = serde_json::from_str::<Value>(body) else { continue };
            if let Some(path) = find_value(&j, value, 0) {
                let full = path_of(&q.url);
                let segs: Vec<&str> =
                    full.split('?')
                        .next()
                        .unwrap_or("")
                        .split('/')
                        .map(|s| {
                            if s.chars().any(|c| c.is_ascii_digit()) && s.len() > 1 {
                                "*"
                            } else {
                                s
                            }
                        })
                        .collect();
                let pat = segs.join("/");
                let access: String = path
                    .iter()
                    .map(|p| match p {
                        Ok(k) => format!("'s {k}"),
                        Err(i) => format!("[{i}]"),
                    })
                    .collect();
                let resource = segs
                    .iter()
                    .rev()
                    .find(|s| !s.is_empty() && **s != "*" && **s != "api")
                    .map(|s| s.trim_end_matches('s'))
                    .unwrap_or("value");
                let key = path
                    .iter()
                    .rev()
                    .find_map(|p| p.as_ref().ok().cloned())
                    .unwrap_or_else(|| "value".into());
                let name = if key == "id" { format!("{resource}_id") } else { key };
                let expr = format!("last request \"{} {pat}\"'s json{access}", q.method);
                // the request that produced the value (a write) beats later reads that echo it
                let score = (path.len(), !["POST", "PUT", "PATCH"].contains(&q.method.as_str()));
                if best.as_ref().is_none_or(|b| score < b.0) {
                    best = Some((score, expr, name))
                }
            }
        }
        best.map(|(_, e, n)| (e, n))
    }
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
                .tk(
                    "snapshot",
                    &[
                        Value::Null,
                        json!({"all": false, "refs": true, "max": self.snapshot_lines(0.5)}),
                    ],
                )
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

/// Path to the first value equal to `v` (keys as Ok, indices as Err), shallowest first.
fn find_value(j: &Value, v: &str, depth: usize) -> Option<Vec<Result<String, usize>>> {
    if depth > 6 {
        return None;
    }
    let here = match j {
        Value::String(s) => s == v,
        Value::Number(n) => n.to_string() == v,
        _ => false,
    };
    if here {
        return Some(vec![]);
    }
    let kids: Vec<(Result<String, usize>, &Value)> = match j {
        Value::Object(o) => o.iter().map(|(k, x)| (Ok(k.clone()), x)).collect(),
        Value::Array(a) => a.iter().enumerate().take(50).map(|(i, x)| (Err(i), x)).collect(),
        _ => return None,
    };
    for (k, x) in &kids {
        if matches!(x, Value::String(s) if s == v)
            || matches!(x, Value::Number(n) if n.to_string() == v)
        {
            return Some(vec![k.clone()]);
        }
    }
    kids.into_iter().find_map(|(k, x)| {
        find_value(x, v, depth + 1).map(|mut p| {
            p.insert(0, k);
            p
        })
    })
}
