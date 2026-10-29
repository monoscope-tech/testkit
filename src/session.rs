//! CLI sessions (spec §6, §12): a background daemon per session name hosting a `Runner`, a socket
//! client, and the operations shared by the daemon, the REPL and the MCP server.
use crate::expr::eval::{key, queries};
use crate::expr::parse;
use crate::item::{parse_item, parse_yaml, scalar_text, Item};
use crate::record;
use crate::runner::{Config, Runner, StepResult};
use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

pub fn sock_path(name: &str) -> PathBuf {
    PathBuf::from(".testkit/sessions").join(format!("{name}.sock"))
}

/// Builds an item from CLI words: `click button "Save"` or `fill field "Email"` + `--value x`.
pub fn cli_item(verb: &str, words: &[String], value: Option<&str>) -> Result<Item> {
    let mut text = words.join(" ");
    if let Some(v) = value {
        let q = serde_json::to_string(v)?;
        text = match verb {
            "type" | "enter" => q,
            _ => format!("{text} with {q}"),
        };
    }
    parse_item(json!({ verb: text }), 0)
}

/// One operation against a runner. Used by the daemon, the in-process REPL and MCP.
pub async fn op(r: &mut Runner, req: &Value) -> Value {
    match handle(r, req).await {
        Ok(v) => v,
        Err(e) => json!({"ok": false, "error": e.to_string()}),
    }
}
async fn handle(r: &mut Runner, req: &Value) -> Result<Value> {
    let s = |k: &str| req[k].as_str().map(String::from);
    Ok(match s("op").as_deref().unwrap_or("step") {
        "step" => {
            let items: Vec<Item> = if let Some(y) = s("yaml") {
                parse_yaml(&y)?
            } else {
                let verb = s("verb").ok_or_else(|| anyhow!("missing verb"))?;
                let words: Vec<String> = req["args"]
                    .as_array()
                    .map(|a| a.iter().map(scalar_text).collect())
                    .unwrap_or_default();
                vec![cli_item(&verb, &words, s("value").as_deref())?]
            };
            let start = r.results.len();
            let mut notes = vec![];
            for item in &items {
                if item.verb == "meta" || item.verb == "claim" {
                    r.run_items(std::slice::from_ref(item)).await;
                    continue;
                }
                r.run_one(item).await;
                let res = r.results.last().cloned().unwrap_or_default();
                if let (Some(path), true) = (s("record"), res.ok()) {
                    notes.extend(record::record(r, item, &res, Path::new(&path)).await?);
                }
                if !res.ok() {
                    break;
                }
            }
            let results: Vec<StepResult> = r.results[start..].to_vec();
            json!({"ok": results.iter().all(|x| x.ok()), "results": results, "notes": notes})
        }
        "snapshot" => {
            let loc = s("locator")
                .filter(|l| !l.trim().is_empty())
                .map(|l| parse::locator(&l))
                .transpose()
                .map_err(|e| anyhow!("{e}"))?;
            json!({"ok": true, "text": r.snapshot(loc.as_ref(), req["all"].as_bool().unwrap_or(false)).await?})
        }
        "find" => {
            let needle = s("text").unwrap_or_default();
            let t = r.tab(None).await?;
            json!({"ok": true, "found": t.tk("find", &[json!(needle)]).await?})
        }
        "explain" => {
            let src = s("expr").unwrap_or_default();
            let (ast, resolved) = match parse::cond(&src) {
                Ok(c) => {
                    let mut qs = vec![];
                    crate::expr::eval::queries_cond(&c, &r.vars, &mut qs);
                    (format!("{c:#?}"), explain_queries(r, &qs).await)
                }
                Err(e) => match parse::locator(&src) {
                    Ok(l) => {
                        let e = crate::expr::Expr::Loc(l.clone());
                        (format!("{l:#?}"), explain_queries(r, &[e]).await)
                    }
                    Err(_) => bail!("{e}"),
                },
            };
            let ok = r
                .check(&parse::cond(&src).map_err(|e| anyhow!("{e}"))?)
                .await
                .map(|x| x.0)
                .unwrap_or(false);
            json!({"ok": true, "ast": ast, "resolves": resolved, "currently": ok})
        }
        "observe" => {
            let kind = s("kind").unwrap_or("console".into());
            let all = req["all"].as_bool().unwrap_or(false);
            let e = match kind.as_str() {
                "console" => format!("{}console messages", if all { "all " } else { "" }),
                "network" | "requests" => "every request \"**\"".to_string(),
                "output" => format!("{}output", if all { "all " } else { "" }),
                "page" => "page".into(),
                k => bail!("observe console, network, output or page (not `{k}`)"),
            };
            let v = r.value(&parse::value(&e).map_err(|e| anyhow!("{e}"))?).await?;
            json!({"ok": true, "value": v})
        }
        "suggest" => {
            let last =
                r.results.iter().rev().find(|x| x.verb != "expect").cloned().unwrap_or_default();
            let list = |k: &str| -> Vec<String> {
                last.report[k]
                    .as_array()
                    .map(|a| a.iter().map(scalar_text).collect())
                    .unwrap_or_default()
            };
            let (appeared, gone) = (list("appeared"), list("gone"));
            let base = |x: &str| {
                x.trim_end_matches(" [checked]").trim_end_matches(" [expanded]").to_string()
            };
            let mut out: Vec<String> = appeared
                .iter()
                .map(|x| {
                    // a state change shows up as the same element appearing with a new state
                    if let Some(b) = x.strip_suffix(" [checked]") {
                        format!("{b} is checked")
                    } else if let Some(b) = x.strip_suffix(" [expanded]") {
                        format!("{b} is expanded")
                    } else if gone.iter().any(|g| base(g) == *x)
                        && gone.iter().any(|g| g.ends_with(" [checked]"))
                    {
                        format!("{x} is not checked")
                    } else {
                        format!("{x} is visible")
                    }
                })
                .collect();
            for g in &gone {
                if !appeared.iter().any(|a| base(a) == base(g)) {
                    out.push(format!("no {}", base(g)))
                }
            }
            if let Some(u) = last.report["url"].as_array().and_then(|u| u.get(1)) {
                out.push(format!("the url of page contains {:?}", scalar_text(u)))
            }
            for n in last.report["network"].as_array().into_iter().flatten() {
                let parts: Vec<String> =
                    scalar_text(n).split_whitespace().map(String::from).collect();
                if parts.len() >= 3 && parts[0] != "GET" {
                    out.push(format!(
                        "the status of request \"{} {}\" is {}",
                        parts[0], parts[1], parts[2]
                    ))
                }
            }
            if last.report["console"].is_null() && last.verb != "GET" {
                out.push("no console errors".into())
            }
            if let Some(acc) = s("accept") {
                let picks: Vec<usize> =
                    acc.split(',').filter_map(|x| x.trim().parse().ok()).collect();
                let mut recorded = vec![];
                for p in picks {
                    if let Some(e) = out.get(p.wrapping_sub(1)) {
                        recorded.push(format!("expect: {e}"))
                    }
                }
                let yaml = recorded
                    .iter()
                    .map(|l| format!("- {}", record::yaml_item(l)))
                    .collect::<Vec<_>>()
                    .join("\n");
                return Box::pin(handle(
                    r,
                    &json!({"op": "step", "yaml": yaml, "record": s("record")}),
                ))
                .await;
            }
            json!({"ok": true, "suggestions": out})
        }
        "claim" => {
            let title = s("title").unwrap_or_default();
            if title == "end" {
                let dir = crate::receipt::write(r, &r.file.clone(), Instant::now(), true).await?;
                json!({"ok": true, "receipt": dir, "md": std::fs::read_to_string(dir.join("receipt.md")).unwrap_or_default()})
            } else {
                r.cfg.frames = true;
                r.run_items(&[parse_item(json!({"claim": title}), 0)?]).await;
                if let Some(p) = s("record") {
                    record::append(Path::new(&p), &[format!("claim: {title}")])?;
                }
                json!({"ok": true, "claim": title})
            }
        }
        "status" => {
            json!({"ok": true, "pid": std::process::id(), "tabs": r.tabs.keys().collect::<Vec<_>>(), "terminals": r.ptys.keys().collect::<Vec<_>>(),
            "steps": r.results.len(), "file": r.file})
        }
        "close" => {
            r.close().await;
            json!({"ok": true})
        }
        o => bail!("unknown op {o}"),
    })
}
async fn explain_queries(r: &mut Runner, qs: &[crate::expr::Expr]) -> Value {
    let mut out = vec![];
    for q in qs {
        let v = r.value(q).await.unwrap_or(Value::Null);
        let desc = match &v {
            Value::Array(a) if a.iter().all(|x| x.get("__el").is_some()) => {
                let mut locs = vec![];
                for x in a.iter().take(5) {
                    if let (Some(rf), Ok(t)) = (x["ref"].as_i64(), r.tab(None).await) {
                        locs.push(t.locator_for(rf).await.unwrap_or_default())
                    }
                }
                json!({"matches": a.len(), "elements": locs})
            }
            v => json!(crate::runner::short(v)),
        };
        out.push(json!({"query": key(q), "value": desc}));
    }
    let _ = queries;
    json!(out)
}

// ---------- daemon ----------
pub fn parse_idle(s: &str) -> Option<Duration> {
    if s == "never" {
        return None;
    }
    let (n, unit) =
        s.trim().split_at(s.trim().find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
    let n: u64 = n.parse().unwrap_or(30);
    Some(Duration::from_secs(
        n * match unit {
            "s" => 1,
            "h" => 3600,
            _ => 60,
        },
    ))
}

/// Local transport for the session daemon: Unix sockets, or named pipes on Windows.
#[cfg(unix)]
mod transport {
    use super::*;
    pub struct Listener(tokio::net::UnixListener);
    impl Listener {
        pub fn bind(name: &str) -> Result<Self> {
            let path = sock_path(name);
            std::fs::create_dir_all(path.parent().unwrap())?;
            std::fs::remove_file(&path).ok();
            Ok(Listener(tokio::net::UnixListener::bind(&path)?))
        }
        pub async fn accept(&mut self) -> Result<tokio::net::UnixStream> {
            Ok(self.0.accept().await?.0)
        }
    }
    pub fn cleanup(name: &str) {
        std::fs::remove_file(sock_path(name)).ok();
    }
    pub async fn connect(name: &str) -> Result<tokio::net::UnixStream> {
        Ok(tokio::net::UnixStream::connect(sock_path(name)).await?)
    }
    pub fn detach(c: &mut std::process::Command) {
        use std::os::unix::process::CommandExt;
        c.process_group(0);
    }
}
#[cfg(windows)]
mod transport {
    use super::*;
    use tokio::net::windows::named_pipe::{
        ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
    };
    /// One pipe per (project directory, session name).
    fn pipe(name: &str) -> String {
        let cwd = std::env::current_dir().unwrap_or_default().to_string_lossy().to_lowercase();
        let h = cwd
            .bytes()
            .fold(0xcbf29ce484222325u64, |h, b| (h ^ b as u64).wrapping_mul(0x100000001b3));
        format!(r"\\.\pipe\testkit-{h:x}-{name}")
    }
    pub struct Listener {
        name: String,
        next: NamedPipeServer,
    }
    impl Listener {
        pub fn bind(name: &str) -> Result<Self> {
            Ok(Listener {
                name: pipe(name),
                next: ServerOptions::new().first_pipe_instance(true).create(pipe(name))?,
            })
        }
        pub async fn accept(&mut self) -> Result<NamedPipeServer> {
            self.next.connect().await?;
            Ok(std::mem::replace(&mut self.next, ServerOptions::new().create(&self.name)?))
        }
    }
    pub fn cleanup(_: &str) {}
    pub async fn connect(name: &str) -> Result<NamedPipeClient> {
        Ok(ClientOptions::new().open(pipe(name))?)
    }
    pub fn detach(c: &mut std::process::Command) {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x8;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x200;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        c.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW);
    }
}

pub async fn serve(name: &str, cfg: Config, idle: Option<Duration>) -> Result<()> {
    let mut listener = transport::Listener::bind(name)?;
    let mut r = Runner::new(cfg);
    r.file = format!("session:{name}");
    let mut last = Instant::now();
    loop {
        let wait =
            idle.map(|i| i.saturating_sub(last.elapsed())).unwrap_or(Duration::from_secs(3600));
        let Ok(Ok(stream)) = tokio::time::timeout(wait, listener.accept()).await else {
            if idle.is_some_and(|i| last.elapsed() >= i) {
                break;
            } else {
                continue;
            }
        };
        last = Instant::now();
        let (rd, mut wr) = tokio::io::split(stream);
        let mut line = String::new();
        BufReader::new(rd).read_line(&mut line).await?;
        let req: Value = serde_json::from_str(&line).unwrap_or_default();
        let stop = req["op"] == "stop";
        let res = if stop { json!({"ok": true, "stopped": name}) } else { op(&mut r, &req).await };
        wr.write_all(format!("{res}\n").as_bytes()).await.ok();
        wr.flush().await.ok();
        if stop {
            break;
        }
    }
    r.close().await;
    transport::cleanup(name);
    Ok(())
}

pub async fn send(name: &str, req: &Value) -> Result<Value> {
    let s = transport::connect(name).await?;
    let (rd, mut wr) = tokio::io::split(s);
    wr.write_all(format!("{req}\n").as_bytes()).await?;
    wr.flush().await?;
    let mut out = String::new();
    BufReader::new(rd).read_line(&mut out).await?;
    serde_json::from_str(&out).map_err(|e| anyhow!("bad daemon reply: {e}"))
}

/// Connects to the session daemon, starting it in the background first if needed.
pub async fn ensure(name: &str, extra: &[String]) -> Result<()> {
    if send(name, &json!({"op": "status"})).await.is_ok() {
        return Ok(());
    }
    std::fs::create_dir_all(".testkit/sessions")?;
    let log = std::fs::File::create(format!(".testkit/sessions/{name}.log"))?;
    let mut c = std::process::Command::new(std::env::current_exe()?);
    c.args(["__daemon", "--session", name])
        .args(extra)
        .stdin(std::process::Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log);
    transport::detach(&mut c);
    c.spawn()?;
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(15) {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if send(name, &json!({"op": "status"})).await.is_ok() {
            return Ok(());
        }
    }
    bail!("session `{name}` did not start; see .testkit/sessions/{name}.log")
}
