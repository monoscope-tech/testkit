//! Firefox over WebDriver BiDi: navigation, scripts (the same inject.js engine), input, screenshots,
//! dialogs, console and network logs. DevTools-only steps (routes, traces, emulation…) need Chromium.
use crate::browser::{rand_id, Log, Msg, Req, Tab, INJECT};
use crate::item::scalar_text;
use anyhow::{anyhow, bail, Result};
use async_tungstenite::tungstenite::Message;
use futures_util::StreamExt;
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::io::BufRead;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

pub(crate) type Dialog = Arc<Mutex<(bool, Option<String>)>>;
/// Per browsing context: where its events go.
pub(crate) type Sinks = Mutex<HashMap<String, (Arc<Mutex<Log>>, Dialog)>>;
type Pending = Arc<Mutex<HashMap<u64, oneshot::Sender<Result<Value>>>>>;

pub struct Bidi {
    out: mpsc::UnboundedSender<String>,
    pending: Pending,
    pub(crate) sinks: Arc<Sinks>,
    id: AtomicU64,
    child: Mutex<std::process::Child>,
    profile: std::path::PathBuf,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for Bidi {
    fn drop(&mut self) {
        self.tasks.iter().for_each(|t| t.abort());
        self.child.lock().unwrap().kill().ok();
        std::fs::remove_dir_all(&self.profile).ok();
    }
}

pub fn find_firefox() -> Option<String> {
    std::env::var("TESTKIT_FIREFOX").ok().or_else(|| {
        [
            "/Applications/Firefox.app/Contents/MacOS/firefox",
            "/usr/bin/firefox",
            "/usr/local/bin/firefox",
            "/snap/bin/firefox",
            "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
        ]
        .iter()
        .find(|p| std::path::Path::new(p).exists())
        .map(|s| s.to_string())
    })
}

/// BiDi's typed RemoteValue → plain JSON (what CDP's returnByValue gives).
fn remote(v: &Value) -> Value {
    let val = &v["value"];
    match v["type"].as_str().unwrap_or("") {
        "string" | "boolean" | "date" => val.clone(),
        "number" if val.is_number() => val.clone(),
        "array" | "set" => Value::Array(val.as_array().into_iter().flatten().map(remote).collect()),
        "object" | "map" => Value::Object(
            val.as_array()
                .into_iter()
                .flatten()
                .map(|kv| {
                    let k = kv[0]
                        .as_str()
                        .map(String::from)
                        .unwrap_or_else(|| scalar_text(&remote(&kv[0])));
                    (k, remote(&kv[1]))
                })
                .collect::<Map<_, _>>(),
        ),
        _ => Value::Null,
    }
}

fn headers(h: &Value) -> Value {
    Value::Object(
        h.as_array()
            .into_iter()
            .flatten()
            .map(|h| (scalar_text(&h["name"]), h["value"]["value"].clone()))
            .collect(),
    )
}

fn event(sinks: &Sinks, out: &mpsc::UnboundedSender<String>, v: &Value) {
    let p = &v["params"];
    let ctx = p["context"].as_str().or(p["source"]["context"].as_str()).unwrap_or("");
    let Some((log, dialog)) = sinks.lock().unwrap().get(ctx).cloned() else { return };
    let mut l = log.lock().unwrap();
    let s = |v: &Value| v.as_str().unwrap_or("").to_string();
    let r = &p["request"];
    match v["method"].as_str().unwrap_or("") {
        "log.entryAdded" => {
            let seq = l.tick();
            let f = &p["stackTrace"]["callFrames"][0];
            let source = if f.is_null() {
                String::new()
            } else {
                format!(
                    "{}:{}",
                    s(&f["url"]).rsplit('/').next().unwrap_or(""),
                    f["lineNumber"].as_i64().unwrap_or(0) + 1
                )
            };
            let level = match (s(&p["type"]).as_str(), s(&p["level"]).as_str()) {
                ("javascript", _) => "pageerror",
                (_, "error") => "error",
                (_, "warn") => "warning",
                (_, "debug") => "debug",
                _ => "log",
            };
            let text = s(&p["text"]);
            let text = if level == "pageerror" {
                text.lines().next().unwrap_or("").to_string()
            } else {
                text
            };
            l.console.push(Msg { seq, level: level.into(), text, source });
        }
        "network.beforeRequestSent" if p["redirectCount"].as_u64().unwrap_or(0) == 0 => {
            let seq = l.tick();
            let dest = s(&r["destination"]);
            let kind = match (s(&r["initiatorType"]).as_str(), dest.as_str()) {
                ("fetch", _) => "fetch",
                ("xmlhttprequest", _) => "xhr",
                (_, "style") => "stylesheet",
                (_, "") => "other",
                (_, d) => d,
            };
            l.reqs.push(Req {
                seq,
                id: s(&r["request"]),
                method: s(&r["method"]),
                url: s(&r["url"]),
                kind: kind.into(),
                t0: p["timestamp"].as_f64().unwrap_or(0.0) / 1000.0,
                req: json!({"headers": headers(&r["headers"])}),
                ..Default::default()
            });
        }
        m @ ("network.responseCompleted" | "network.fetchError") => {
            let ts = p["timestamp"].as_f64().unwrap_or(0.0);
            if let Some(q) = l.reqs.iter_mut().rev().find(|q| q.id == s(&r["request"])) {
                q.done = true;
                q.ms = (ts - q.t0 * 1000.0).max(0.0).round();
                if m == "network.fetchError" {
                    q.failed = Some(s(&p["errorText"]))
                } else {
                    q.status = p["response"]["status"].as_i64();
                    q.headers = headers(&p["response"]["headers"]);
                    q.size = p["response"]["bytesReceived"].as_f64().unwrap_or(0.0);
                }
            }
        }
        "browsingContext.userPromptOpened" => {
            l.dialogs.push(s(&p["message"]));
            let (accept, text) = dialog.lock().unwrap().clone();
            let id = 1_000_000_000 + l.tick();
            let mut params = json!({"context": ctx, "accept": accept});
            if let Some(t) = text {
                params["userText"] = json!(t)
            }
            let cmd =
                json!({"id": id, "method": "browsingContext.handleUserPrompt", "params": params});
            out.send(cmd.to_string()).ok();
        }
        _ => {}
    }
}

impl Bidi {
    pub async fn launch(headed: bool) -> Result<Arc<Bidi>> {
        let bin = find_firefox()
            .ok_or_else(|| anyhow!("Firefox not found; install it or set TESTKIT_FIREFOX"))?;
        let profile = std::env::temp_dir().join(format!("testkit-firefox-{}", rand_id()));
        std::fs::create_dir_all(&profile)?;
        let prefs = [
            ("browser.shell.checkDefaultBrowser", "false"),
            ("datareporting.policy.dataSubmissionEnabled", "false"),
            ("toolkit.telemetry.reportingpolicy.firstRun", "false"),
            ("browser.startup.homepage_override.mstone", "\"ignore\""),
            (
                "browser.download.dir",
                &format!("{:?}", std::env::current_dir()?.join(".testkit/downloads")),
            ),
            ("browser.download.folderList", "2"),
        ];
        let user_js: String =
            prefs.iter().map(|(k, v)| format!("user_pref(\"{k}\", {v});\n")).collect();
        std::fs::write(profile.join("user.js"), user_js)?;
        let mut cmd = std::process::Command::new(bin);
        cmd.args([
            "--no-remote",
            "--remote-debugging-port=0",
            "--window-size=1280,800",
            "--profile",
        ])
        .arg(&profile)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped());
        if !headed {
            cmd.arg("--headless");
        }
        let mut child = cmd.spawn().map_err(|e| anyhow!("cannot launch Firefox: {e}"))?;
        let stderr = child.stderr.take().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(stderr).lines().map_while(Result::ok) {
                if let Some(i) = line.find("ws://") {
                    tx.send(line[i..].trim().to_string()).ok();
                }
            }
        });
        let ws = tokio::task::spawn_blocking(move || rx.recv_timeout(Duration::from_secs(30)))
            .await?
            .map_err(|_| anyhow!("Firefox did not start WebDriver BiDi within 30s"))?;
        let (stream, _) = async_tungstenite::tokio::connect_async(format!("{ws}/session")).await?;
        let (mut sink, mut source) = stream.split();
        let (out, mut rx) = mpsc::unbounded_channel::<String>();
        let pending: Pending = Arc::default();
        let sinks: Arc<Sinks> = Arc::default();
        let writer = tokio::spawn(async move {
            while let Some(m) = rx.recv().await {
                if sink.send(Message::text(m)).await.is_err() {
                    break;
                }
            }
        });
        let (p, s, o) = (pending.clone(), sinks.clone(), out.clone());
        let reader = tokio::spawn(async move {
            while let Some(Ok(m)) = source.next().await {
                let Ok(v) = m.to_text().map(serde_json::from_str::<Value>) else { continue };
                let Ok(v) = v else { continue };
                if v["type"] == "event" {
                    event(&s, &o, &v)
                } else if let Some(tx) =
                    v["id"].as_u64().and_then(|id| p.lock().unwrap().remove(&id))
                {
                    tx.send(if v["type"] == "error" {
                        Err(anyhow!("{}: {}", scalar_text(&v["error"]), scalar_text(&v["message"])))
                    } else {
                        Ok(v["result"].clone())
                    })
                    .ok();
                }
            }
        });
        let b = Arc::new(Bidi {
            out,
            pending,
            sinks,
            id: AtomicU64::new(0),
            child: Mutex::new(child),
            profile,
            tasks: vec![writer, reader],
        });
        let caps = json!({"alwaysMatch": {"acceptInsecureCerts": true, "unhandledPromptBehavior": {"default": "ignore"}}});
        b.send("session.new", json!({ "capabilities": caps })).await?;
        let events = [
            "log.entryAdded",
            "network.beforeRequestSent",
            "network.responseCompleted",
            "network.fetchError",
            "browsingContext.userPromptOpened",
        ];
        b.send("session.subscribe", json!({ "events": events })).await?;
        Ok(b)
    }

    pub async fn send(&self, method: &str, params: Value) -> Result<Value> {
        let id = self.id.fetch_add(1, Ordering::SeqCst) + 1;
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(id, tx);
        self.out.send(json!({"id": id, "method": method, "params": params}).to_string())?;
        tokio::time::timeout(Duration::from_secs(60), rx)
            .await
            .map_err(|_| anyhow!("Firefox did not answer {method} within 60s"))?
            .map_err(|_| anyhow!("Firefox closed the connection"))?
    }

    /// A tab in its own user context (cookies and storage isolated), with the locator engine preloaded.
    pub async fn tab(self: &Arc<Self>) -> Result<Tab> {
        let uc =
            scalar_text(&self.send("browser.createUserContext", json!({})).await?["userContext"]);
        let preload = format!("() => {{ {INJECT} }}");
        self.send(
            "script.addPreloadScript",
            json!({"functionDeclaration": preload, "userContexts": [uc]}),
        )
        .await?;
        let ctx = scalar_text(
            &self.send("browsingContext.create", json!({"type": "tab", "userContext": uc})).await?
                ["context"],
        );
        self.send(
            "browsingContext.setViewport",
            json!({"context": ctx, "viewport": {"width": 1280, "height": 800}}),
        )
        .await
        .ok();
        let collect =
            json!({"dataTypes": ["response"], "maxEncodedDataSize": 20_000_000, "contexts": [ctx]});
        if let Err(e) = self.send("network.addDataCollector", collect).await {
            log::debug!(target: "testkit", "no response bodies in Firefox: {e}");
        }
        Ok(Tab::bidi(self.clone(), ctx, uc))
    }

    pub async fn eval(&self, ctx: &str, js: &str) -> Result<Value> {
        let p = json!({"expression": js, "target": {"context": ctx}, "awaitPromise": true, "resultOwnership": "none"});
        let r = self.send("script.evaluate", p).await?;
        if r["type"] == "exception" {
            bail!("{}", r["exceptionDetails"]["text"].as_str().unwrap_or("script error"))
        }
        Ok(remote(&r["result"]))
    }

    /// A finished response's body (needs `network.addDataCollector`).
    pub async fn body(&self, request: &str) -> Option<String> {
        let r = self
            .send("network.getData", json!({"dataType": "response", "request": request}))
            .await
            .ok()?;
        let b = &r["bytes"];
        use base64::Engine;
        Some(match b["type"].as_str()? {
            "base64" => String::from_utf8_lossy(
                &base64::engine::general_purpose::STANDARD.decode(b["value"].as_str()?).ok()?,
            )
            .into(),
            _ => scalar_text(&b["value"]),
        })
    }
    pub async fn actions(&self, ctx: &str, source: Value) -> Result<()> {
        self.send("input.performActions", json!({"context": ctx, "actions": [source]}))
            .await
            .map(drop)
    }
}

/// `press:` key names → WebDriver key values.
pub fn key_value(k: &str) -> String {
    match k.to_lowercase().as_str() {
        "enter" | "return" => "\u{E007}",
        "tab" => "\u{E004}",
        "escape" | "esc" => "\u{E00C}",
        "backspace" => "\u{E003}",
        "delete" => "\u{E017}",
        "space" => " ",
        "up" | "arrowup" => "\u{E013}",
        "down" | "arrowdown" => "\u{E015}",
        "left" | "arrowleft" => "\u{E012}",
        "right" | "arrowright" => "\u{E014}",
        "home" => "\u{E011}",
        "end" => "\u{E010}",
        "pageup" => "\u{E00E}",
        "pagedown" => "\u{E00F}",
        "ctrl" | "control" => "\u{E009}",
        "shift" => "\u{E008}",
        "alt" => "\u{E00A}",
        "meta" | "cmd" => "\u{E03D}",
        _ => return k.to_string(),
    }
    .to_string()
}
