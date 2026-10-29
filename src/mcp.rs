//! MCP server on stdio (spec §13): six tools; the grammar is the API.
use crate::runner::{Config, Runner};
use crate::session::op;
use serde_json::{json, Value};
use std::collections::HashMap;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

pub const GRAMMAR: &str = include_str!("grammar.md");

fn tools() -> Value {
    let s = |d: &str| json!({"type": "string", "description": d});
    json!([
        {"name": "step", "description": format!("Run one or more testkit steps (any surface: HTTP, browser, terminal) and get a semantic step report.\n\n{GRAMMAR}"),
         "inputSchema": {"type": "object", "properties": {"line": s("One step, e.g. `click: button \"Save\"` or `expect: no console errors`"), "yaml": s("Several YAML items"), "session": s("Session name (default: default)"), "record": s("Append successful steps to this .tk.yaml file")}}},
        {"name": "snapshot", "description": "Aria snapshot of the page (or terminal screen). Every line, minus `- ` and `:`, is a valid locator; refs like [ref=e5] can be used as @e5.",
         "inputSchema": {"type": "object", "properties": {"locator": s("Scope, e.g. main or form \"Login\""), "all": {"type": "boolean"}, "session": s("Session name")}}},
        {"name": "find", "description": "Find elements whose name or text contains the given text; returns stable locators.", "inputSchema": {"type": "object", "properties": {"text": s("Text to look for"), "session": s("Session name")}, "required": ["text"]}},
        {"name": "observe", "description": "Console, network, terminal output or page state since the last step (all: true for the whole session).",
         "inputSchema": {"type": "object", "properties": {"kind": {"type": "string", "enum": ["console", "network", "output", "page"]}, "all": {"type": "boolean"}, "session": s("Session name")}, "required": ["kind"]}},
        {"name": "claim", "description": "Start a named claim (`title`) before the steps that prove it; call with title `end` to write a proof receipt and get receipt.md.",
         "inputSchema": {"type": "object", "properties": {"title": s("What the following steps prove, or `end`"), "session": s("Session name")}, "required": ["title"]}},
        {"name": "receipt", "description": "Read or verify a receipt (latest by default).", "inputSchema": {"type": "object", "properties": {"id": s("Receipt id"), "verify": {"type": "boolean"}}}},
    ])
}

fn text_of(v: &Value) -> String {
    if let Some(e) = v["error"].as_str() {
        return format!("error: {e}");
    }
    match v {
        v if v.get("results").is_some() => {
            let mut out: Vec<String> = v["results"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|r| {
                    let res = crate::runner::StepResult {
                        verb: r["verb"].as_str().unwrap_or("").into(),
                        text: r["text"].as_str().unwrap_or("").into(),
                        status: r["status"].as_str().unwrap_or("").into(),
                        ms: r["ms"].as_u64().unwrap_or(0),
                        file: r["file"].as_str().unwrap_or("").into(),
                        line: r["line"].as_u64().unwrap_or(0) as usize,
                        report: r["report"].clone(),
                        step_log: r["step_log"].as_str().unwrap_or("").into(),
                        step_name: r["step_name"].as_str().map(String::from),
                        ..Default::default()
                    };
                    let mut t = crate::report::step_text(&res, false);
                    if !r["it"].is_null() && res.verb != "snapshot" {
                        t.push_str(&format!("\n  it = {}", crate::runner::short(&r["it"])))
                    }
                    t
                })
                .collect();
            out.extend(v["notes"].as_array().into_iter().flatten().map(crate::item::scalar_text));
            out.join("\n")
        }
        v if v.get("text").is_some() => crate::item::scalar_text(&v["text"]),
        v if v.get("md").is_some() => format!(
            "{}\n\nreceipt: {}",
            crate::item::scalar_text(&v["md"]),
            crate::item::scalar_text(&v["receipt"])
        ),
        v => serde_json::to_string_pretty(v).unwrap_or_default(),
    }
}

pub async fn serve(cfg: Config) -> anyhow::Result<()> {
    std::env::set_var("NO_COLOR", "1");
    let mut runners: HashMap<String, Runner> = HashMap::new();
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut out = tokio::io::stdout();
    while let Some(line) = lines.next_line().await? {
        let Ok(req) = serde_json::from_str::<Value>(&line) else { continue };
        let id = req.get("id").cloned();
        let method = req["method"].as_str().unwrap_or("");
        let result = match method {
            "initialize" => {
                json!({"protocolVersion": req["params"]["protocolVersion"].as_str().unwrap_or("2025-06-18"), "capabilities": {"tools": {}},
                "serverInfo": {"name": "testkit", "version": env!("CARGO_PKG_VERSION")}, "instructions": GRAMMAR})
            }
            "tools/list" => json!({"tools": tools()}),
            "ping" => json!({}),
            "tools/call" => {
                let name = req["params"]["name"].as_str().unwrap_or("");
                let a = &req["params"]["arguments"];
                let sess = a["session"].as_str().unwrap_or("default").to_string();
                let r = runners.entry(sess.clone()).or_insert_with(|| {
                    let mut r = Runner::new(cfg.clone());
                    r.file = format!("mcp:{sess}");
                    r
                });
                let reply = match name {
                    "step" => {
                        let yaml = a["yaml"]
                            .as_str()
                            .map(String::from)
                            .or_else(|| {
                                a["line"]
                                    .as_str()
                                    .map(|l| format!("- {}", crate::record::yaml_item(l)))
                            })
                            .unwrap_or_default();
                        op(r, &json!({"op": "step", "yaml": yaml, "record": a["record"]})).await
                    }
                    "snapshot" => {
                        op(r, &json!({"op": "snapshot", "locator": a["locator"], "all": a["all"]}))
                            .await
                    }
                    "find" => op(r, &json!({"op": "find", "text": a["text"]})).await,
                    "observe" => {
                        op(r, &json!({"op": "observe", "kind": a["kind"], "all": a["all"]})).await
                    }
                    "claim" => op(r, &json!({"op": "claim", "title": a["title"]})).await,
                    "receipt" => match crate::receipt::find(a["id"].as_str()) {
                        Ok(dir) if a["verify"] == true => match crate::receipt::verify(&dir) {
                            Ok(bad) if bad.is_empty() => {
                                json!({"text": format!("✓ verified {}", dir.display())})
                            }
                            Ok(bad) => json!({"text": format!("✗ changed: {}", bad.join(", "))}),
                            Err(e) => json!({"error": e.to_string()}),
                        },
                        Ok(dir) => {
                            json!({"text": std::fs::read_to_string(dir.join("receipt.md")).unwrap_or_default()})
                        }
                        Err(e) => json!({"error": e.to_string()}),
                    },
                    n => json!({"error": format!("unknown tool {n}")}),
                };
                let failed = reply["ok"] == false || reply.get("error").is_some();
                json!({"content": [{"type": "text", "text": text_of(&reply)}], "isError": failed})
            }
            m if m.starts_with("notifications/") => continue,
            _ => {
                if id.is_some() {
                    out.write_all(format!("{}\n", json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": format!("unknown method {method}")}})).as_bytes()).await?;
                    out.flush().await?;
                }
                continue;
            }
        };
        if id.is_some() {
            out.write_all(
                format!("{}\n", json!({"jsonrpc": "2.0", "id": id, "result": result})).as_bytes(),
            )
            .await?;
            out.flush().await?;
        }
    }
    for (_, mut r) in runners {
        r.close().await
    }
    Ok(())
}
