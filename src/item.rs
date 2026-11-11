//! A test file item: exactly one verb key plus sibling keys (spec §2).
//!
//! ```
//! use testkit::item::parse_yaml;
//! let items = parse_yaml("- click: button \"Save\"\n  timeout: 2s\n- GET: /api\n  asserts:\n    - ok: $.resp.status == 200\n").unwrap();
//! assert_eq!(items[0].verb, "click");
//! assert_eq!(items[1].verb, "GET");
//! assert_eq!(items[1].line, 3);
//! let i = &parse_yaml("- POST: /api\n  expect: [status is 201, json.id is a Number]\n").unwrap()[0];
//! assert_eq!((i.verb.as_str(), i.opts.asserts.as_ref().unwrap().len()), ("POST", 2));
//! assert!(parse_yaml("- POST: /api\n  expect: status is is").is_err());
//! assert_eq!(parse_yaml("- create order: for \"Al\"").unwrap()[0].verb, "create order"); // a flow
//! assert!(parse_yaml("- Clik: x").unwrap_err().to_string().contains("unknown step"));
//! assert!(parse_yaml("- click: x\n  colour: red").unwrap_err().to_string().contains("unknown key `colour`"));
//! ```
use crate::base_request::{Assert, RequestConfig};
use crate::expr::parse::{args, Args};
use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub const HTTP: &[&str] =
    &["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "CONNECT", "TRACE"];
pub const VERBS: &[&str] = &[
    "meta", "claim", "call", "visit", "click", "dblclick", "hover", "check", "uncheck", "tap",
    "focus", "fill", "upload", "type", "press", "drag", "wait", "expect", "extract", "shot",
    "snapshot", "route", "unroute", "exec", "spawn", "enter", "signal", "resize", "trace",
    "profile", "heap", "coverage", "throttle", "network", "emulate", "mark", "back", "reload",
    "act", "launch", "swipe", "home", "deeplink",
];

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Opts {
    pub title: Option<String>,
    pub dump: Option<bool>,
    #[serde(default, with = "serde_yaml::with::singleton_map_recursive")]
    pub asserts: Option<Vec<Assert>>,
    pub exports: Option<Value>,
    pub iterations: Option<Value>,
    pub timeout: Option<Value>,
    pub session: Option<String>,
    pub allow: Option<Value>,
    pub claim: Option<String>,
    pub evidence: Option<Vec<String>>,
    pub independent: Option<bool>,
    pub measure: Option<Value>,
    pub samples: Option<u32>,
    pub dialog: Option<String>,
    pub matches: Option<Value>,
    pub with: Option<Map<String, Value>>,
    pub respond: Option<Value>,
    pub modify: Option<Value>,
    pub abort: Option<Value>,
    pub delay: Option<Value>,
    pub times: Option<u32>,
    pub cookies: Option<String>,
    pub cwd: Option<String>,
    pub env: Option<Map<String, Value>>,
    pub size: Option<String>,
    pub prompt: Option<String>,
    pub ready: Option<String>,
    pub record: Option<String>,
    #[serde(flatten)]
    pub request: RequestConfig,
}

const OPT_KEYS: &[&str] = &[
    "record",
    "title",
    "dump",
    "asserts",
    "exports",
    "iterations",
    "timeout",
    "session",
    "allow",
    "claim",
    "evidence",
    "independent",
    "measure",
    "samples",
    "dialog",
    "matches",
    "with",
    "respond",
    "modify",
    "abort",
    "delay",
    "times",
    "cookies",
    "cwd",
    "env",
    "size",
    "prompt",
    "ready",
    "headers",
    "json",
    "params",
    "disabled",
    "httpVersion",
    "follow_redirects",
    "ignore_ssl_errors",
    "raw",
    "requestBody",
    "pre_request_hook",
    "post_response_hook",
];

#[derive(Debug, Clone, Serialize)]
pub struct Item {
    pub verb: String,
    pub text: String,
    pub raw: Value,
    #[serde(skip)]
    pub args: Args,
    pub opts: Opts,
    pub line: usize,
}

/// A step key that isn't a built-in verb calls the flow of that name.
pub fn is_flow(verb: &str) -> bool {
    !VERBS.contains(&verb) && !HTTP.contains(&verb)
}

impl Item {
    /// The single-line form used by the CLI, recorder and reports: `verb: text`.
    pub fn line_text(&self) -> String {
        format!("{}: {}", self.verb, self.text)
    }
}

/// Parses a test file. YAML traps that agents and people hit constantly (a `: ` or ` #` inside an
/// unquoted step value) are repaired by quoting that value, with a warning naming the line.
pub fn parse_yaml(src: &str) -> Result<Vec<Item>> {
    let (items, quoted) = parse_yaml_quoted(src)?;
    for l in quoted {
        eprintln!("⚠ line {l}: quoted the value because it contains `: ` or ` #` (YAML syntax); write it as '…' to silence this");
    }
    Ok(items)
}

/// Like `parse_yaml`, also returning the lines whose values had to be auto-quoted.
pub fn parse_yaml_quoted(src: &str) -> Result<(Vec<Item>, Vec<usize>)> {
    let mut src = src.to_string();
    let mut quoted = vec![];
    for _ in 0..50 {
        match parse_once(&src) {
            Ok(items) => return Ok((items, quoted)),
            Err((line, e)) => match line.and_then(|l| requote(&src, l)) {
                Some(fixed) => {
                    quoted.push(line.unwrap_or(0));
                    src = fixed
                }
                None => return Err(e),
            },
        }
    }
    parse_once(&src).map(|i| (i, quoted)).map_err(|e| e.1)
}

/// Wraps the value of `- key: value` / `key: value` on line `n` (1-based) in single quotes.
///
/// ```
/// use testkit::item::requote;
/// assert_eq!(requote("- expect: button \"a: b\"\n", 1).unwrap(), "- expect: 'button \"a: b\"'\n");
/// assert_eq!(requote("  - ok: x contains \"#1\" # c\n", 1).unwrap(), "  - ok: 'x contains \"#1\" # c'\n");
/// assert!(requote("- expect: 'done'\n", 1).is_none());
/// ```
pub fn requote(src: &str, n: usize) -> Option<String> {
    let lines: Vec<&str> = src.split_inclusive('\n').collect();
    let line = lines.get(n.checked_sub(1)?)?;
    let body = line.trim_end_matches(['\n', '\r']);
    let indent = body.len() - body.trim_start().len();
    let rest = &body[indent..];
    let (dash, rest) = rest.strip_prefix("- ").map(|r| ("- ", r)).unwrap_or(("", rest));
    let (key, value) = rest.split_once(": ")?;
    if key.contains(' ') || value.starts_with(['\'', '|', '>']) || value.trim().is_empty() {
        return None;
    }
    let fixed = format!(
        "{}{dash}{key}: '{}'{}",
        &body[..indent],
        value.replace('\'', "''"),
        &line[body.len()..]
    );
    Some(
        lines
            .iter()
            .enumerate()
            .map(|(i, l)| if i + 1 == n { fixed.clone() } else { l.to_string() })
            .collect(),
    )
}

fn parse_once(src: &str) -> std::result::Result<Vec<Item>, (Option<usize>, anyhow::Error)> {
    let docs: Value = serde_yaml::from_str(src).map_err(|e| {
        let line = e
            .location()
            .map(|l| l.line())
            .filter(|_| e.to_string().contains("mapping values are not allowed"));
        (line, anyhow!("invalid YAML: {e}"))
    })?;
    let lines = item_lines(src);
    parse_values(docs, &lines).map_err(|e| {
        let msg = e.to_string();
        let item_line: Option<usize> = msg
            .strip_prefix("line ")
            .and_then(|r| r.split(':').next())
            .and_then(|n| n.parse().ok());
        // a value cut short by ` #` (YAML comment) shows up as an unclosed quote
        let line = item_line.filter(|_| msg.contains("closing quote")).and_then(|l| {
            (l..l + 8).find(|&k| {
                src.lines().nth(k - 1).is_some_and(|x| x.contains(" #") && x.contains('"'))
            })
        });
        (line, e)
    })
}

pub fn parse_values(docs: Value, lines: &[usize]) -> Result<Vec<Item>> {
    let list = match docs {
        Value::Array(a) => a,
        Value::Null => vec![],
        other => vec![other],
    };
    list.into_iter()
        .enumerate()
        .map(|(i, v)| parse_item(v, lines.get(i).copied().unwrap_or(0)))
        .collect()
}

/// Line numbers of top-level sequence items (`- ` at the outermost indent).
fn item_lines(src: &str) -> Vec<usize> {
    let indent = src
        .lines()
        .filter_map(|l| l.find("- ").filter(|&i| l[..i].trim().is_empty()))
        .min()
        .unwrap_or(0);
    src.lines()
        .enumerate()
        .filter(|(_, l)| {
            l.len() > indent
                && l[..indent].trim().is_empty()
                && (l[indent..].starts_with("- ") || &l[indent..] == "-")
        })
        .map(|(i, _)| i + 1)
        .collect()
}

pub fn scalar_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        v => v.to_string(),
    }
}

pub fn parse_item(v: Value, line: usize) -> Result<Item> {
    let Value::Object(mut map) = v else {
        bail!("line {line}: each step must be a map like `- click: button \"Save\"`")
    };
    let is_verb = |k: &str| VERBS.contains(&k) || HTTP.contains(&k);
    let mut verbs: Vec<String> = map.keys().filter(|k| is_verb(k)).cloned().collect();
    // `claim:` and `expect:` next to another verb are sibling keys
    for k in ["claim", "expect"] {
        if verbs.len() > 1 && verbs.iter().any(|v| v == k) {
            verbs.retain(|v| v != k)
        }
    }
    let verb = match verbs.as_slice() {
        [v] => v.clone(),
        [] => {
            let unknown: Vec<_> =
                map.keys().filter(|k| !OPT_KEYS.contains(&k.as_str())).cloned().collect();
            match unknown.as_slice() {
                [k] if k == "select" => bail!("line {line}: `select:` is now `fill:` (it picks `<select>` options); `testkit migrate` rewrites it"),
                // any other single key names a flow: `login:` runs flows/login.yaml
                [k] if k.starts_with(|c: char| c.is_ascii_lowercase())
                    && k.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || " -_".contains(c))
                    && !map[k].is_object()
                    && !map[k].is_array() =>
                {
                    k.clone()
                }
                _ => bail!("line {line}: unknown step {:?}; expected one of: {}, or a flow name", unknown, VERBS.join(", ")),
            }
        }
        many => bail!("line {line}: a step has exactly one verb, found {}", many.join(", ")),
    };
    if let Some(k) =
        map.keys().find(|k| **k != verb && !is_verb(k) && !OPT_KEYS.contains(&k.as_str()))
    {
        bail!("line {line}: unknown key `{k}` on `{verb}` step")
    }
    let raw = if HTTP.contains(&verb.as_str()) {
        map.get(&verb).cloned().unwrap_or_default()
    } else {
        map.remove(&verb).unwrap_or_default()
    };
    let text = scalar_text(&raw);
    let parsed = if is_flow(&verb)
        || ["meta", "claim", "act", "launch", "swipe", "home", "deeplink"].contains(&verb.as_str())
    {
        Args::Raw(text.clone())
    } else {
        args(&verb, &text).map_err(|e| anyhow!("line {line}: `{verb}: {text}`\n{e}"))?
    };
    if let Some(e) = map.remove("expect") {
        let conds = match e {
            Value::Array(a) => a,
            v => vec![v],
        };
        for c in &conds {
            crate::expr::parse::cond(&scalar_text(c))
                .map_err(|e| anyhow!("line {line}: `expect: {}`\n{e}", scalar_text(c)))?;
        }
        let asserts = map.entry("asserts").or_insert(Value::Array(vec![]));
        if let Value::Array(a) = asserts {
            a.extend(conds.into_iter().map(|c| serde_json::json!({ "ok": scalar_text(&c) })))
        }
    }
    if !HTTP.contains(&verb.as_str()) {
        map.insert("GET".into(), Value::String("<UNSET>".into()));
    }
    let opts: Opts =
        serde_json::from_value(Value::Object(map)).map_err(|e| anyhow!("line {line}: {e}"))?;
    Ok(Item { verb, text, raw, args: parsed, opts, line })
}
