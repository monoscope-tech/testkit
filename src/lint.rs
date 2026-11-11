//! `testkit lint`: static checks on test files, without running anything.
//!
//! ```
//! use testkit::lint::lint;
//! let src = "- visit: http://localhost:3000/login\n- wait: 2s\n- expect: text \"Order 2026-01-05\" is visible\n- GET: /x/{{id}}\n- click: <div:nth-of-type(3) > span/>\n- expect: button \"a: b\" is visible\n";
//! let f = lint(src);
//! let rules: Vec<&str> = f.iter().map(|x| x.rule).collect();
//! assert_eq!(rules, ["absolute-url", "fixed-sleep", "volatile-literal", "legacy-syntax", "brittle-css", "yaml-quote"]);
//! assert!(lint("- click: \"x").iter().any(|x| x.error));
//! ```
use crate::item::{parse_yaml_quoted, HTTP};
use regex::Regex;

#[derive(Debug, Clone)]
pub struct Finding {
    pub line: usize,
    pub rule: &'static str,
    pub message: String,
    pub error: bool,
}

pub fn lint(src: &str) -> Vec<Finding> {
    let w = |line, rule, message: String| Finding { line, rule, message, error: false };
    let (items, quoted) = match parse_yaml_quoted(src) {
        Ok(x) => x,
        Err(e) => {
            let line = e
                .to_string()
                .strip_prefix("line ")
                .and_then(|r| r.split(':').next())
                .and_then(|n| n.parse().ok())
                .unwrap_or(0);
            return vec![Finding { line, rule: "parse", message: e.to_string(), error: true }];
        }
    };
    let volatile = Regex::new(r"\d{4}-\d{2}-\d{2}|\b\d{1,2}:\d{2}\b|\b\d{4,}\b").unwrap();
    let lit = Regex::new(r#""((?:[^"\\]|\\.)*)""#).unwrap();
    let local = Regex::new(r"^https?://(localhost|127\.0\.0\.1)(:\d+)?").unwrap();
    let sleep = Regex::new(r"^\d").unwrap();
    let mut out = vec![];
    for it in &items {
        let (l, t) = (it.line, it.text.as_str());
        if (it.verb == "visit" || HTTP.contains(&it.verb.as_str())) && local.is_match(t) {
            out.push(w(l, "absolute-url", format!("`{t}` hard-codes a local server; use a relative path with `meta: {{ base_url: … }}` or --base-url")));
        }
        if it.verb == "wait" && sleep.is_match(t) {
            out.push(w(l, "fixed-sleep", format!("`wait: {t}` is a fixed sleep; prefer `wait: for …` or an `expect:` (they retry)")));
        }
        for c in lit.captures_iter(t) {
            if !c[1].contains("${") && volatile.is_match(&c[1]) {
                out.push(w(l, "volatile-literal", format!("\"{}\" contains a date, time or id that may change; use a regex like /…/ or a variable", &c[1])));
            }
        }
        let raw = format!(
            "{}{}",
            serde_json::to_string(&it.raw).unwrap_or_default(),
            serde_json::to_string(&it.opts).unwrap_or_default()
        );
        if raw.contains("{{") || raw.contains("$.env.") {
            out.push(w(
                l,
                "legacy-syntax",
                "uses `{{var}}` or `$.env.X`; `testkit migrate` rewrites them to `${…}`".into(),
            ));
        }
        if t.contains("nth-of-type") || t.contains(":nth-child") {
            out.push(w(l, "brittle-css", "positional CSS breaks when the layout changes; prefer a role locator like `button \"Save\"`".into()));
        }
    }
    for q in quoted {
        out.push(w(
            q,
            "yaml-quote",
            "the value contains `: ` or ` #`; YAML needs it quoted: '…'".into(),
        ));
    }
    out.sort_by_key(|f| f.line);
    out
}

/// `testkit migrate`: rewrites legacy forms to their current spelling.
///
/// ```
/// use testkit::lint::migrate;
/// let old = "- GET: /x/{{id}}\n  asserts:\n    - ok: status is 200\n    - ok: $.env.X\n- POST: /y\n  asserts:\n    - ok: status is 201\n    - array: $.resp.json\n- select: field \"P\" with \"x\"\n- expect: the url of page is \"/\"\n";
/// assert_eq!(migrate(old), "- GET: /x/${id}\n  expect:\n    - status is 200\n    - ${env.X}\n- POST: /y\n  asserts:\n    - ok: status is 201\n    - array: $.resp.json\n- fill: field \"P\" with \"x\"\n- expect: the url is \"/\"\n");
/// ```
pub fn migrate(src: &str) -> String {
    let re = |p: &str| Regex::new(p).expect("static regex");
    let s = re(r"\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}").replace_all(src, "$${$1}");
    let s = re(r"\$\.env\.([A-Za-z_][A-Za-z0-9_]*)").replace_all(&s, "$${env.$1}");
    let s = re(r"(?m)^(\s*- )select: ").replace_all(&s, "${1}fill: ");
    let s = re(r"\bthe (url|title|path) of page\b").replace_all(&s, "the $1");
    // an `asserts:` block of only `- ok:` items becomes `expect:`
    let lines: Vec<&str> = s.lines().collect();
    let mut out: Vec<String> = vec![];
    let mut i = 0;
    while i < lines.len() {
        let l = lines[i].trim_end();
        if let Some(ind) = l.strip_suffix("asserts:").filter(|p| p.trim().is_empty()) {
            fn item<'a>(l: &'a str, ind: &str) -> Option<&'a str> {
                l.strip_prefix(ind)?.strip_prefix("  - ")
            }
            let oks: Vec<&str> =
                lines[i + 1..].iter().map_while(|l| item(l, ind)?.strip_prefix("ok: ")).collect();
            if !oks.is_empty() && lines.get(i + 1 + oks.len()).and_then(|l| item(l, ind)).is_none()
            {
                match oks.as_slice() {
                    [one] => out.push(format!("{ind}expect: {one}")),
                    many => out.extend(
                        std::iter::once(format!("{ind}expect:"))
                            .chain(many.iter().map(|o| format!("{ind}  - {o}"))),
                    ),
                }
                i += 1 + oks.len();
                continue;
            }
        }
        out.push(lines[i].into());
        i += 1;
    }
    out.join("\n") + if src.ends_with('\n') { "\n" } else { "" }
}
