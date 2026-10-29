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
    let mut out = vec![];
    for it in &items {
        let (l, t) = (it.line, it.text.as_str());
        if (it.verb == "visit" || HTTP.contains(&it.verb.as_str()))
            && Regex::new(r"^https?://(localhost|127\.0\.0\.1)(:\d+)?").unwrap().is_match(t)
        {
            out.push(w(l, "absolute-url", format!("`{t}` hard-codes a local server; use a relative path with `meta: {{ base_url: … }}` or --base-url")));
        }
        if it.verb == "wait" && Regex::new(r"^\d").unwrap().is_match(t) {
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
