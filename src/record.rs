//! Recording (spec §12): successful CLI steps become `.tk.yaml` items with stable locators,
//! parameterised values and no secrets.
use crate::item::{scalar_text, Item};
use crate::runner::{Runner, StepResult};
use anyhow::Result;
use regex::Regex;
use serde_json::Value;
use std::io::Write;
use std::path::Path;

const READ_ONLY: &[&str] = &["snapshot", "shot", "mark"];

/// Quotes a step value when YAML would misread it (spec §16).
///
/// ```
/// use testkit::record::yaml_item;
/// assert_eq!(yaml_item(r#"click: button "Save""#), r#"click: button "Save""#);
/// assert_eq!(yaml_item(r#"type: "orders""#), r#"type: '"orders"'"#);
/// assert_eq!(yaml_item("click: #save"), "click: '#save'");
/// assert_eq!(yaml_item("expect: its json: x"), "expect: 'its json: x'");
/// ```
pub fn yaml_item(line: &str) -> String {
    let (verb, text) = line.split_once(": ").unwrap_or((line.trim_end_matches(':'), ""));
    let unsafe_start = text.starts_with([
        '#', '@', '`', '*', '&', '!', '|', '>', '%', '[', '{', '\'', '"', '-', '?', ':',
    ]);
    if text.is_empty() {
        return format!("{verb}:");
    }
    if unsafe_start || text.contains(": ") || text.contains(" #") || text.ends_with(':') {
        return format!("{verb}: '{}'", text.replace('\'', "''"));
    }
    format!("{verb}: {text}")
}

pub fn append(path: &Path, lines: &[String]) -> Result<()> {
    if let Some(p) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(p)?;
    }
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
    for l in lines {
        writeln!(f, "{l}")?;
    }
    Ok(())
}

fn env_name(label: &str) -> String {
    let n: String = label
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_uppercase() } else { '_' })
        .collect();
    let n = n.trim_matches('_').to_string();
    if n.is_empty() {
        "PASSWORD".into()
    } else {
        n
    }
}

/// Writes one successful step; returns notes for the user (parameterised values, lints).
pub async fn record(
    r: &mut Runner,
    item: &Item,
    res: &StepResult,
    path: &Path,
) -> Result<Vec<String>> {
    if READ_ONLY.contains(&item.verb.as_str()) || !res.ok() {
        return Ok(vec![]);
    }
    let mut text = item.text.clone();
    let mut notes = vec![];
    for m in Regex::new(r"@e(\d+)")?.captures_iter(&item.text.clone()) {
        let n: i64 = m[1].parse().unwrap_or(0);
        if let Ok(t) = r.tab(None).await {
            if let Some(stable) = t.locator_for(n).await {
                text = text.replace(&m[0], &stable);
            }
        }
    }
    if text.contains("@e") {
        notes.push(format!("⚠ could not turn a ref into a stable locator in `{text}`"))
    }
    let lit = Regex::new(r#""((?:[^"\\]|\\.)*)""#)?;
    let volatile = Regex::new(r"\d{4}-\d{2}-\d{2}|\d{1,2}:\d{2}|\b\d{3,}\b")?;
    if item.verb == "fill" && res.it["attrs"]["type"] == "password" {
        if let Some(c) = lit.captures_iter(&text.clone()).last() {
            let name = env_name(&scalar_text(&res.it["name"]));
            text = text.replace(&c[0], &format!("\"${{env.{name}}}\""));
            notes.push(format!(
                "🔒 recorded the password as ${{env.{name}}}; set {name} before replaying"
            ));
        }
    }
    for c in lit.captures_iter(&text.clone()) {
        let v = &c[1];
        if v.len() < 3 || v.contains("${") {
            continue;
        }
        if let Some((k, _)) =
            r.vars.iter().find(|(k, x)| k.as_str() != "base_url" && scalar_text(x) == v)
        {
            text = text.replacen(&c[0], &format!("\"${{{k}}}\""), 1);
            notes.push(format!("↺ \"{v}\" recorded as ${{{k}}}"));
        } else if volatile.is_match(v) {
            notes.push(format!("⚠ volatile literal \"{v}\" (contains a date, time or id); consider a regex like /…/"));
        }
    }
    if item.verb == "wait" && Regex::new(r"^\d")?.is_match(&text) {
        notes.push(
            "⚠ fixed sleeps make tests slow and flaky; prefer `wait: for …` or an `expect:`".into(),
        )
    }
    let mut lines = vec![format!("- {}", yaml_item(&format!("{}: {text}", item.verb)))];
    if let Some(d) = &item.opts.dialog {
        lines.push(format!("  dialog: {d}"))
    }
    if let Some(m) = &item.opts.measure {
        lines.push(format!("  measure: {}", scalar_text(m)))
    }
    if let Some(s) = &item.opts.session {
        lines.push(format!("  session: {s}"))
    }
    for (k, v) in [("timeout", &item.opts.timeout), ("allow", &item.opts.allow)] {
        if let Some(v) = v {
            lines.push(format!(
                "  {k}: {}",
                match v {
                    Value::String(s) => s.clone(),
                    v => v.to_string(),
                }
            ))
        }
    }
    append(path, &lines)?;
    notes.push(format!("recorded → {}", path.display()));
    Ok(notes)
}
