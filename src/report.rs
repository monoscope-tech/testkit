//! Output: live step reports (spec §7.2) and machine formats (json, junit, tap, github).
use crate::runner::{Claim, StepResult};
use colored_json::ToColoredJson;
use serde_json::{json, Value};

const DIM: &str = "\x1b[2m";
const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const RESET: &str = "\x1b[0m";

fn color() -> bool {
    std::env::var("NO_COLOR").is_err() && atty()
}
fn atty() -> bool {
    use std::io::IsTerminal;
    std::io::stderr().is_terminal()
}
fn c(code: &str) -> &str {
    if color() {
        code
    } else {
        ""
    }
}

/// The human step report: one header line plus a semantic diff, at most ~15 lines.
pub fn step_text(r: &StepResult, verbose: bool) -> String {
    let (mark, col) = match r.status.as_str() {
        "pass" => ("✓", GREEN),
        "skip" => ("⏭", YELLOW),
        _ => ("✗", RED),
    };
    let name = r
        .step_name
        .clone()
        .filter(|n| !n.starts_with(&r.verb))
        .map(|n| format!("  {}{n}{}", c(DIM), c(RESET)))
        .unwrap_or_default();
    let mut out = vec![format!(
        "{}{mark}{} {}{name}  {}{}ms · {}:{}{}",
        c(col),
        c(RESET),
        r.line_text(),
        c(DIM),
        r.ms,
        short_file(&r.file),
        r.line,
        c(RESET)
    )];
    if r.status == "skip" {
        return out.join("\n");
    }
    for (k, label) in [
        ("url", "url"),
        ("appeared", "appeared"),
        ("gone", "gone"),
        ("console", "console"),
        ("network", "network"),
    ] {
        match &r.report[k] {
            Value::Array(a) if k == "url" && a.len() == 2 => {
                out.push(format!("  {label:<9}{} → {}", s(&a[0]), s(&a[1])))
            }
            Value::Array(a) if !a.is_empty() => out.push(format!(
                "  {label:<9}{}",
                a.iter().map(s).collect::<Vec<_>>().join(if k == "console" {
                    "\n           "
                } else {
                    " · "
                })
            )),
            _ => {}
        }
    }
    if let Some(snap) = r.report["snapshot"].as_str() {
        out.push(snap.to_string())
    }
    if verbose || r.status == "fail" {
        for l in r.step_log.lines().filter(|l| !l.trim().is_empty()) {
            out.push(format!("  {l}"))
        }
    } else if r.verb == "expect" || !r.assert_results.is_empty() {
        for l in r.step_log.lines().filter(|l| l.starts_with('✅')) {
            out.push(format!("  {l}"))
        }
    }
    out.join("\n")
}
fn s(v: &Value) -> String {
    crate::item::scalar_text(v)
}
fn short_file(f: &str) -> String {
    f.trim_start_matches("./").to_string()
}

pub fn summary(results: &[StepResult], claims: &[Claim], ms: u128) -> String {
    let n = |st: &str| results.iter().filter(|r| r.status == st).count();
    let mut line = format!(
        "{} passed, {} failed, {} skipped · {:.1}s",
        n("pass"),
        n("fail"),
        n("skip"),
        ms as f64 / 1000.0
    );
    if !claims.is_empty() {
        let p = claims.iter().filter(|c| c.status == "pass").count();
        line = format!(
            "{}{p}/{} claims proven{} · {line}",
            if p == claims.len() { c(GREEN) } else { c(RED) },
            claims.len(),
            c(RESET)
        );
    }
    line
}

pub fn json(results: &[StepResult]) -> String {
    let v = serde_json::to_string_pretty(results).unwrap_or_default();
    if color() {
        v.to_colored_json_auto().unwrap_or(v)
    } else {
        v
    }
}

pub fn junit(files: &[(String, Vec<StepResult>)]) -> String {
    let esc = |s: &str| {
        s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
    };
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuites>\n");
    for (f, rs) in files {
        let fails = rs.iter().filter(|r| r.status == "fail").count();
        let skips = rs.iter().filter(|r| r.status == "skip").count();
        out.push_str(&format!("  <testsuite name=\"{}\" tests=\"{}\" failures=\"{fails}\" skipped=\"{skips}\" time=\"{:.3}\">\n", esc(f), rs.len(), rs.iter().map(|r| r.ms).sum::<u64>() as f64 / 1000.0));
        for r in rs {
            out.push_str(&format!(
                "    <testcase name=\"{}\" classname=\"{}:{}\" time=\"{:.3}\"",
                esc(&r.step_name.clone().unwrap_or_else(|| r.line_text())),
                esc(f),
                r.line,
                r.ms as f64 / 1000.0
            ));
            match r.status.as_str() {
                "fail" => out.push_str(&format!(
                    "><failure message=\"{}\">{}</failure></testcase>\n",
                    esc(r
                        .step_error
                        .as_deref()
                        .unwrap_or("assertion failed")
                        .lines()
                        .next()
                        .unwrap_or("")),
                    esc(&r.step_log)
                )),
                "skip" => out.push_str("><skipped/></testcase>\n"),
                _ => out.push_str("/>\n"),
            }
        }
        out.push_str("  </testsuite>\n");
    }
    out + "</testsuites>\n"
}

pub fn tap(results: &[StepResult]) -> String {
    let mut out = format!("TAP version 13\n1..{}\n", results.len());
    for (i, r) in results.iter().enumerate() {
        let d = r.step_name.clone().unwrap_or_else(|| r.line_text());
        match r.status.as_str() {
            "pass" => out.push_str(&format!("ok {} - {d}\n", i + 1)),
            "skip" => out.push_str(&format!("ok {} - {d} # SKIP\n", i + 1)),
            _ => out.push_str(&format!(
                "not ok {} - {d}\n  ---\n  message: {}\n  at: {}:{}\n  ...\n",
                i + 1,
                json!(r.step_error.clone().unwrap_or_default()),
                r.file,
                r.line
            )),
        }
    }
    out
}

/// GitHub Actions annotations on the failing YAML line, plus a markdown step summary.
pub fn github(results: &[StepResult], claims: &[Claim]) -> String {
    let mut out = String::new();
    for r in results.iter().filter(|r| r.status == "fail") {
        let msg = r
            .step_error
            .clone()
            .unwrap_or_else(|| r.step_log.clone())
            .replace('%', "%25")
            .replace('\n', "%0A");
        out.push_str(&format!(
            "::error file={},line={},title={}::{msg}\n",
            r.file,
            r.line,
            r.line_text().replace(',', ";")
        ));
    }
    if let Ok(p) = std::env::var("GITHUB_STEP_SUMMARY") {
        let md = format!(
            "### testkit\n\n{}\n\n| | step | file |\n|---|---|---|\n{}\n",
            summary(results, claims, results.iter().map(|r| r.ms as u128).sum()),
            results
                .iter()
                .map(|r| format!(
                    "| {} | `{}` | {}:{} |",
                    match r.status.as_str() {
                        "pass" => "✅",
                        "skip" => "⏭",
                        _ => "❌",
                    },
                    r.line_text().replace('|', "\\|"),
                    r.file,
                    r.line
                ))
                .collect::<Vec<_>>()
                .join("\n")
        );
        std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(p)
            .and_then(|mut f| std::io::Write::write_all(&mut f, md.as_bytes()))
            .ok();
    }
    out
}
