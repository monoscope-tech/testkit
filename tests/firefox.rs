//! Runs tests/firefox in Firefox over WebDriver BiDi; skips when Firefox isn't installed.
use std::process::Command;

fn tk(args: &[&str]) -> (bool, String) {
    let o = Command::new(env!("CARGO_BIN_EXE_testkit")).args(args).output().unwrap();
    (
        o.status.success(),
        format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)),
    )
}

#[test]
fn firefox_flows() {
    if testkit::bidi::find_firefox().is_none() {
        eprintln!("skipping: Firefox not installed (set TESTKIT_FIREFOX)");
        return;
    }
    let (ok, out) = tk(&["test", "tests/firefox/orders.tk.yaml"]);
    assert!(ok, "{out}");
    let (ok, out) = tk(&["test", "tests/firefox/devtools_only.yaml"]);
    assert!(!ok && out.contains("E_UNSUPPORTED"), "{out}");
}
