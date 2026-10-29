//! testkit tests itself: runs every tests/tk/*.tk.yaml with the freshly built binary.
//! Each file drives the fixture app (tests/app) and/or the testkit CLI through exec/spawn.
use std::process::Command;

#[test]
fn testkit_proves_itself() {
    let bin = env!("CARGO_BIN_EXE_testkit");
    let root = env!("CARGO_MANIFEST_DIR");
    let filter = std::env::var("TK_FILTER").unwrap_or_default();
    let out = Command::new(bin)
        .current_dir(root)
        .env("TESTKIT_BIN", bin)
        .env("NO_COLOR", "1")
        .args(["test", "tests/tk", "-q", &filter])
        .output()
        .expect("run testkit");
    let text =
        format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    println!("{text}");
    assert!(out.status.success(), "self-test suite failed (see output above)");
}
