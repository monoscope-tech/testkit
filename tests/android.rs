//! Runs tests/android against an attached device or emulator; skips when there is none.
use std::process::Command;

#[test]
fn android_settings() {
    let attached = testkit::mobile::Device::connect().is_ok();
    if !attached {
        eprintln!("skipping: no Android device (start an emulator to run this)");
        return;
    }
    let out = Command::new(env!("CARGO_BIN_EXE_testkit"))
        .args(["test", "tests/android"])
        .output()
        .unwrap();
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{s}{}", String::from_utf8_lossy(&out.stderr));
}
