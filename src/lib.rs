// src/lib.rs

// Declare modules in the order needed by sibling modules.
pub mod base_browser;
pub mod base_request;
pub mod base_cli;

// Optionally re-export items:
pub use base_request::{ConfigVariable, TestContext, run, run_json};

use libc::c_char;
use std::ffi::{CStr, CString};
use std::path::PathBuf;
use std::sync::Arc;

#[no_mangle]
pub extern "C" fn haskell_binding(
    content: *const c_char,
    collection_id: *const c_char,
    local_vars: *const c_char,
) -> *mut c_char {
    if content.is_null() || collection_id.is_null() || local_vars.is_null() {
        let err = CString::new("{\"error\": \"Null pointer passed in.\"}")
            .expect("CString::new failed");
        return err.into_raw();
    }

    let cont_rs = unsafe { CStr::from_ptr(content) }
        .to_str()
        .unwrap_or_default()
        .to_owned();

    let col_path: Option<PathBuf> = unsafe { CStr::from_ptr(collection_id) }
        .to_str()
        .ok()
        .map(|s| PathBuf::from(s));

    let local_vars_str = unsafe { CStr::from_ptr(local_vars) }
        .to_str()
        .unwrap_or("{}");

    let local_vars_map: Vec<base_request::ConfigVariable> =
        serde_json::from_str(local_vars_str).unwrap_or_default();

    let ctx = base_request::TestContext {
        file: Arc::new("haskell_binding".to_string()),
        file_source: Arc::new(cont_rs.clone()),
        should_log: false,
        ..Default::default()
    };

    let rt = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");
    let result = rt.block_on(async {
        base_request::run_json(ctx, cont_rs, col_path, Some(local_vars_map)).await
    });

    let output_json = match result {
        Ok(res) => serde_json::to_string(&res)
            .unwrap_or_else(|e| format!("{{\"error\": \"Serialization error: {}\"}}", e)),
        Err(e) => format!("{{\"error\": \"{}\"}}", e),
    };

    CString::new(output_json)
        .unwrap_or_else(|_| CString::new("{\"error\": \"CString conversion failed\"}").unwrap())
        .into_raw()
}

#[no_mangle]
pub extern "C" fn free_haskell_binding_result(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    let _ = unsafe { CString::from_raw(s) };
}