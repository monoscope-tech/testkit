//! Behaviour of existing API test files that must survive the grammar rewrite.
use httpmock::prelude::*;
use serde_json::json;
use testkit::{run, TestContext};

fn ok(res: &[testkit::base_request::RequestResult]) -> Vec<Vec<bool>> {
    res.iter().map(|r| r.assert_results.iter().map(|a| matches!(a, Ok(true))).collect()).collect()
}

#[tokio::test]
async fn legacy_api_file_semantics() {
    let s = MockServer::start();
    s.mock(|w, t| {
        w.method(POST)
            .path("/todos")
            .json_body(json!({"task": "write", "n": 5}))
            .header("X-Key", "abc");
        t.status(201)
            .json_body(json!({"id": 7, "task": "write", "tags": ["a", "b"], "when": "2024-01-02"}));
    });
    s.mock(|w, t| {
        w.method(GET).path("/todos/7").query_param("full", "yes");
        t.status(200).json_body(json!({"id": 7, "done": false, "name": "x"}));
    });
    std::env::set_var("TK_KEY", "abc");
    let yaml = format!(
        r#"
- title: create
  POST: {base}/todos
  headers:
    X-Key: $.env.TK_KEY
  json:
    task: write
    n: 5
  asserts:
    - ok: $.resp.status == 201
    - ok: $.resp.json.task == "write"
    - number: $.resp.json.id
    - array: $.resp.json.tags
    - notEmpty: $.resp.json.tags
    - contains: $.resp.json.tags ~ a
    - date: $.resp.json.when %Y-%m-%d
    - ok: $.resp.status == 500
  exports:
    todo_id: $.resp.json.id
- title: fetch
  GET: {base}/todos/{{{{todo_id}}}}
  params:
    full: "yes"
  asserts:
    - ok: $.resp.json.id == 7
    - boolean: $.resp.json.done
    - string: $.resp.json.name
- title: skipped
  GET: {base}/nothing
  disabled: true
  asserts:
    - ok: $.resp.status == 200
"#,
        base = s.base_url()
    );
    let res = run(TestContext { file: "t.tk.yaml".to_string().into(), ..Default::default() }, yaml)
        .await
        .unwrap();
    assert_eq!(
        ok(&res),
        vec![
            vec![true, true, true, true, true, true, true, false],
            vec![true, true, true],
            vec![true]
        ]
    );
    assert_eq!(res[0].request.resp.status, 201);
    assert_eq!(res[1].step_name.as_deref(), Some("fetch"));
}

/// Legacy files in the repo must keep parsing with the new item loader (running them needs the network).
#[test]
fn legacy_files_parse() {
    let root = env!("CARGO_MANIFEST_DIR");
    for f in [
        "combined_test.tk.yaml",
        "my_tests.tk.yaml",
        "browser_test.tk.yaml",
        "Examples/realworld.tk.yaml",
        "Examples/rick-and-morty.tk.yaml",
    ] {
        let src = std::fs::read_to_string(format!("{root}/{f}")).unwrap();
        let items = testkit::item::parse_yaml(&src).unwrap_or_else(|e| panic!("{f}: {e}"));
        assert!(!items.is_empty(), "{f} has no items");
    }
}
