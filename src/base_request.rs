// src/base_request.rs

use anyhow::Result;
use chrono::{NaiveDate, NaiveDateTime};
use jsonpath_lib::select;
use miette::{Diagnostic, GraphicalReportHandler, GraphicalTheme, NamedSource, SourceSpan};
use regex::Regex;
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::redirect::Policy;
use rhai::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::serde_as;
use std::{
    collections::HashMap,
    env::{self, VarError},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};
use thiserror::Error;

// Import the browser module using a crate‑relative path.
// IMPORTANT: Make sure that your crate root (in src/lib.rs or src/main.rs) declares:
//     pub mod base_browser;
use crate::base_browser;
use crate::base_browser::BrowserTestItem;

// -- Definitions for DSL types --

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BrowserTestConfig {
    pub action: String,
    pub url: Option<String>,
    pub selector: Option<String>,
    pub fields: Option<HashMap<String, String>>,
    pub submit_selector: Option<String>,
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct TestItem {
    pub title: Option<String>,
    pub dump: Option<bool>,
    // Add default so that if no request data is provided, RequestConfig::default() is used.
    #[serde(flatten, default)]
    pub request: RequestConfig,
    pub iterations: Option<Vec<HashMap<String, String>>>,
    #[serde(default)]
    #[serde(with = "serde_yaml::with::singleton_map_recursive")]
    pub asserts: Option<Vec<Assert>>,
    pub exports: Option<HashMap<String, String>>,
    pub browser: Option<BrowserTestConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Assert {
    #[serde(rename = "ok")]
    IsOk(String),
    #[serde(rename = "array")]
    IsArray(String),
    #[serde(rename = "empty")]
    IsEmpty(String),
    #[serde(rename = "string")]
    IsString(String),
    #[serde(rename = "stringAll")]
    IsStringAll(String),
    #[serde(rename = "stringAny")]
    IsStringAny(String),
    #[serde(rename = "number")]
    IsNumber(String),
    #[serde(rename = "numberAll")]
    NumberAll(String),
    #[serde(rename = "numberAny")]
    NumberAny(String),
    #[serde(rename = "boolean")]
    IsBoolean(String),
    #[serde(rename = "null")]
    IsNull(String),
    #[serde(rename = "exists")]
    Exists(String),
    #[serde(rename = "date")]
    IsDate(String),
    #[serde(rename = "notEmpty")]
    NotEmpty(String),
    #[serde(rename = "contains")]
    Contains(String),
    #[serde(rename = "notContains")]
    NotContains(String),
    #[serde(rename = "regexMatch")]
    RegexMatch(String),
    #[serde(rename = "noRegexMatch")]
    NotRegexMatch(String),
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ConfigVariable {
    pub variable_name: String,
    pub variable_value: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct RequestConfig {
    // Added #[serde(default)] here so that if no HTTP method key is provided,
    // the default is used.
    #[serde(default, flatten)]
    pub http_method: HttpMethod,
    pub headers: Option<HashMap<String, String>>,
    pub json: Option<Value>,
    pub params: Option<HashMap<String, String>>,
    pub disabled: Option<bool>,
    #[serde(rename = "httpVersion")]
    pub http_version: Option<String>,
    pub timeout: Option<u64>,
    #[serde(rename = "follow_redirects")]
    pub follow_redirects: Option<bool>,
    #[serde(rename = "ignore_ssl_errors")]
    pub ignore_ssl_errors: Option<bool>,
    pub raw: Option<String>,
    #[serde(rename = "requestBody")]
    pub request_body: Option<HashMap<String, String>>,
    pub pre_request_hook: Option<String>,
    pub post_response_hook: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub curl: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Header {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    GET(String),
    POST(String),
    DELETE(String),
    PUT(String),
    PATCH(String),
    HEAD(String),
    OPTIONS(String),
    CONNECT(String),
    TRACE(String),
}

impl Default for HttpMethod {
    fn default() -> Self {
        // You can customize the default value here.
        HttpMethod::GET("<UNSET>".into())
    }
}

impl HttpMethod {
    pub fn get_url(&self) -> &String {
        match self {
            HttpMethod::GET(u)
            | HttpMethod::POST(u)
            | HttpMethod::PUT(u)
            | HttpMethod::DELETE(u)
            | HttpMethod::PATCH(u)
            | HttpMethod::HEAD(u)
            | HttpMethod::OPTIONS(u)
            | HttpMethod::CONNECT(u)
            | HttpMethod::TRACE(u) => u,
        }
    }
    pub fn get_method(&self) -> reqwest::Method {
        match self {
            HttpMethod::GET(_) => reqwest::Method::GET,
            HttpMethod::POST(_) => reqwest::Method::POST,
            HttpMethod::PUT(_) => reqwest::Method::PUT,
            HttpMethod::DELETE(_) => reqwest::Method::DELETE,
            HttpMethod::PATCH(_) => reqwest::Method::PATCH,
            HttpMethod::HEAD(_) => reqwest::Method::HEAD,
            HttpMethod::OPTIONS(_) => reqwest::Method::OPTIONS,
            HttpMethod::CONNECT(_) => reqwest::Method::CONNECT,
            HttpMethod::TRACE(_) => reqwest::Method::TRACE,
        }
    }
}

#[derive(Debug, Default, Serialize)]
pub struct RequestResult {
    pub step_name: Option<String>,
    pub step_index: u32,
    pub assert_results: Vec<Result<bool, AssertionError>>,
    pub request: RequestAndResponse,
    pub step_log: String,
    pub step_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RequestAndResponse {
    pub req: RequestConfig,
    pub resp: ResponseObject,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResponseObject {
    pub status: u16,
    pub headers: Value,
    pub json: Value,
    pub raw: String,
}

#[derive(Error, Serialize, Clone, Debug, Diagnostic)]
#[error("request assertion failed!")]
#[diagnostic(severity(error))]
pub struct AssertionError {
    #[help]
    pub advice: Option<String>,
    #[source_code]
    #[serde(skip_serializing)]
    pub src: NamedSource<String>,
    #[label("This jsonpath here")]
    #[serde(skip_serializing)]
    pub bad_bit: SourceSpan,
}

fn report_error(diag: &impl Diagnostic) -> String {
    let mut out = String::new();
    GraphicalReportHandler::new_themed(GraphicalTheme::unicode())
        .with_width(80)
        .render_report(&mut out, diag)
        .unwrap();
    out
}

// Suppress dead code warnings if these fields aren’t used elsewhere.
#[allow(dead_code)]
#[derive(Clone, Default)]
pub struct TestContext {
    pub plan: Option<Arc<String>>,
    pub step: Option<Arc<String>>,
    pub step_index: u32,
    pub path: Arc<String>,
    pub file: Arc<String>,
    pub file_source: Arc<String>,
    pub should_log: bool,
}

pub async fn run(ctx: TestContext, exec_string: String) -> Result<Vec<RequestResult>> {
    let test_items: Vec<TestItem> = serde_yaml::from_str(&exec_string)?;
    log::debug!(target: "testkit", "test_items: {:#?}", test_items);
    let result = base_request(ctx.clone(), &test_items, None, None).await;
    result
}

#[allow(dead_code)]
pub async fn run_json(
    ctx: TestContext,
    exec_string: String,
    col_id: Option<PathBuf>,
    local_vars: Option<Vec<ConfigVariable>>,
) -> Result<Vec<RequestResult>> {
    let test_items: Vec<TestItem> = serde_json::from_str(&exec_string)?;
    log::debug!(target: "testkit", "test_items: {:#?}", test_items);
    let result = base_request(
        ctx.clone(),
        &test_items,
        col_id.map(|p| p.to_string_lossy().into()),
        local_vars,
    )
    .await;
    result
}

pub async fn base_request(
    ctx: TestContext,
    test_items: &Vec<TestItem>,
    col_id: Option<String>,
    local_vars: Option<Vec<ConfigVariable>>,
) -> Result<Vec<RequestResult>> {
    let mut results: Vec<RequestResult> = Vec::new();
    let exports_map = Arc::new(Mutex::new(HashMap::<String, Value>::new()));
    if let Some(local_vars) = local_vars {
        for var in local_vars {
            exports_map
                .lock()
                .unwrap()
                .insert(var.variable_name, Value::String(var.variable_value));
        }
    }
    for (i, test_item) in test_items.iter().enumerate() {
        let iterations = test_item.iterations.clone().unwrap_or_else(|| vec![HashMap::new()]);
        for (iter_index, params) in iterations.into_iter().enumerate() {
            let mut iter_ctx = ctx.clone();
            for (k, v) in params.iter() {
                exports_map.lock().unwrap().insert(k.to_string(), Value::String(v.clone()));
            }
            iter_ctx.step = Some(Arc::new(
                test_item
                    .title
                    .clone()
                    .unwrap_or_else(|| format!("Step {} (iter {})", i, iter_index)),
            ));
            iter_ctx.step_index = i as u32;

            if let Some(browser_config) = &test_item.browser {
                let browser_test_item =
                    BrowserTestItem::from_config(test_item.title.clone(), browser_config);
                let mut step_result = RequestResult {
                    step_name: iter_ctx.step.clone().map(|s| s.as_ref().clone()),
                    step_index: iter_ctx.step_index,
                    ..Default::default()
                };
                match base_browser::run_browser_action(browser_test_item).await {
                    Ok(_) => {
                        step_result.step_log = "Browser action executed successfully.".into();
                    }
                    Err(_err) => {
                        step_result.step_log = "Error executing browser action.".into();
                        step_result.step_error = Some("Error executing browser action".into());
                    }
                }
                results.push(step_result);
                continue;
            }

            let mut client = reqwest::Client::builder().connection_verbose(true);
            if let Some(version) = test_item.request.http_version.clone() {
                if version == "http-2" {
                    client = client.http2_prior_knowledge();
                }
            }
            if let Some(timeout) = test_item.request.timeout {
                client = client.timeout(Duration::from_secs(timeout));
            }
            if let Some(follow) = test_item.request.follow_redirects {
                if follow {
                    client = client.redirect(Policy::limited(10));
                } else {
                    client = client.redirect(Policy::none());
                }
            }
            if test_item.request.ignore_ssl_errors.unwrap_or(false) {
                client = client.danger_accept_invalid_certs(true);
            }
            let mut step_result = RequestResult {
                step_name: iter_ctx.step.clone().map(|s| s.as_ref().clone()),
                step_index: iter_ctx.step_index,
                ..Default::default()
            };
            if let Ok(client) = client.build() {
                if test_item.request.disabled.unwrap_or(false) {
                    step_result.step_log = "Step disabled, skipping".to_string();
                    if let Some(asserts) = &test_item.asserts {
                        for _ in asserts {
                            step_result.assert_results.push(Ok(true));
                        }
                    }
                    results.push(step_result);
                    continue;
                }
                if let Some(pre_hook) = &test_item.request.pre_request_hook {
                    let engine = Engine::new();
                    if let Ok(hook_result) = engine.eval_expression::<String>(pre_hook) {
                        log::info!(target: "testkit", "Pre-request hook result: {}", hook_result);
                    }
                }
                let url =
                    format_url(&iter_ctx, &test_item.request.http_method.get_url(), &exports_map);
                let method = test_item.request.http_method.get_method();
                let mut request_builder = client.request(method, url.clone());
                request_builder = request_builder.header("X-Testkit-Run", "true");
                if let Some(v) = test_item.request.params.clone() {
                    let mut params = vec![];
                    for (name, value) in v {
                        params.push((
                            replace_vars(name.as_str(), &exports_map),
                            replace_vars(value.as_str(), &exports_map),
                        ));
                    }
                    request_builder = request_builder.query(&params);
                }
                if let Some(col) = &col_id {
                    request_builder = request_builder.header("X-Testkit-Collection-ID", col);
                }
                if let Some(headers) = &test_item.request.headers {
                    for (name, mut value) in headers.clone() {
                        for env_var in get_env_variable_paths(&value) {
                            if let Ok(val) = get_env_variable(&env_var) {
                                value = value.replace(&env_var, &val);
                            }
                        }
                        for export_var in get_vars(&value) {
                            let key_str = export_var.replace("{{", "").replace("}}", "");
                            if let Some(val) = exports_map.lock().unwrap().get(&key_str) {
                                value = value.replace(&export_var, &val.to_string());
                            }
                        }
                        request_builder = request_builder.header(name, value);
                    }
                }
                if let Some(json) = &test_item.request.json {
                    let js_string = match json {
                        Value::String(s) => s.clone(),
                        _ => json.to_string(),
                    };
                    let j_string = prepare_json_body(
                        js_string,
                        &exports_map,
                        &mut step_result,
                        iter_ctx.should_log,
                    );
                    request_builder = request_builder.header("Content-Type", "application/json");
                    if let Ok(json) = serde_json::from_str::<Value>(&j_string) {
                        request_builder = request_builder.json(&json);
                    }
                } else if let Some(b) = &test_item.request.request_body {
                    let mut body = b.clone();
                    for (key, val) in body.clone().iter() {
                        body.insert(key.clone(), replace_vars(val, &exports_map));
                    }
                    if let Ok(body_str) = serde_json::to_string(&body) {
                        request_builder = request_builder.body(body_str);
                    }
                }
                let mut request_config = test_item.request.clone();
                if let Some(col) = &col_id {
                    let mut headers = request_config.headers.clone().unwrap_or_default();
                    headers.insert("X-Testkit-Collection-ID".into(), col.clone());
                    request_config.headers = Some(headers);
                }

                let method_str = test_item.request.http_method.get_method().to_string();
                let params_vec = if let Some(v) = test_item.request.params.clone() {
                    Some(
                        v.iter()
                            .map(|(k, v)| {
                                (replace_vars(k, &exports_map), replace_vars(v, &exports_map))
                            })
                            .collect(),
                    )
                } else {
                    None
                };

                let mut processed_headers = HashMap::new();
                if let Some(headers) = &test_item.request.headers {
                    for (name, mut value) in headers.clone() {
                        for env_var in get_env_variable_paths(&value) {
                            if let Ok(val) = get_env_variable(&env_var) {
                                value = value.replace(&env_var, &val);
                            }
                        }
                        for export_var in get_vars(&value) {
                            let key_str = export_var.replace("{{", "").replace("}}", "");
                            if let Some(val) = exports_map.lock().unwrap().get(&key_str) {
                                value = value.replace(&export_var, &val.to_string());
                            }
                        }
                        processed_headers.insert(name, value);
                    }
                }

                let json_body_str = if let Some(json) = &test_item.request.json {
                    let js_string = match json {
                        Value::String(s) => s.clone(),
                        _ => json.to_string(),
                    };
                    let j_string =
                        prepare_json_body(js_string.clone(), &exports_map, &mut step_result, false);
                    processed_headers
                        .insert("Content-Type".to_string(), "application/json".to_string());
                    Some(j_string)
                } else {
                    None
                };

                let request_body_str = if let Some(b) = &test_item.request.request_body {
                    let mut body = b.clone();
                    for (key, val) in body.clone().iter() {
                        body.insert(key.clone(), replace_vars(val, &exports_map));
                    }
                    serde_json::to_string(&body).ok()
                } else {
                    None
                };

                let curl_cmd = generate_curl_command(
                    &method_str,
                    &url,
                    &Some(processed_headers),
                    &json_body_str,
                    &request_body_str,
                    &params_vec,
                );

                // Store curl command in request_config
                request_config.curl = Some(curl_cmd);

                let response = request_builder.send().await;
                match response {
                    Err(e) => {
                        let error_message = format!("Error sending request: {}", e);
                        step_result.step_log.push_str(&error_message);
                        step_result.step_log.push('\n');
                        step_result.step_error = Some(error_message);
                        results.push(step_result);
                    }
                    Ok(response) => {
                        let status_code = response.status().as_u16();
                        let header_hashmap = header_map_to_hashmap(response.headers());
                        let raw_body = response.text().await.unwrap_or_else(|_| "{}".into());
                        let json_body = serde_json::from_str(&raw_body)
                            .unwrap_or(Value::Object(serde_json::Map::new()));
                        let assert_object = RequestAndResponse {
                            req: request_config,
                            resp: ResponseObject {
                                status: status_code,
                                headers: serde_json::json!(header_hashmap),
                                json: json_body.clone(),
                                raw: raw_body.clone(),
                            },
                        };
                        if let Some(post_hook) = &test_item.request.post_response_hook {
                            let engine = Engine::new();
                            if let Ok(hook_result) = engine.eval_expression::<String>(post_hook) {
                                log::info!(target: "testkit", "Post-response hook result: {}", hook_result);
                            }
                        }
                        step_result.request = assert_object.clone();
                        let assert_context: Value = serde_json::json!(&assert_object);
                        if test_item.dump.unwrap_or(false) {
                            let dump_message = format!(
                                "💡 DUMP jsonpath request response context:\n {}",
                                colored_json::to_colored_json_auto(&assert_context)
                                    .unwrap_or_else(|_| assert_context.to_string())
                            );
                            step_result.step_log.push_str(&dump_message);
                            step_result.step_log.push('\n');
                            log::info!(target: "testkit", "{}", dump_message);
                            println!("{}", dump_message);
                        }
                        let assert_results = check_assertions(
                            iter_ctx.clone(),
                            &test_item.asserts.clone().unwrap_or_default(),
                            assert_context,
                            &exports_map,
                            &mut step_result.step_log,
                        )
                        .await;
                        if let Some(exports) = &test_item.exports {
                            for (key, value) in exports.iter() {
                                if value.starts_with("$.res.header.") {
                                    let header = value.replace("$.res.header.", "");
                                    if let Some(header_val) = header_hashmap.get(&header) {
                                        exports_map.lock().unwrap().insert(
                                            key.to_string(),
                                            Value::String(header_val.join("")),
                                        );
                                    }
                                    continue;
                                }
                                if value.starts_with("$.res.status.") {
                                    exports_map
                                        .lock()
                                        .unwrap()
                                        .insert(key.to_string(), Value::Number(status_code.into()));
                                    continue;
                                }
                                let json_bod = serde_json::json!(assert_object);
                                if let Ok(v) = select(&json_bod, value) {
                                    if let Some(evaled) = v.first() {
                                        exports_map
                                            .lock()
                                            .unwrap()
                                            .insert(key.to_string(), (*evaled).clone());
                                    }
                                }
                            }
                        }
                        step_result.assert_results = assert_results;
                        results.push(step_result);
                    }
                }
            } else {
                step_result.step_log = "Error building request client".to_string();
                if let Some(asserts) = &test_item.asserts {
                    for _ in asserts {
                        step_result.assert_results.push(Err(AssertionError {
                            advice: Some("request failed to initialize".to_string()),
                            src: NamedSource::new("", "".to_string()),
                            bad_bit: (0, 0).into(),
                        }));
                    }
                }
                results.push(step_result);
            }
        }
    }
    Ok(results)
}

fn header_map_to_hashmap(headers: &HeaderMap<HeaderValue>) -> HashMap<String, Vec<String>> {
    let mut header_hashmap = HashMap::new();
    for (k, v) in headers {
        let k = k.as_str().to_owned();
        let v = String::from_utf8_lossy(v.as_bytes()).into_owned();
        header_hashmap.entry(k).or_insert_with(Vec::new).push(v);
    }
    header_hashmap
}

fn format_url(
    _ctx: &TestContext,
    original_url: &String,
    exports_map: &Arc<Mutex<HashMap<String, Value>>>,
) -> String {
    let mut url = original_url.clone();
    for export in get_vars(original_url) {
        let target_var = export.replace("{{", "").replace("}}", "");
        if let Some(Value::String(s)) = exports_map.lock().unwrap().get(&target_var) {
            url = url.replace(&export, s);
        } else {
            log::error!(target: "testkit", "Export not found: {}", export);
        }
    }
    for env_var in get_env_variable_paths(original_url) {
        if let Ok(val) = get_env_variable(&env_var) {
            url = url.replace(&env_var, &val);
        }
    }
    url
}

fn get_vars(expr: &str) -> Vec<String> {
    let regex_pattern = r#"\{\{([a-zA-Z0-9_]+)\}\}"#;
    let regex = Regex::new(regex_pattern).unwrap();
    regex.find_iter(expr).map(|v| v.as_str().to_string()).collect()
}

fn get_env_variable_paths(val: &String) -> Vec<String> {
    let regex_pattern = r#"\$\.(env\.[A-Za-z_][A-Za-z0-9_]*)"#;
    let regex = Regex::new(regex_pattern).unwrap();
    regex.find_iter(val).map(|v| v.as_str().to_string()).collect()
}

fn replace_vars(expr: &str, exports_map: &Arc<Mutex<HashMap<String, Value>>>) -> String {
    let vars = get_vars(expr);
    let mut result = expr.to_string();
    for var in vars {
        let target_var = var.replace("{{", "").replace("}}", "");
        if let Some(Value::String(s)) = exports_map.lock().unwrap().get(&target_var) {
            result = result.replace(&var, s);
        }
    }
    result
}

fn get_env_variable(env_key_path: &String) -> Result<String, VarError> {
    let key = env_key_path.split('.').last().unwrap_or_default();
    env::var(key)
}

pub fn prepare_json_body(
    json: String,
    exports_map: &Arc<Mutex<HashMap<String, Value>>>,
    _step_result: &mut RequestResult,
    _should_log: bool,
) -> String {
    let mut j_string = json;
    for env_var in get_env_variable_paths(&j_string) {
        if let Ok(val) = get_env_variable(&env_var) {
            j_string = j_string.replace(&env_var, &val);
        }
    }
    for local_var in get_vars(&j_string) {
        let key_str = local_var.replace("{{", "").replace("}}", "");
        if let Some(val) = exports_map.lock().unwrap().get(&key_str) {
            j_string = j_string.replace(&local_var, &val.to_string());
        }
    }
    j_string
}

fn evaluate_expressions<'a, T: Clone + 'static>(
    ctx: TestContext,
    original_expr: &String,
    object: &'a Value,
    outputs: &Arc<Mutex<HashMap<String, Value>>>,
) -> Result<(T, String), AssertionError> {
    let paths = find_all_jsonpaths(original_expr);
    let output_vars = get_vars(original_expr);
    let mut expr = original_expr.clone();
    for var in output_vars.iter() {
        let target_var = var.replace("{{", "").replace("}}", "");
        if let Some(value) = outputs.lock().unwrap().get(&target_var) {
            expr = expr.replace(var.as_str(), &value.to_string());
        } else {
            return Err(AssertionError {
                advice: Some(format!("{}: could not resolve output variable", var)),
                src: NamedSource::new(&*ctx.file, var.clone()),
                bad_bit: (0, var.len()).into(),
            });
        }
    }
    for env_var in get_env_variable_paths(&expr) {
        if let Ok(val) = get_env_variable(&env_var) {
            expr = expr.replace(&env_var, &val);
        }
    }
    for path in paths {
        match select(object, &path) {
            Ok(selected_values) => {
                let replacement = if selected_values.len() == 1 {
                    selected_values[0].to_string()
                } else {
                    serde_json::to_string(&selected_values).unwrap_or("[]".into())
                };
                expr = expr.replace(path, &replacement);
            }
            Err(err) => {
                return Err(AssertionError {
                    advice: Some(format!("Could not evaluate jsonpath: {}, error: {}", path, err)),
                    src: NamedSource::new(&*ctx.file, expr.clone()),
                    bad_bit: (0, 4).into(),
                });
            }
        }
    }
    log::debug!(target: "testkit", "Normalized expression: {:?}", expr);
    let evaluated = parse_expression::<T>(&expr).map_err(|_e| AssertionError {
        advice: Some("Expression could not be evaluated".to_string()),
        src: NamedSource::new(&*ctx.file, expr.clone()),
        bad_bit: (0, 4).into(),
    })?;
    Ok((evaluated, expr.clone()))
}

fn find_all_jsonpaths(input: &String) -> Vec<&str> {
    input.split_whitespace().filter(|x| x.starts_with("$.resp")).collect()
}

fn evaluate_value<'a, T: Clone + 'static>(
    ctx: TestContext,
    expr: &String,
    object: &Value,
    value_type: &str,
) -> Result<(bool, String), AssertionError> {
    let (base_type, _) = if value_type.ends_with("All") || value_type.ends_with("Any") {
        (&value_type[..value_type.len() - 3], ())
    } else {
        (value_type, ())
    };
    let mut path = expr.clone();
    let mut date_format = String::new();
    if base_type == "date" {
        let elements: Vec<&str> = expr.split_whitespace().collect();
        if elements.len() < 2 {
            return Err(AssertionError {
                advice: Some("Date format is required".to_string()),
                src: NamedSource::new(&*ctx.file, expr.to_string()),
                bad_bit: (0, 4).into(),
            });
        }
        path = elements[0].to_string();
        date_format = elements[1..].join(" ");
    }
    let selected_result = match select(object, &path) {
        Ok(v) => v,
        Err(err) => {
            return Err(AssertionError {
                advice: Some(format!("Could not resolve jsonpath: {}, error: {}", expr, err)),
                src: NamedSource::new(&*ctx.file, expr.clone()),
                bad_bit: (0, 4).into(),
            });
        }
    };
    if selected_result.is_empty() {
        return Err(AssertionError {
            advice: Some(format!(
                "No values matched the JSONPath: {} (Add 'dump: true' to see response)",
                path
            )),
            src: NamedSource::new(&*ctx.file, expr.clone()),
            bad_bit: (0, expr.len()).into(),
        });
    }
    let mut overall_pass = true;
    for (idx, val) in selected_result.iter().enumerate() {
        let pass =
            check_value_type(val, base_type, &date_format, expr, &ctx).map_err(|mut e| {
                e.advice = Some(format!("At index {}: {}", idx, e.advice.unwrap_or_default()));
                e
            })?;
        if !pass {
            overall_pass = false;
            break;
        }
    }
    Ok((overall_pass, expr.clone()))
}

fn check_value_type(
    val: &Value,
    base_type: &str,
    date_format: &str,
    expr: &str,
    ctx: &TestContext,
) -> Result<bool, AssertionError> {
    match val {
        Value::Array(array_val) => match base_type {
            "array" => Ok(true),
            "empty" => Ok(array_val.is_empty()),
            "notEmpty" => Ok(!array_val.is_empty()),
            _ => Ok(false),
        },
        Value::String(str_val) => {
            if base_type == "date" {
                if NaiveDateTime::parse_from_str(str_val, date_format).is_ok()
                    || NaiveDate::parse_from_str(str_val, date_format).is_ok()
                {
                    Ok(true)
                } else {
                    Err(AssertionError {
                        advice: Some("Error parsing date".to_string()),
                        src: NamedSource::new(&*ctx.file, expr.to_string()),
                        bad_bit: (0, expr.len()).into(),
                    })
                }
            } else {
                match base_type {
                    "empty" => Ok(str_val.is_empty()),
                    "notEmpty" => Ok(!str_val.is_empty()),
                    "str" => Ok(true),
                    _ => Ok(false),
                }
            }
        }
        Value::Number(_) => {
            if base_type == "num" || base_type == "number" {
                Ok(true)
            } else {
                Ok(false)
            }
        }
        Value::Bool(_) => {
            if base_type == "bool" {
                Ok(true)
            } else {
                Ok(false)
            }
        }
        Value::Null => {
            if base_type == "null" {
                Ok(true)
            } else {
                Ok(false)
            }
        }
        _ => Ok(false),
    }
}

fn evaluate_funcs<T: Clone + 'static>(
    _ctx: TestContext,
    expr: &str,
    json_body: &Value,
    assert_type: &str,
    outputs: &Arc<Mutex<HashMap<String, Value>>>,
) -> Result<(bool, String), AssertionError> {
    let exprs: Vec<&str> = expr.split('~').collect();
    if exprs.len() != 2 {
        return Err(AssertionError {
            advice: Some("Ensure proper format: jsonpath~target_value".to_string()),
            src: NamedSource::new("base_request.rs", expr.to_string()),
            bad_bit: (0, 4).into(),
        });
    }
    let jsonpath = exprs[0];
    let target_value = replace_vars(exprs[1], outputs);
    let selected_result = match select(&json_body, jsonpath) {
        Ok(v) => v,
        Err(_e) => {
            return Ok((
                fallback_path_check(jsonpath, &target_value, assert_type),
                expr.to_string(),
            ))
        }
    };
    if selected_result.is_empty() {
        return Ok((fallback_path_check(jsonpath, &target_value, assert_type), expr.to_string()));
    }
    let overall =
        selected_result.iter().any(|val| funcs_check_one(val, &target_value, assert_type));
    Ok((overall, expr.to_string()))
}

fn funcs_check_one(val: &Value, target_value: &str, assert_type: &str) -> bool {
    match val {
        Value::Array(v) => {
            if assert_type == "contains" {
                v.contains(&Value::String(target_value.to_string()))
            } else if assert_type == "notContains" {
                !v.contains(&Value::String(target_value.to_string()))
            } else {
                false
            }
        }
        Value::String(s) => match assert_type {
            "contains" => s.contains(target_value),
            "notContains" => !s.contains(target_value),
            "regexMatch" => Regex::new(target_value).map_or(false, |re| re.is_match(s)),
            "notRegexMatch" => Regex::new(target_value).map_or(false, |re| !re.is_match(s)),
            _ => false,
        },
        _ => false,
    }
}

fn fallback_path_check(jsonpath: &str, target_value: &str, assert_type: &str) -> bool {
    match assert_type {
        "contains" => jsonpath.contains(target_value),
        "notContains" => !jsonpath.contains(target_value),
        "regexMatch" => Regex::new(target_value).map_or(false, |re| re.is_match(jsonpath)),
        "notRegexMatch" => Regex::new(target_value).map_or(false, |re| !re.is_match(jsonpath)),
        _ => false,
    }
}

fn parse_expression<T: Clone + 'static>(expr: &str) -> Result<T, Box<dyn std::error::Error>> {
    let engine = Engine::new();
    let result = engine.eval_expression::<T>(expr)?;
    Ok(result)
}

async fn check_assertions(
    ctx: TestContext,
    asserts: &[Assert],
    json_body: Value,
    outputs: &Arc<Mutex<HashMap<String, Value>>>,
    step_log: &mut String,
) -> Vec<Result<bool, AssertionError>> {
    let mut assert_results = Vec::new();
    let should_log = ctx.should_log;
    for assertion in asserts {
        let eval_result = match assertion {
            Assert::IsOk(expr) => {
                evaluate_expressions::<bool>(ctx.clone(), expr, &json_body, outputs)
                    .map(|(e, _)| ("OK", e, expr.clone()))
            }
            Assert::IsArray(expr) => evaluate_value::<bool>(ctx.clone(), expr, &json_body, "array")
                .map(|(e, _)| ("ARRAY", e, expr.clone())),
            Assert::IsEmpty(expr) => evaluate_value::<bool>(ctx.clone(), expr, &json_body, "empty")
                .map(|(e, _)| ("EMPTY", e, expr.clone())),
            Assert::IsString(expr) => evaluate_value::<bool>(ctx.clone(), expr, &json_body, "str")
                .map(|(e, _)| ("STRING", e, expr.clone())),
            Assert::IsStringAll(expr) => {
                evaluate_value::<bool>(ctx.clone(), expr, &json_body, "strAll")
                    .map(|(e, _)| ("STRING ALL", e, expr.clone()))
            }
            Assert::IsStringAny(expr) => {
                evaluate_value::<bool>(ctx.clone(), expr, &json_body, "strAny")
                    .map(|(e, _)| ("STRING ANY", e, expr.clone()))
            }
            Assert::IsNumber(expr) => {
                evaluate_value::<bool>(ctx.clone(), expr, &json_body, "number")
                    .map(|(e, _)| ("NUMBER", e, expr.clone()))
            }
            Assert::NumberAll(expr) => {
                evaluate_value::<bool>(ctx.clone(), expr, &json_body, "numberAll")
                    .map(|(e, _)| ("NUMBER ALL", e, expr.clone()))
            }
            Assert::NumberAny(expr) => {
                evaluate_value::<bool>(ctx.clone(), expr, &json_body, "numberAny")
                    .map(|(e, _)| ("NUMBER ANY", e, expr.clone()))
            }
            Assert::IsBoolean(expr) => {
                evaluate_value::<bool>(ctx.clone(), expr, &json_body, "bool")
                    .map(|(e, _)| ("BOOLEAN", e, expr.clone()))
            }
            Assert::IsNull(expr) => evaluate_value::<bool>(ctx.clone(), expr, &json_body, "null")
                .map(|(e, _)| ("NULL", e, expr.clone())),
            Assert::Exists(expr) => evaluate_value::<bool>(ctx.clone(), expr, &json_body, "exists")
                .map(|(e, _)| ("EXISTS", e, expr.clone())),
            Assert::IsDate(expr) => evaluate_value::<bool>(ctx.clone(), expr, &json_body, "date")
                .map(|(e, _)| ("DATE", e, expr.clone())),
            Assert::NotEmpty(expr) => {
                evaluate_value::<bool>(ctx.clone(), expr, &json_body, "notEmpty")
                    .map(|(e, _)| ("NOT EMPTY", e, expr.clone()))
            }
            Assert::Contains(expr) => {
                evaluate_funcs::<bool>(ctx.clone(), expr, &json_body, "contains", outputs)
                    .map(|(e, _)| ("CONTAINS", e, expr.clone()))
            }
            Assert::NotContains(expr) => {
                evaluate_funcs::<bool>(ctx.clone(), expr, &json_body, "notContains", outputs)
                    .map(|(e, _)| ("NOT CONTAINS", e, expr.clone()))
            }
            Assert::RegexMatch(expr) => {
                evaluate_funcs::<bool>(ctx.clone(), expr, &json_body, "regexMatch", outputs)
                    .map(|(e, _)| ("REGEX MATCH", e, expr.clone()))
            }
            Assert::NotRegexMatch(expr) => {
                evaluate_funcs::<bool>(ctx.clone(), expr, &json_body, "notRegexMatch", outputs)
                    .map(|(e, _)| ("NOT REGEX MATCH", e, expr.clone()))
            }
        };
        match eval_result {
            Err(e) => {
                assert_results.push(Err(e.clone()));
                if should_log {
                    log::error!(target: "testkit", "{}", report_error(&e));
                }
            }
            Ok((prefix, result, expr_str)) => {
                assert_results.push(Ok(result));
                if should_log {
                    let log_val = if result {
                        format!("✅ {: <12}  ⮕   {} ", prefix, expr_str)
                    } else {
                        format!("❌ {: <12}  ⮕   {} ", prefix, expr_str)
                    };
                    step_log.push_str(&log_val);
                    step_log.push('\n');
                    if result {
                        log::info!(target: "testkit", "{}", log_val);
                    } else {
                        log::error!(target: "testkit", "{}", log_val);
                    }
                }
            }
        }
    }
    assert_results
}

fn generate_curl_command(
    method: &str,
    url: &str,
    headers: &Option<HashMap<String, String>>,
    json_body: &Option<String>,
    request_body: &Option<String>,
    params: &Option<Vec<(String, String)>>,
) -> String {
    let mut curl_cmd = String::from("curl");

    // Build URL with query params first
    let mut final_url = url.to_string();
    if let Some(params_vec) = params {
        if !params_vec.is_empty() {
            let query_string: Vec<String> =
                params_vec.iter().map(|(k, v)| format!("{}={}", k, v)).collect();
            final_url.push_str(&format!("?{}", query_string.join("&")));
        }
    }

    // Add method if not GET
    if method != "GET" {
        curl_cmd.push_str(&format!(" -X {} '{}'", method, final_url));
    } else {
        curl_cmd.push_str(&format!(" '{}'", final_url));
    }

    if let Some(headers_map) = headers {
        for (key, value) in headers_map {
            let escaped_value = value.replace("'", "'\\''");
            curl_cmd.push_str(&format!(" -H '{}: {}'", key, escaped_value));
        }
    }

    if let Some(json) = json_body {
        let escaped_json = json.replace("'", "'\\''");
        curl_cmd.push_str(&format!(" -d '{}'", escaped_json));
    }

    if let Some(body) = request_body {
        let escaped_body = body.replace("'", "'\\''");
        curl_cmd.push_str(&format!(" -d '{}'", escaped_body));
    }

    curl_cmd
}

#[cfg(test)]
mod tests {
    // Unit tests for this module can be added here.
}
