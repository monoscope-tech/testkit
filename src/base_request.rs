// src/base_request.rs: HTTP types, typed (legacy) assertions and request execution.

use crate::expr::eval::{render, Ctx};
use crate::expr::parse::template;
use anyhow::Result;
use chrono::{NaiveDate, NaiveDateTime};
use jsonpath_lib::select;
use miette::{Diagnostic, GraphicalReportHandler, GraphicalTheme, NamedSource, SourceSpan};
use regex::Regex;
use reqwest::header::{HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::HashMap, path::PathBuf, sync::Arc};
use thiserror::Error;

pub use crate::runner::StepResult as RequestResult;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BrowserTestConfig {}

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
    /// The sent request as a `curl` command (filled in by the runner).
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

pub(crate) fn report_error(diag: &impl Diagnostic) -> String {
    let mut out = String::new();
    GraphicalReportHandler::new_themed(GraphicalTheme::unicode())
        .with_width(80)
        .render_report(&mut out, diag)
        .ok();
    out
}

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
    let mut r = crate::runner::Runner::new(crate::runner::Config {
        should_log: ctx.should_log,
        ..Default::default()
    });
    r.run_src(&ctx.file, &exec_string).await
}

pub async fn run_json(
    ctx: TestContext,
    exec_string: String,
    col_id: Option<PathBuf>,
    local_vars: Option<Vec<ConfigVariable>>,
) -> Result<Vec<RequestResult>> {
    let docs: Value = serde_json::from_str(&exec_string)?;
    let items = crate::item::parse_values(docs, &[])?;
    let mut r = crate::runner::Runner::new(crate::runner::Config {
        should_log: ctx.should_log,
        col_id: col_id.map(|p| p.to_string_lossy().into()),
        ..Default::default()
    });
    for v in local_vars.unwrap_or_default() {
        r.vars.insert(v.variable_name, Value::String(v.variable_value));
    }
    r.file = ctx.file.to_string();
    Ok(r.run_items(&items).await)
}

pub(crate) fn header_map_to_hashmap(
    headers: &HeaderMap<HeaderValue>,
) -> HashMap<String, Vec<String>> {
    let mut header_hashmap = HashMap::new();
    for (k, v) in headers {
        let k = k.as_str().to_owned();
        let v = String::from_utf8_lossy(v.as_bytes()).into_owned();
        header_hashmap.entry(k).or_insert_with(Vec::new).push(v);
    }
    header_hashmap
}

/// A request as a shell `curl` command.
///
/// ```
/// let c = reqwest::Client::new().post("http://x/a?b=1").header("A", "it's").body("{}").build().unwrap();
/// assert_eq!(testkit::base_request::curl(&c), r#"curl -X POST 'http://x/a?b=1' -H 'a: it'\''s' -d '{}'"#);
/// ```
pub fn curl(rq: &reqwest::Request) -> String {
    let q = |s: &str| format!("'{}'", s.replace('\'', "'\\''"));
    let mut c = match rq.method().as_str() {
        "GET" => format!("curl {}", q(rq.url().as_str())),
        m => format!("curl -X {m} {}", q(rq.url().as_str())),
    };
    for (k, v) in rq.headers() {
        c += &format!(" -H {}", q(&format!("{k}: {}", v.to_str().unwrap_or_default())));
    }
    if let Some(b) = rq.body().and_then(|b| b.as_bytes()) {
        c += &format!(" -d {}", q(&String::from_utf8_lossy(b)));
    }
    c
}

/// Typed assertion keys (`array:`, `numberAll:`, `contains:` …). `ok:` is evaluated by the expression engine.
pub fn typed_assert(
    file: &str,
    a: &Assert,
    body: &Value,
    ctx: &Ctx,
) -> Option<Result<(&'static str, bool), AssertionError>> {
    let f = |e: &String, t: &'static str, label: &'static str| {
        Some(evaluate_value(file, e, body, t).map(|(b, _)| (label, b)))
    };
    let g = |e: &String, t: &'static str, label: &'static str| {
        Some(evaluate_funcs(file, e, body, t, ctx).map(|(b, _)| (label, b)))
    };
    match a {
        Assert::IsOk(_) => None,
        Assert::IsArray(e) => f(e, "array", "ARRAY"),
        Assert::IsEmpty(e) => f(e, "empty", "EMPTY"),
        Assert::IsString(e) => f(e, "str", "STRING"),
        Assert::IsStringAll(e) => f(e, "strAll", "STRING ALL"),
        Assert::IsStringAny(e) => f(e, "strAny", "STRING ANY"),
        Assert::IsNumber(e) => f(e, "number", "NUMBER"),
        Assert::NumberAll(e) => f(e, "numberAll", "NUMBER ALL"),
        Assert::NumberAny(e) => f(e, "numberAny", "NUMBER ANY"),
        Assert::IsBoolean(e) => f(e, "bool", "BOOLEAN"),
        Assert::IsNull(e) => f(e, "null", "NULL"),
        Assert::Exists(e) => f(e, "exists", "EXISTS"),
        Assert::IsDate(e) => f(e, "date", "DATE"),
        Assert::NotEmpty(e) => f(e, "notEmpty", "NOT EMPTY"),
        Assert::Contains(e) => g(e, "contains", "CONTAINS"),
        Assert::NotContains(e) => g(e, "notContains", "NOT CONTAINS"),
        Assert::RegexMatch(e) => g(e, "regexMatch", "REGEX MATCH"),
        Assert::NotRegexMatch(e) => g(e, "notRegexMatch", "NOT REGEX MATCH"),
    }
}

fn evaluate_value(
    file: &str,
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
                src: NamedSource::new(file, expr.to_string()),
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
                src: NamedSource::new(file, expr.clone()),
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
            src: NamedSource::new(file, expr.clone()),
            bad_bit: (0, expr.len()).into(),
        });
    }
    let mut overall_pass = true;
    for (idx, val) in selected_result.iter().enumerate() {
        let pass =
            check_value_type(val, base_type, &date_format, expr, file).map_err(|mut e| {
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
    file: &str,
) -> Result<bool, AssertionError> {
    if base_type == "exists" {
        return Ok(true);
    }
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
                        src: NamedSource::new(file, expr.to_string()),
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

fn evaluate_funcs(
    file: &str,
    expr: &str,
    json_body: &Value,
    assert_type: &str,
    ctx: &Ctx,
) -> Result<(bool, String), AssertionError> {
    let exprs: Vec<&str> = expr.split('~').collect();
    if exprs.len() != 2 {
        return Err(AssertionError {
            advice: Some("Ensure proper format: jsonpath~target_value".to_string()),
            src: NamedSource::new(file, expr.to_string()),
            bad_bit: (0, 4).into(),
        });
    }
    let jsonpath = exprs[0].trim();
    let target_value = template(exprs[1].trim())
        .ok()
        .and_then(|t| render(&t, ctx).ok())
        .unwrap_or_else(|| exprs[1].trim().to_string());
    let selected_result = match select(json_body, jsonpath) {
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
            "regexMatch" => Regex::new(target_value).is_ok_and(|re| re.is_match(s)),
            "notRegexMatch" => Regex::new(target_value).is_ok_and(|re| !re.is_match(s)),
            _ => false,
        },
        _ => false,
    }
}

fn fallback_path_check(jsonpath: &str, target_value: &str, assert_type: &str) -> bool {
    match assert_type {
        "contains" => jsonpath.contains(target_value),
        "notContains" => !jsonpath.contains(target_value),
        "regexMatch" => Regex::new(target_value).is_ok_and(|re| re.is_match(jsonpath)),
        "notRegexMatch" => Regex::new(target_value).is_ok_and(|re| !re.is_match(jsonpath)),
        _ => false,
    }
}
