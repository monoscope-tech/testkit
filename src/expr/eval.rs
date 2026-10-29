//! Evaluation over `serde_json::Value`. Subjects and locators are resolved up front by the
//! runner (one batch per expression) and looked up here by their canonical key.
//!
//! ```
//! use testkit::expr::{eval::*, parse::cond};
//! use serde_json::json;
//! let vars = json!({"orders": [{"Total": "30"}, {"Total": "12"}], "name": "Alice"});
//! let it = json!({"status": 201, "json": {"id": 1043, "items": ["a", "b"]}, "duration": 120});
//! let ctx = Ctx::new(vars.as_object().unwrap(), &it);
//! let t = |s: &str| test(&cond(s).unwrap(), &ctx).unwrap();
//! assert!(t("its status is 201"));
//! assert!(t("its json's id is 1043 and its duration is less than 300ms"));
//! assert!(t("the length of its json's items is 2"));
//! assert!(t("(orders mapped to (its Total as Int)) contains 30"));
//! assert!(t("the length of (orders where its Total as Int > 20) is 1"));
//! assert!(t("name starts with \"ali\" ignoring case"));
//! assert!(t("name matches /^A/"));
//! assert!(t("no its missing"));
//! assert!(!t("its status is not 201"));
//! assert!(t("its json contains \"a\""));
//! ```
use super::*;
use regex::RegexBuilder;
use serde_json::{json, Map};
use std::collections::HashMap;

pub type Res<T> = Result<T, String>;

pub struct Ctx<'a> {
    pub vars: &'a Map<String, Value>,
    pub it: &'a Value,
    pub legacy: Option<&'a Value>,
    pub resolved: HashMap<String, Value>,
}

impl<'a> Ctx<'a> {
    pub fn new(vars: &'a Map<String, Value>, it: &'a Value) -> Self {
        Ctx { vars, it, legacy: None, resolved: HashMap::new() }
    }
    fn with_it<'b>(&'b self, it: &'b Value) -> Ctx<'b> {
        Ctx { vars: self.vars, it, legacy: self.legacy, resolved: self.resolved.clone() }
    }
}

pub fn key<T: Serialize>(x: &T) -> String {
    serde_json::to_string(x).unwrap_or_default()
}

/// Nodes the runner must resolve before evaluation (subjects, locators, session-scoped values, unknown vars).
pub fn queries_cond(c: &Cond, vars: &Map<String, Value>, out: &mut Vec<Expr>) {
    match c {
        Cond::Not(c) => queries_cond(c, vars, out),
        Cond::No(e) | Cond::Some(e) | Cond::Truthy(e) => queries(e, vars, out),
        Cond::All(cs) | Cond::Any(cs) => cs.iter().for_each(|c| queries_cond(c, vars, out)),
        Cond::Cmp { lhs, op, rhs, .. } => {
            if let (Expr::Loc(a), Op::Matches, Some(Expr::Loc(b))) = (lhs, op, rhs) {
                return out.push(Expr::Loc(scoped(b, a)));
            }
            queries(lhs, vars, out);
            rhs.iter().for_each(|r| queries(r, vars, out));
            if let Op::Between(b) = op {
                queries(b, vars, out)
            }
            if let Op::Baseline(_, n) = op {
                out.push(Expr::Var(format!("baseline:{n}")))
            }
        }
    }
}
pub fn queries(e: &Expr, vars: &Map<String, Value>, out: &mut Vec<Expr>) {
    match e {
        Expr::Subj(_) | Expr::Loc(_) | Expr::In(..) => out.push(e.clone()),
        Expr::Var(v) if v != "env" && !vars.contains_key(v) => out.push(e.clone()),
        Expr::Tmpl(segs) => segs.iter().for_each(|s| {
            if let Seg::Expr(e) = s {
                queries(e, vars, out)
            }
        }),
        Expr::Prop(e, _) | Expr::Conv(e, _) | Expr::Join(e, _) => queries(e, vars, out),
        Expr::Idx(a, b) | Expr::Arith(a, _, b) | Expr::Map(a, b) | Expr::Sort(a, b, _) => {
            queries(a, vars, out);
            queries(b, vars, out)
        }
        Expr::Where(a, c) => {
            queries(a, vars, out);
            queries_cond(c, vars, out)
        }
        Expr::List(xs) => xs.iter().for_each(|x| queries(x, vars, out)),
        Expr::Obj(kv) => kv.iter().for_each(|(_, x)| queries(x, vars, out)),
        _ => {}
    }
}
fn scoped(inner: &Locator, outer: &Locator) -> Locator {
    let mut l = inner.clone();
    l.scope.push(Scope::Loc(outer.clone()));
    l
}

pub fn render(segs: &[Seg], c: &Ctx) -> Res<String> {
    segs.iter()
        .map(|s| match s {
            Seg::Lit(l) => Ok(l.clone()),
            Seg::Expr(e) => match eval(e, c)? {
                Value::Null => Err(format!("`${{{}}}` is null", short_expr(e))),
                v => Ok(to_str(&v)),
            },
        })
        .collect()
}
fn short_expr(e: &Expr) -> String {
    match e {
        Expr::Var(v) => v.clone(),
        Expr::Prop(b, Prop::Name(n)) => format!("{}.{n}", short_expr(b)),
        Expr::It => "it".into(),
        e => format!("{e:?}").chars().take(40).collect(),
    }
}
pub fn to_str(v: &Value) -> String {
    match unwrap1(v) {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        v if is_el(v) => v["text"].as_str().unwrap_or_default().to_string(),
        v => v.to_string(),
    }
}
fn is_el(v: &Value) -> bool {
    v.get("__el").is_some()
}
fn unwrap1(v: &Value) -> &Value {
    match v {
        Value::Array(a) if a.len() == 1 => &a[0],
        v => v,
    }
}
fn scalar(v: &Value) -> Value {
    let v = unwrap1(v);
    if is_el(v) {
        v.get("text").cloned().unwrap_or(Value::Null)
    } else {
        v.clone()
    }
}
pub fn num(v: &Value) -> Option<f64> {
    match scalar(v) {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().trim_end_matches('%').replace(['$', ','], "").parse().ok(),
        Value::Bool(b) => Some(b as u8 as f64),
        _ => None,
    }
}
pub fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64() != Some(0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

pub fn eval(e: &Expr, c: &Ctx) -> Res<Value> {
    Ok(match e {
        Expr::Lit(v) => v.clone(),
        Expr::Re(r, f) => json!({"__re": r, "flags": f}),
        Expr::It => c.it.clone(),
        Expr::Var(v) if v == "env" => {
            Value::Object(std::env::vars().map(|(k, v)| (k, Value::String(v))).collect())
        }
        Expr::Var(v) => match c
            .vars
            .get(v)
            .or_else(|| c.resolved.get(&key(e)))
            .cloned()
            .ok_or_else(|| format!("unknown variable `{v}`"))?
        {
            // config values are lazy templates: `base_url: "http://localhost:${port}"`
            Value::String(s) if s.contains("${") && !s.contains("$${") => {
                match crate::expr::parse::template(&s) {
                    Ok(segs)
                        if !segs.iter().any(|g| matches!(g, Seg::Expr(Expr::Var(x)) if x == v)) =>
                    {
                        Value::String(render(&segs, c)?)
                    }
                    _ => Value::String(s),
                }
            }
            v => v,
        },
        Expr::Tmpl(segs) => Value::String(render(segs, c)?),
        Expr::Path(p) => jsonpath(p, c)?,
        Expr::Subj(_) | Expr::Loc(_) | Expr::In(..) => {
            c.resolved.get(&key(e)).cloned().unwrap_or(Value::Null)
        }
        Expr::Prop(base, p) => {
            if let (Expr::Var(v), Prop::Name(k)) = (&**base, p) {
                if v == "env" {
                    return std::env::var(k)
                        .map(Value::String)
                        .map_err(|_| format!("environment variable `{k}` is not set"));
                }
            }
            prop(&eval(base, c)?, p)
        }
        Expr::Idx(a, i) => index(&eval(a, c)?, &eval(i, c)?),
        Expr::Conv(a, cs) => cs.iter().try_fold(eval(a, c)?, |v, k| conv(v, k))?,
        Expr::Where(a, cnd) => Value::Array(
            items(&eval(a, c)?)
                .into_iter()
                .filter_map(|x| match test(cnd, &c.with_it(&x)) {
                    Ok(true) => Some(Ok(x)),
                    Ok(false) => None,
                    Err(e) => Some(Err(e)),
                })
                .collect::<Res<_>>()?,
        ),
        Expr::Map(a, f) => Value::Array(
            items(&eval(a, c)?).iter().map(|x| eval(f, &c.with_it(x))).collect::<Res<_>>()?,
        ),
        Expr::Sort(a, f, desc) => {
            let mut xs: Vec<(Value, Value)> = items(&eval(a, c)?)
                .into_iter()
                .map(|x| Ok((eval(f, &c.with_it(&x))?, x)))
                .collect::<Res<_>>()?;
            xs.sort_by(|(a, _), (b, _)| cmp(a, b).unwrap_or(std::cmp::Ordering::Equal));
            if *desc {
                xs.reverse()
            }
            Value::Array(xs.into_iter().map(|(_, x)| x).collect())
        }
        Expr::Join(a, sep) => {
            Value::String(items(&eval(a, c)?).iter().map(to_str).collect::<Vec<_>>().join(sep))
        }
        Expr::Arith(a, op, b) => arith(&eval(a, c)?, *op, &eval(b, c)?)?,
        Expr::List(xs) => Value::Array(xs.iter().map(|x| eval(x, c)).collect::<Res<_>>()?),
        Expr::Obj(kv) => {
            Value::Object(kv.iter().map(|(k, v)| Ok((k.clone(), eval(v, c)?))).collect::<Res<_>>()?)
        }
    })
}

fn jsonpath(p: &str, c: &Ctx) -> Res<Value> {
    if let Some(k) = p.strip_prefix("$.env.") {
        return std::env::var(k)
            .map(Value::String)
            .map_err(|_| format!("environment variable `{k}` is not set"));
    }
    let root = c.legacy.unwrap_or(c.it);
    let found = jsonpath_lib::select(root, p).map_err(|e| format!("invalid jsonpath {p}: {e}"))?;
    Ok(match found.as_slice() {
        [] => Value::Null,
        [one] => (*one).clone(),
        many => Value::Array(many.iter().map(|v| (*v).clone()).collect()),
    })
}

fn items(v: &Value) -> Vec<Value> {
    match v {
        Value::Array(a) => a.clone(),
        Value::Null => vec![],
        v => vec![v.clone()],
    }
}

pub fn prop(v: &Value, p: &Prop) -> Value {
    let get = |o: &Map<String, Value>, k: &str| {
        o.get(k)
            .cloned()
            .or_else(|| o.iter().find(|(kk, _)| kk.eq_ignore_ascii_case(k)).map(|(_, v)| v.clone()))
    };
    match (v, p) {
        (Value::Array(a), Prop::Name(n)) if ["length", "count", "size"].contains(&n.as_str()) => {
            a.len().into()
        }
        (Value::Array(a), p) => match a.as_slice() {
            [one] if is_el(one) => prop(one, p),
            _ => Value::Array(a.iter().map(|x| prop(x, p)).collect()),
        },
        (Value::Object(o), Prop::Attr(a)) => {
            o.get("attrs").and_then(|x| x.get(a)).cloned().unwrap_or(Value::Null)
        }
        (Value::Object(o), Prop::Style(s)) => {
            o.get("styles").and_then(|x| x.get(s)).cloned().unwrap_or(Value::Null)
        }
        (Value::Object(o), Prop::Name(n)) => {
            get(o, n).unwrap_or_else(|| if n == "length" { o.len().into() } else { Value::Null })
        }
        (Value::String(s), Prop::Name(n)) => match n.as_str() {
            "length" => s.chars().count().into(),
            "json" => serde_json::from_str(s).unwrap_or(Value::Null),
            "lines" => Value::Array(s.lines().map(|l| l.into()).collect()),
            "text" => v.clone(),
            _ => Value::Null,
        },
        _ => Value::Null,
    }
}
fn index(v: &Value, i: &Value) -> Value {
    match (v, i) {
        (Value::Array(a), i) => num(i)
            .map(|n| n as i64)
            .and_then(|n| {
                a.get(if n < 0 { (a.len() as i64 + n) as usize } else { n as usize }).cloned()
            })
            .unwrap_or(Value::Null),
        (Value::Object(_), Value::String(k)) => prop(v, &Prop::Name(k.clone())),
        _ => Value::Null,
    }
}
fn conv(v: Value, k: &str) -> Res<Value> {
    let (k, arg) = k.split_once(':').unwrap_or((k, ""));
    Ok(match k.to_lowercase().as_str() {
        "int" => num(&v).map(|n| (n.trunc() as i64).into()).unwrap_or(Value::Null),
        "number" | "float" => num(&v).map(Value::from).unwrap_or(Value::Null),
        "string" => to_str(&v).into(),
        "json" => match &v {
            Value::String(s) => serde_json::from_str(s).map_err(|e| e.to_string())?,
            v => v.to_string().into(),
        },
        "fixed" => num(&v)
            .map(|n| format!("{:.*}", arg.parse().unwrap_or(2), n).into())
            .unwrap_or(Value::Null),
        "lower" => to_str(&v).to_lowercase().into(),
        "upper" => to_str(&v).to_uppercase().into(),
        "boolean" | "bool" => truthy(&v).into(),
        "array" => Value::Array(items(&v)),
        "keys" => v
            .as_object()
            .map(|o| o.keys().map(|k| Value::from(k.clone())).collect())
            .unwrap_or(Value::Array(vec![])),
        "values" => {
            v.as_object().map(|o| o.values().cloned().collect()).unwrap_or(Value::Array(vec![]))
        }
        "unique" => {
            let mut out: Vec<Value> = vec![];
            items(&v).into_iter().for_each(|x| {
                if !out.contains(&x) {
                    out.push(x)
                }
            });
            Value::Array(out)
        }
        "reversed" => Value::Array(items(&v).into_iter().rev().collect()),
        "date" => v,
        other => return Err(format!("unknown conversion `{other}`")),
    })
}
fn arith(a: &Value, op: char, b: &Value) -> Res<Value> {
    if op == '+'
        && (scalar(a).is_string() || scalar(b).is_string())
        && (num(a).is_none() || num(b).is_none())
    {
        return Ok(format!("{}{}", to_str(a), to_str(b)).into());
    }
    let (x, y) =
        (num(a).ok_or("left side is not a number")?, num(b).ok_or("right side is not a number")?);
    Ok(match op {
        '+' => x + y,
        '-' => x - y,
        '*' => x * y,
        _ => x / y,
    }
    .into())
}
fn cmp(a: &Value, b: &Value) -> Option<std::cmp::Ordering> {
    match (num(a), num(b)) {
        (Some(x), Some(y)) => x.partial_cmp(&y),
        _ => Some(to_str(a).cmp(&to_str(b))),
    }
}
fn eq(a: &Value, b: &Value, icase: bool) -> bool {
    let (a, b) = (scalar(a), scalar(b));
    match (&a, &b) {
        (Value::String(x), Value::String(y)) => {
            if icase {
                x.to_lowercase() == y.to_lowercase()
            } else {
                x == y
            }
        }
        (Value::Number(_), Value::String(_)) | (Value::String(_), Value::Number(_)) => {
            num(&a).zip(num(&b)).is_some_and(|(x, y)| x == y)
        }
        (Value::Number(x), Value::Number(y)) => x.as_f64() == y.as_f64(),
        _ => a == b,
    }
}
fn contains(hay: &Value, needle: &Value, icase: bool) -> bool {
    let low = |s: &str| if icase { s.to_lowercase() } else { s.to_string() };
    match (unwrap1(hay), needle) {
        (h, n) if is_el(h) => contains(&scalar(h), n, icase),
        (Value::String(h), n) => low(h).contains(&low(&to_str(n))),
        (Value::Array(a), n) => a.iter().any(|x| eq(x, n, icase) || contains(x, n, icase)),
        (Value::Object(o), n) => {
            o.iter().any(|(k, v)| eq(&Value::String(k.clone()), n, icase) || contains(v, n, icase))
        }
        (h, n) => eq(h, n, icase),
    }
}
pub fn re_match(v: &Value, pat: &Value, icase: bool) -> Res<bool> {
    let (src, flags) = match pat {
        Value::Object(o) if o.contains_key("__re") => (
            o["__re"].as_str().unwrap_or_default().to_string(),
            o["flags"].as_str().unwrap_or_default().to_string(),
        ),
        p => (regex::escape(&to_str(p)), String::new()),
    };
    let re = RegexBuilder::new(&src)
        .case_insensitive(icase || flags.contains('i'))
        .multi_line(flags.contains('m'))
        .dot_matches_new_line(flags.contains('s'))
        .build()
        .map_err(|e| e.to_string())?;
    Ok(match unwrap1(v) {
        Value::Array(a) => a.iter().any(|x| re.is_match(&to_str(x))),
        v => re.is_match(&to_str(v)),
    })
}
fn is_a(v: &Value, t: &str) -> bool {
    let v = unwrap1(v);
    match t.to_lowercase().as_str() {
        "number" => v.is_number() || (v.is_string() && num(v).is_some()),
        "int" | "integer" => v.is_i64() || v.is_u64(),
        "string" => v.is_string(),
        "array" | "list" => v.is_array(),
        "object" | "map" => v.is_object() && !is_el(v),
        "boolean" | "bool" => v.is_boolean(),
        "null" => v.is_null(),
        "element" => is_el(v),
        "date" => v.as_str().is_some_and(|s| {
            chrono::DateTime::parse_from_rfc3339(s).is_ok()
                || chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").is_ok()
        }),
        _ => false,
    }
}
fn state(v: &Value, s: &str) -> bool {
    let els = items(v);
    let any = |k: &str| els.iter().any(|e| e.get(k).and_then(Value::as_bool).unwrap_or(false));
    match s {
        "visible" => any("visible"),
        "hidden" => !any("visible"),
        "enabled" => !els.is_empty() && !any("disabled"),
        s => any(s),
    }
}

/// Evaluates a condition. Ordering comparisons over lists hold only if every item satisfies them.
pub fn test(cnd: &Cond, c: &Ctx) -> Res<bool> {
    Ok(match cnd {
        Cond::Not(x) => !test(x, c)?,
        Cond::No(e) => !truthy(&eval(e, c)?),
        Cond::Some(e) | Cond::Truthy(e) => truthy(&eval(e, c)?),
        Cond::All(cs) => {
            for x in cs {
                if !test(x, c)? {
                    return Ok(false);
                }
            }
            true
        }
        Cond::Any(cs) => {
            for x in cs {
                if test(x, c)? {
                    return Ok(true);
                }
            }
            false
        }
        Cond::Cmp { lhs, neg, op, rhs, icase } => {
            if let (Expr::Loc(a), Op::Matches, Some(Expr::Loc(b))) = (lhs, op, rhs) {
                return Ok(neg ^ truthy(&eval(&Expr::Loc(scoped(b, a)), c)?));
            }
            let l = eval(lhs, c)?;
            let r = rhs.as_ref().map(|r| eval(r, c)).transpose()?.unwrap_or(Value::Null);
            let ord = |f: &dyn Fn(std::cmp::Ordering) -> bool| -> bool {
                match &l {
                    Value::Array(a) if a.len() > 1 => a.iter().all(|x| cmp(x, &r).is_some_and(f)),
                    x => cmp(x, &r).is_some_and(f),
                }
            };
            let res = match op {
                Op::Eq => eq(&l, &r, *icase),
                Op::Ne => !eq(&l, &r, *icase),
                Op::Lt => ord(&|o| o.is_lt()),
                Op::Gt => ord(&|o| o.is_gt()),
                Op::Le => ord(&|o| o.is_le()),
                Op::Ge => ord(&|o| o.is_ge()),
                Op::Between(hi) => {
                    let hi = eval(hi, c)?;
                    ord(&|o| o.is_ge())
                        && match &l {
                            Value::Array(a) if a.len() > 1 => {
                                a.iter().all(|x| cmp(x, &hi).is_some_and(|o| o.is_le()))
                            }
                            x => cmp(x, &hi).is_some_and(|o| o.is_le()),
                        }
                }
                Op::IsA(t) => is_a(&l, t),
                Op::Empty => {
                    !truthy(unwrap1(&l))
                        && !matches!(unwrap1(&l), Value::Bool(_) | Value::Number(_))
                }
                Op::State(s) => state(&l, s),
                Op::Contains => contains(&l, &r, *icase),
                Op::Starts => {
                    to_str(&l).to_lowercase().starts_with(&to_str(&r).to_lowercase())
                        && (*icase || to_str(&l).starts_with(&to_str(&r)))
                }
                Op::Ends => {
                    to_str(&l).to_lowercase().ends_with(&to_str(&r).to_lowercase())
                        && (*icase || to_str(&l).ends_with(&to_str(&r)))
                }
                Op::Matches => re_match(&l, &r, *icase)?,
                Op::Exists => !l.is_null() && l != Value::Array(vec![]),
                Op::Baseline(pct, n) => {
                    let base = c.resolved.get(&key(&Expr::Var(format!("baseline:{n}")))).and_then(num)
                        .ok_or_else(|| format!("no baseline named \"{n}\"; record one with `testkit baseline update`"))?;
                    num(&l).is_some_and(|v| v <= base * (1.0 + pct / 100.0))
                }
            };
            neg ^ res
        }
    })
}
