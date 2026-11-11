//! winnow parser combinators for the expression grammar (spec §3.4).
//!
//! ```
//! use testkit::expr::{parse::*, *};
//! assert!(matches!(cond(r#"heading "Dashboard" is visible"#).unwrap(),
//!     Cond::Cmp { op: Op::State(s), .. } if s == "visible"));
//! assert_eq!(locator(r#"button "Edit" in row /Alice/"#).unwrap().to_string(), r#"button "Edit" in row /Alice/"#);
//! assert!(matches!(value("the status of request \"POST /api/orders\"").unwrap(), Expr::Prop(..)));
//! assert!(matches!(cond("no console errors").unwrap(), Cond::No(Expr::Subj(Subject::Console(false, Some(_))))));
//! assert!(cond("a and b or c").is_err()); // no precedence: mixing needs parentheses
//! assert!(cond("(a and b) or c").is_ok());
//! assert!(matches!(cond(r#""Saved""#).unwrap(), Cond::Truthy(Expr::Loc(_)))); // a bare string is visible text
//! assert!(matches!(cond(r#"no "Alice""#).unwrap(), Cond::No(Expr::Loc(_))));
//! assert!(cond("201").is_err() && cond("true").is_err());
//! assert!(matches!(value("2.5s").unwrap(), Expr::Lit(v) if v == 2500.0));
//! assert_eq!(template("http://x/${id}/$${HOME}").unwrap().len(), 3);
//! ```
use super::*;
use winnow::ascii::{digit1, float, multispace0};
use winnow::combinator::{
    alt, cut_err, delimited, eof, not, opt, peek, preceded, repeat, separated, terminated,
};
use winnow::error::{AddContext, ContextError, ErrMode, StrContext, StrContextValue};
use winnow::prelude::*;
use winnow::stream::Stream;
use winnow::token::{any, none_of, one_of, take_till, take_while};

type In<'a> = &'a str;
type R<T> = ModalResult<T>;

#[derive(Debug, Clone)]
pub struct ParseErr {
    pub input: String,
    pub offset: usize,
    pub msg: String,
}

impl std::fmt::Display for ParseErr {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "E_PARSE {} at column {}\n  {}\n  {}^",
            self.msg,
            self.offset + 1,
            self.input,
            " ".repeat(self.offset)
        )
    }
}
impl std::error::Error for ParseErr {}

fn run<'s, T>(
    mut p: impl Parser<In<'s>, T, ErrMode<ContextError>>,
    s: &'s str,
) -> Result<T, ParseErr> {
    let mut full = |i: &mut In<'s>| -> R<T> {
        let v = p.parse_next(i)?;
        multispace0.parse_next(i)?;
        eof.context(StrContext::Expected(StrContextValue::Description("end of expression")))
            .parse_next(i)?;
        Ok(v)
    };
    full.parse(s).map_err(|e| {
        let ctx = e.inner();
        let exp: Vec<String> = ctx
            .context()
            .filter_map(|c| match c {
                StrContext::Expected(v) => Some(v.to_string()),
                StrContext::Label(l) => Some(l.to_string()),
                _ => None,
            })
            .collect();
        let msg = if exp.is_empty() {
            "unexpected input".into()
        } else {
            format!("expected {}", exp.join(" or "))
        };
        ParseErr { input: s.into(), offset: e.offset(), msg }
    })
}

pub fn value(s: &str) -> Result<Expr, ParseErr> {
    run(expr, s)
}
pub fn cond(s: &str) -> Result<Cond, ParseErr> {
    run(condition, s)
}
pub fn locator(s: &str) -> Result<Locator, ParseErr> {
    run(loc, s)
}
pub fn template(s: &str) -> Result<Vec<Seg>, ParseErr> {
    run(raw_template, s)
}
/// Shell text: only `${…}` interpolates (`$${…}` escapes); legacy `{{x}}`/`$.env.X` stay literal.
pub fn shell_template(s: &str) -> Result<Vec<Seg>, ParseErr> {
    let lit = alt((
        "$${".value(Seg::Lit("${".into())),
        (not("${"), any).map(|(_, c): ((), char)| Seg::Lit(c.into())),
    ));
    let ex = delimited("${", cut_err(expr), cut_err(sym("}"))).map(Seg::Expr);
    run(repeat(0.., alt((ex, lit))).map(merge), s)
}

// ---------- lexical ----------
fn ws(i: &mut In) -> R<()> {
    multispace0.void().parse_next(i)
}
fn is_id(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}
fn kw<'a>(w: &'static str) -> impl FnMut(&mut In<'a>) -> R<()> {
    move |i: &mut In<'a>| {
        preceded(ws, terminated(w, not(one_of(is_id))))
            .void()
            .context(StrContext::Expected(StrContextValue::StringLiteral(w)))
            .parse_next(i)
    }
}
fn sym<'a>(w: &'static str) -> impl FnMut(&mut In<'a>) -> R<()> {
    move |i: &mut In<'a>| {
        preceded(ws, w)
            .void()
            .context(StrContext::Expected(StrContextValue::StringLiteral(w)))
            .parse_next(i)
    }
}
const RESERVED: &[&str] = &[
    "the", "of", "is", "not", "and", "or", "no", "some", "in", "with", "has", "where", "mapped",
    "sorted", "joined", "as", "into", "to", "within", "it", "its", "first", "last", "every", "all",
    "closest", "contains", "includes", "matches", "exists", "does", "starts", "ends", "ignoring",
    "true", "false", "null", "exactly", "times", "on",
];
fn word(i: &mut In) -> R<String> {
    preceded(ws, (one_of(|c: char| c.is_alphabetic() || c == '_'), take_while(0.., is_id)).take())
        .map(String::from)
        .parse_next(i)
}
fn ident(i: &mut In) -> R<String> {
    word.verify(|w: &String| !RESERVED.contains(&w.as_str()))
        .context(StrContext::Label("identifier"))
        .parse_next(i)
}
fn esc_char(i: &mut In) -> R<char> {
    preceded(
        '\\',
        any.map(|c| match c {
            'n' => '\n',
            't' => '\t',
            c => c,
        }),
    )
    .parse_next(i)
}
/// `"…"` with `${}` interpolation.
fn string(i: &mut In) -> R<Expr> {
    ws(i)?;
    '"'.parse_next(i)?;
    let segs: Vec<Seg> =
        cut_err(terminated(repeat(0.., alt((tmpl_expr, esc_lit, plain_lit(Some('"'))))), '"'))
            .context(StrContext::Expected(StrContextValue::Description("closing quote")))
            .parse_next(i)?;
    Ok(segs_expr(segs))
}
fn segs_expr(mut segs: Vec<Seg>) -> Expr {
    segs = merge(segs);
    match segs.as_slice() {
        [] => Expr::Lit(Value::String(String::new())),
        [Seg::Lit(s)] => Expr::Lit(Value::String(s.clone())),
        _ => Expr::Tmpl(segs),
    }
}
fn merge(segs: Vec<Seg>) -> Vec<Seg> {
    segs.into_iter().fold(vec![], |mut acc, s| {
        match (acc.last_mut(), s) {
            (Some(Seg::Lit(a)), Seg::Lit(b)) => a.push_str(&b),
            (_, s) => acc.push(s),
        }
        acc
    })
}
fn esc_lit(i: &mut In) -> R<Seg> {
    esc_char.map(|c| Seg::Lit(c.into())).parse_next(i)
}
fn plain_lit<'a>(stop: Option<char>) -> impl FnMut(&mut In<'a>) -> R<Seg> {
    move |i: &mut In<'a>| {
        alt((
            "$${".value(Seg::Lit("${".into())),
            (
                not("${"),
                not("{{"),
                none_of(move |c| Some(c) == stop || (stop.is_some() && c == '\\')),
            )
                .map(|(_, _, c): ((), (), char)| Seg::Lit(c.into())),
        ))
        .parse_next(i)
    }
}
fn tmpl_expr(i: &mut In) -> R<Seg> {
    alt((
        delimited("${", cut_err(expr), cut_err(sym("}"))).map(Seg::Expr),
        delimited("{{", ident, sym("}}")).map(|v| Seg::Expr(Expr::Var(v))),
    ))
    .parse_next(i)
}
/// Bare text with `${}` / `$${}` / legacy `{{x}}` and `$.env.X`.
fn raw_template(i: &mut In) -> R<Vec<Seg>> {
    let legacy_env = preceded("$.env.", take_while(1.., is_id)).map(|k: &str| {
        Seg::Expr(Expr::Prop(Box::new(Expr::Var("env".into())), Prop::Name(k.into())))
    });
    repeat(0.., alt((tmpl_expr, legacy_env, plain_lit(None)))).map(merge).parse_next(i)
}
fn number(i: &mut In) -> R<f64> {
    preceded((ws, peek(one_of(|c: char| c.is_ascii_digit() || c == '-'))), float).parse_next(i)
}
/// Numbers with unit suffixes: durations normalise to ms, sizes to bytes.
fn quantity(i: &mut In) -> R<f64> {
    let n = number(i)?;
    let unit = opt(terminated(alt(("ms", "s", "m", "KB", "MB", "GB", "B")), not(one_of(is_id))))
        .parse_next(i)?;
    Ok(n * match unit {
        Some("s") => 1000.0,
        Some("m") => 60000.0,
        Some("KB") => 1e3,
        Some("MB") => 1e6,
        Some("GB") => 1e9,
        _ => 1.0,
    })
}
pub fn duration(i: &mut In) -> R<f64> {
    let n = number(i)?;
    let unit = alt(("ms", "s", "m"))
        .context(StrContext::Expected(StrContextValue::Description("duration unit (ms, s, m)")))
        .parse_next(i)?;
    Ok(n * match unit {
        "s" => 1000.0,
        "m" => 60000.0,
        _ => 1.0,
    })
}
fn regex(i: &mut In) -> R<(String, String)> {
    let body: Vec<String> = preceded(
        (ws, '/'),
        cut_err(terminated(
            repeat(
                0..,
                alt((
                    "\\/".value("/".to_string()),
                    ('\\', any).take().map(String::from),
                    none_of('/').map(String::from),
                )),
            ),
            '/',
        )),
    )
    .parse_next(i)?;
    let flags = take_while(0.., |c| c == 'i' || c == 'm' || c == 's').parse_next(i)?;
    Ok((body.concat(), flags.into()))
}
fn str_lit(i: &mut In) -> R<String> {
    match string(i)? {
        Expr::Lit(Value::String(s)) => Ok(s),
        _ => Err(ErrMode::Backtrack(ContextError::new())),
    }
}

// ---------- values ----------
pub fn expr(i: &mut In) -> R<Expr> {
    let first = postfixed(i)?;
    let rest: Vec<(char, Expr)> =
        repeat(0.., (preceded(ws, one_of(['+', '-', '*', '/'])), postfixed)).parse_next(i)?;
    if rest.windows(2).any(|w| w[0].0 != w[1].0) {
        return Err(ErrMode::Cut(ContextError::new().add_context(
            i,
            &i.checkpoint(),
            StrContext::Label("parentheses around mixed operators"),
        )));
    }
    Ok(rest.into_iter().fold(first, |a, (op, b)| Expr::Arith(Box::new(a), op, Box::new(b))))
}
fn postfixed(i: &mut In) -> R<Expr> {
    let mut e = unary(i)?;
    loop {
        if let Some(c) = opt(preceded(kw("where"), cut_err(condition))).parse_next(i)? {
            e = Expr::Where(Box::new(e), Box::new(c));
            continue;
        }
        if let Some(v) = opt(preceded((kw("mapped"), kw("to")), cut_err(unary))).parse_next(i)? {
            e = Expr::Map(Box::new(e), Box::new(v));
            continue;
        }
        if let Some((v, d)) =
            opt(preceded((kw("sorted"), kw("by")), (cut_err(unary), opt(kw("descending")))))
                .parse_next(i)?
        {
            e = Expr::Sort(Box::new(e), Box::new(v), d.is_some());
            continue;
        }
        if let Some(s) = opt(preceded((kw("joined"), kw("by")), cut_err(str_lit))).parse_next(i)? {
            e = Expr::Join(Box::new(e), s);
            continue;
        }
        if let Some(c) =
            opt(preceded(kw("as"), cut_err(separated(1.., conv, sym("|"))))).parse_next(i)?
        {
            e = Expr::Conv(Box::new(e), c);
            continue;
        }
        return Ok(e);
    }
}
fn conv(i: &mut In) -> R<String> {
    (word, opt(preceded(':', digit1)))
        .map(|(w, n): (String, Option<&str>)| n.map_or(w.clone(), |n| format!("{w}:{n}")))
        .parse_next(i)
}
/// `the prop of x` or `[the] primary` followed by possessives/indexing/`in session`.
fn unary(i: &mut In) -> R<Expr> {
    alt((
        (opt(kw("the")), prop, kw("of"), cut_err(unary))
            .map(|(_, p, _, v)| Expr::Prop(Box::new(v), p)),
        preceded(opt(kw("the")), access),
    ))
    .parse_next(i)
}
fn access(i: &mut In) -> R<Expr> {
    let mut e = primary(i)?;
    loop {
        if let Some(p) = opt(preceded((ws, "'s"), cut_err(prop))).parse_next(i)? {
            e = Expr::Prop(Box::new(e), p);
            continue;
        }
        if let Some(p) = opt(preceded('.', word)).parse_next(i)? {
            e = Expr::Prop(Box::new(e), Prop::Name(p));
            continue;
        }
        if let Some(x) = opt(delimited('[', cut_err(expr), cut_err(sym("]")))).parse_next(i)? {
            e = Expr::Idx(Box::new(e), Box::new(x));
            continue;
        }
        if !matches!(e, Expr::Loc(_)) {
            if let Some(s) = opt(preceded(kw("in"), ident)).parse_next(i)? {
                e = Expr::In(Box::new(e), s);
                continue;
            }
        }
        return Ok(e);
    }
}
fn prop(i: &mut In) -> R<Prop> {
    preceded(
        ws,
        alt((
            preceded('@', take_while(1.., |c: char| is_id(c) || c == '-'))
                .map(|s: &str| Prop::Attr(s.into())),
            preceded('*', take_while(1.., |c: char| is_id(c) || c == '-'))
                .map(|s: &str| Prop::Style(s.into())),
            str_lit.map(Prop::Name),
            word.verify(|w: &String| !["of", "is", "in"].contains(&w.as_str())).map(Prop::Name),
        )),
    )
    .context(StrContext::Label("property"))
    .parse_next(i)
}
fn primary(i: &mut In) -> R<Expr> {
    preceded(
        ws,
        alt((
            delimited('(', expr, sym(")")),
            string,
            regex.map(|(r, f)| Expr::Re(r, f)),
            quantity.map(|n| Expr::Lit(n.into())),
            delimited('[', separated(0.., expr, sym(",")), sym("]")).map(Expr::List),
            delimited(
                '{',
                separated(
                    0..,
                    (preceded(ws, alt((str_lit, word))), sym(":"), expr).map(|(k, _, v)| (k, v)),
                    sym(","),
                ),
                sym("}"),
            )
            .map(Expr::Obj),
            tmpl_expr.map(|s| match s {
                Seg::Expr(e) => e,
                Seg::Lit(l) => Expr::Lit(l.into()),
            }),
            preceded("$.", take_till(0.., char::is_whitespace))
                .take()
                .map(|s: &str| Expr::Path(s.into())),
            alt((kw("true").value(true), kw("false").value(false))).map(|b| Expr::Lit(b.into())),
            kw("null").value(Expr::Lit(Value::Null)),
            kw("it").value(Expr::It),
            preceded(kw("its"), cut_err(prop)).map(|p| Expr::Prop(Box::new(Expr::It), p)),
            subject.map(Expr::Subj),
            loc.map(Expr::Loc),
            ident.map(Expr::Var),
        )),
    )
    .parse_next(i)
}
fn reqpat(i: &mut In) -> R<(Option<String>, String)> {
    let s = str_lit(i)?;
    Ok(split_method(&s))
}
pub fn split_method(s: &str) -> (Option<String>, String) {
    match s.split_once(' ') {
        Some((m, p)) if m.chars().all(|c| c.is_ascii_uppercase()) => {
            (Some(m.into()), p.trim().into())
        }
        _ => (None, s.trim().into()),
    }
}
fn subject(i: &mut In) -> R<Subject> {
    let pos = alt((
        kw("first").value(Pos::First),
        kw("last").value(Pos::Last),
        kw("every").value(Pos::Every),
        kw("all").value(Pos::All),
    ));
    alt((
        (opt(pos), alt((kw("requests"), kw("request"))), cut_err(reqpat))
            .map(|(p, _, (m, u))| Subject::Request(p.unwrap_or(Pos::Latest), m, u)),
        (
            opt(kw("all")),
            kw("console"),
            opt(alt((
                kw("errors").value("error"),
                kw("warnings").value("warning"),
                kw("messages").value("all"),
            ))),
        )
            .map(|(a, _, l)| Subject::Console(a.is_some(), l.map(String::from))),
        (opt(kw("all")), kw("output")).map(|(a, _)| Subject::Output(a.is_some())),
        preceded(kw("file"), cut_err(primary)).map(|e| Subject::File(Box::new(e))),
        preceded((kw("files"), kw("in")), cut_err(primary)).map(|e| Subject::Files(Box::new(e))),
        preceded(kw("cookie"), cut_err(str_lit)).map(Subject::Cookie),
        (kw("focused"), kw("element")).value(Subject::Focused),
        preceded((kw("long"), kw("tasks")), opt(preceded(kw("over"), duration)))
            .map(Subject::LongTasks),
        (kw("a11y"), kw("violations")).value(Subject::A11y),
        alt((
            kw("page").value(Subject::Page),
            kw("json").value(Subject::Json),
            (kw("status"), not(peek(name))).value(Subject::Status),
            kw("headers").value(Subject::Headers),
            kw("response").value(Subject::Response),
            kw("screen").value(Subject::Screen),
            kw("stdout").value(Subject::Stdout),
            kw("stderr").value(Subject::Stderr),
            kw("exit").value(Subject::Exit),
            kw("cursor").value(Subject::Cursor),
        )),
    ))
    .parse_next(i)
}

// ---------- locators ----------
fn name(i: &mut In) -> R<Name> {
    alt((
        preceded(kw("exactly"), cut_err(str_lit)).map(Name::Exact),
        string.map(|e| match e {
            Expr::Tmpl(segs) => Name::Tmpl(segs),
            e => Name::Sub(crate::expr::eval::to_str(&match e {
                Expr::Lit(v) => v,
                _ => Value::Null,
            })),
        }),
        regex.map(|(r, f)| Name::Re(r, f)),
    ))
    .parse_next(i)
}
fn css(i: &mut In) -> R<String> {
    preceded(
        ws,
        alt((
            delimited('<', take_till(1.., |c| c == '/'), cut_err("/>"))
                .map(|s: &str| s.trim().to_string()),
            (one_of(['#', '.']), take_while(1.., |c: char| is_id(c) || c == '-'))
                .take()
                .map(String::from),
        )),
    )
    .parse_next(i)
}
fn head(i: &mut In) -> R<Head> {
    alt((
        css.map(Head::Css),
        preceded((ws, "@e"), digit1.parse_to()).map(Head::Ref),
        kw("field").value(Head::Field),
        kw("text").value(Head::Text),
        kw("testid").value(Head::Testid),
        preceded(kw("line"), preceded(ws, digit1.parse_to())).map(Head::Line),
        (kw("last"), kw("line")).value(Head::LastLine),
        (kw("closest"), cut_err(loc), cut_err(kw("to")), cut_err(loc))
            .map(|(_, a, _, b)| Head::Closest(Box::new(a), Box::new(b))),
        word.verify(|w: &String| ROLES.contains(&w.as_str())).map(Head::Role),
    ))
    .parse_next(i)
}
pub fn loc(i: &mut In) -> R<Locator> {
    let first = opt(alt((kw("first").value(true), (kw("last"), not(kw("line"))).value(false))))
        .parse_next(i)?;
    let head = head(i)?;
    let nm = if matches!(
        head,
        Head::Css(_) | Head::Ref(_) | Head::Line(_) | Head::LastLine | Head::Closest(..)
    ) {
        None
    } else {
        opt(name).parse_next(i)?
    };
    let filters = repeat(
        0..,
        alt((
            preceded((kw("with"), kw("text")), cut_err(name)).map(Filter::Text),
            preceded(kw("has"), cut_err(loc)).map(|l| Filter::Has(Box::new(l))),
        )),
    )
    .parse_next(i)?;
    let nth =
        opt(delimited((ws, '['), preceded(ws, winnow::ascii::dec_int), sym("]"))).parse_next(i)?;
    let scope = scopes(i)?;
    Ok(Locator { head, name: nm, filters, nth, first, scope })
}
fn scopes(i: &mut In) -> R<Vec<Scope>> {
    repeat(
        0..,
        preceded(
            kw("in"),
            cut_err(alt((
                preceded(kw("frame"), alt((str_lit, css))).map(Scope::Frame),
                loc.map(Scope::Loc),
                ident.map(Scope::Session),
            ))),
        ),
    )
    .parse_next(i)
}
/// Where an action expects a locator, a bare name also works: `"Save" in dialog "X"`, or unquoted
/// text up to `until` (`Save`, `Toggle Todo in listitem "Milk"`, `Search with …`). `head` is `Named` or `Field`.
fn bare_loc<'a>(head: Head, until: &'static str) -> impl FnMut(&mut In<'a>) -> R<Locator> {
    move |i: &mut In<'a>| {
        let unquoted = |i: &mut In<'a>| {
            let s: &str = if until.is_empty() {
                winnow::token::rest.parse_next(i)?
            } else {
                winnow::token::take_until(1.., until).parse_next(i)?
            };
            let s = s.trim();
            // the name ends at the first ` in ` whose remainder is a scope (`Sign in` has none)
            let (n, scope) = s
                .match_indices(" in ")
                .find_map(|(k, _)| Some((&s[..k], run(scopes, &s[k..]).ok()?)))
                .filter(|(_, sc)| sc.iter().all(|x| !matches!(x, Scope::Session(_))))
                .unwrap_or((s, vec![]));
            match template(n) {
                Ok(segs) if !n.is_empty() && !n.starts_with('"') => Ok((
                    match segs_expr(segs) {
                        Expr::Tmpl(t) => Name::Tmpl(t),
                        e => Name::Sub(super::eval::to_str(&match e {
                            Expr::Lit(v) => v,
                            _ => Value::Null,
                        })),
                    },
                    scope,
                )),
                _ => Err(ErrMode::Backtrack(ContextError::new())),
            }
        };
        alt(((name, scopes), unquoted))
            .map(|(n, scope)| Locator {
                head: head.clone(),
                name: Some(n),
                scope,
                ..Default::default()
            })
            .parse_next(i)
    }
}
/// A string literal where a condition expects a subject is the visible text it names.
fn textual(e: Expr) -> Expr {
    match e {
        Expr::Lit(Value::String(s)) => {
            Expr::Loc(Locator { name: Some(Name::Sub(s)), ..Default::default() })
        }
        Expr::Tmpl(t) => Expr::Loc(Locator { name: Some(Name::Tmpl(t)), ..Default::default() }),
        e => e,
    }
}

// ---------- conditions ----------
pub fn condition(i: &mut In) -> R<Cond> {
    let first = cond_unary(i)?;
    let rest: Vec<(bool, Cond)> = repeat(
        0..,
        (
            alt((
                kw("and").value(true),
                sym("&&").value(true),
                kw("or").value(false),
                sym("||").value(false),
            )),
            cut_err(cond_unary),
        ),
    )
    .parse_next(i)?;
    if rest.is_empty() {
        return Ok(first);
    }
    if rest.iter().any(|(a, _)| *a != rest[0].0) {
        return Err(ErrMode::Cut(ContextError::new().add_context(
            i,
            &i.checkpoint(),
            StrContext::Label("parentheses: `and` and `or` cannot be mixed"),
        )));
    }
    let and = rest[0].0;
    let all = std::iter::once(first).chain(rest.into_iter().map(|(_, c)| c)).collect();
    Ok(if and { Cond::All(all) } else { Cond::Any(all) })
}
fn cond_unary(i: &mut In) -> R<Cond> {
    alt((
        preceded(alt((kw("not"), sym("!"))), cond_unary).map(|c| Cond::Not(Box::new(c))),
        preceded(kw("no"), cut_err(expr)).map(|e| Cond::No(textual(e))),
        preceded(kw("some"), cut_err(expr)).map(|e| Cond::Some(textual(e))),
        (expr, comparison).map(|(lhs, (neg, op, rhs, icase))| Cond::Cmp {
            lhs: if matches!(op, Op::State(_)) { textual(lhs) } else { lhs },
            neg,
            op,
            rhs,
            icase,
        }),
        delimited(sym("("), condition, sym(")")),
        cut_err(expr.verify(|e| !matches!(e, Expr::Lit(Value::Number(_) | Value::Bool(_)))))
            .context(StrContext::Label(
                "a comparison (a bare number or boolean always passes; e.g. `status is 201`)",
            ))
            .map(|e| Cond::Truthy(textual(e))),
    ))
    .parse_next(i)
}
type CmpOut = (bool, Op, Option<Expr>, bool);
fn comparison(i: &mut In) -> R<CmpOut> {
    let icase = |i: &mut In| opt((kw("ignoring"), kw("case"))).map(|o| o.is_some()).parse_next(i);
    let sym_op = alt((
        sym("==").value(Op::Eq),
        sym("!=").value(Op::Ne),
        sym("<=").value(Op::Le),
        sym(">=").value(Op::Ge),
        sym("<").value(Op::Lt),
        sym(">").value(Op::Gt),
    ));
    alt((
        (sym_op, cut_err(expr)).map(|(op, v)| (false, op, Some(v), false)),
        preceded(kw("is"), cut_err(is_tail)),
        (
            alt((
                kw("contains").value(Op::Contains),
                kw("includes").value(Op::Contains),
                (kw("starts"), kw("with")).value(Op::Starts),
                (kw("ends"), kw("with")).value(Op::Ends),
                kw("matches").value(Op::Matches),
            )),
            cut_err(matches_rhs),
            icase,
        )
            .map(|(op, v, ic)| (false, op, Some(v), ic)),
        kw("exists").value((false, Op::Exists, None, false)),
        (kw("does"), kw("not"), kw("exist")).value((true, Op::Exists, None, false)),
        preceded(
            (kw("does"), kw("not")),
            cut_err((
                alt((
                    kw("contain").value(Op::Contains),
                    kw("include").value(Op::Contains),
                    kw("match").value(Op::Matches),
                    (kw("start"), kw("with")).value(Op::Starts),
                    (kw("end"), kw("with")).value(Op::Ends),
                )),
                matches_rhs,
                icase,
            )),
        )
        .map(|(op, v, ic)| (true, op, Some(v), ic)),
    ))
    .parse_next(i)
}
fn matches_rhs(i: &mut In) -> R<Expr> {
    alt((loc.map(Expr::Loc), expr)).parse_next(i)
}
fn is_tail(i: &mut In) -> R<CmpOut> {
    let neg = opt(kw("not")).map(|o| o.is_some()).parse_next(i)?;
    let (op, rhs) = alt((
        preceded(alt((kw("an"), kw("a"))), word).map(|t| (Op::IsA(t), None)),
        kw("empty").value((Op::Empty, None)),
        word.verify(|w: &String| STATES.contains(&w.as_str())).map(|s| (Op::State(s), None)),
        (kw("between"), unary, kw("and"), unary)
            .map(|(_, a, _, b)| (Op::Between(Box::new(b)), Some(a))),
        (
            alt((kw("less").value(true), kw("greater").value(false))),
            kw("than"),
            opt((kw("or"), kw("equal"), kw("to"))),
            expr,
        )
            .map(|(lt, _, eq, v)| {
                (
                    match (lt, eq.is_some()) {
                        (true, false) => Op::Lt,
                        (true, true) => Op::Le,
                        (false, false) => Op::Gt,
                        _ => Op::Ge,
                    },
                    Some(v),
                )
            }),
        (kw("within"), number, sym("%"), kw("of"), kw("baseline"), str_lit)
            .map(|(_, p, _, _, _, n)| (Op::Baseline(p, n), None)),
        expr.map(|v| (Op::Eq, Some(v))),
    ))
    .parse_next(i)?;
    let ic = opt((kw("ignoring"), kw("case"))).parse_next(i)?.is_some();
    Ok((neg, op, rhs, ic))
}

// ---------- step arguments ----------
#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum Args {
    None,
    Tmpl(Vec<Seg>),
    Loc(Locator),
    LocVal(Locator, Expr),
    Type(Expr, Option<Locator>),
    Press(Vec<String>, u32, Option<Locator>),
    Drag(Locator, Locator),
    Wait(Vec<Event>),
    Expect(Cond, Option<f64>),
    Extract(Expr, String),
    Route(Option<String>, String),
    Shot(Option<Vec<Seg>>, Option<Locator>),
    Snapshot(Option<Locator>),
    Signal(String, Option<String>),
    Resize(u16, u16),
    Toggle(bool, Option<String>),
    Raw(String),
}

fn event(i: &mut In) -> R<Event> {
    let into = |i: &mut In| opt(preceded(kw("into"), ident)).parse_next(i);
    alt((
        kw("navigation").value(Event::Navigation),
        preceded(kw("popup"), into).map(Event::Popup),
        preceded(kw("download"), into).map(Event::Download),
        kw("dialog").value(Event::Dialog),
        preceded(kw("request"), reqpat).map(|(m, p)| Event::Request(m, p)),
        preceded(kw("response"), reqpat).map(|(m, p)| Event::Response(m, p)),
        (kw("text"), name, opt(preceded(kw("in"), ident))).map(|(_, n, s)| Event::Text(n, s)),
        preceded(kw("console"), name).map(Event::Console),
        duration.map(Event::Dur),
    ))
    .parse_next(i)
}
fn keyseq(i: &mut In) -> R<Vec<String>> {
    let key = preceded(ws, take_while(1.., |c: char| is_id(c) || c == '+'))
        .verify(|k: &str| k != "on")
        .map(String::from);
    repeat(1.., preceded(not((ws, digit1, kw("times"))), key)).parse_next(i)
}

/// Parses the value of a verb key into its typed arguments.
///
/// ```
/// use testkit::expr::{parse::{args, Args}, Expr};
/// assert!(matches!(args("fill", r#"field "Email" with "${user}""#).unwrap(), Args::LocVal(..)));
/// assert!(matches!(args("press", "down 3 times").unwrap(), Args::Press(k, 3, None) if k == ["down"]));
/// assert!(matches!(args("wait", "for text /listening on :(\\d+)/ in server or 60s").unwrap(), Args::Wait(e) if e.len() == 2));
/// assert!(matches!(args("extract", "its match[1] into port").unwrap(), Args::Extract(_, p) if p == "port"));
/// assert!(args("click", "").is_err());
/// assert_eq!(args("click", "Sign in").unwrap(), Args::Loc(testkit::expr::Locator { head: testkit::expr::Head::Named, name: Some(testkit::expr::Name::Sub("Sign in".into())), ..Default::default() }));
/// assert!(matches!(args("click", r#""Pay" in dialog "Checkout""#).unwrap(), Args::Loc(l) if l.to_string() == r#""Pay" in dialog "Checkout""#));
/// assert!(matches!(args("check", r#"Toggle Todo in listitem "Milk""#).unwrap(), Args::Loc(l) if l.to_string() == r#""Toggle Todo" in listitem "Milk""#));
/// assert!(matches!(args("click", "Log in to the app").unwrap(), Args::Loc(l) if l.scope.is_empty()));
/// assert!(matches!(args("click", "Sign in quickly").unwrap(), Args::Loc(l) if l.scope.is_empty()));
/// assert!(matches!(args("fill", r#"Search Wikipedia with "selenium""#).unwrap(), Args::LocVal(l, _) if l.to_string() == r#"field "Search Wikipedia""#));
/// assert!(matches!(args("type", "hello ${name} into field \"Q\"").unwrap(), Args::Type(Expr::Tmpl(_), Some(_))));
/// assert!(matches!(args("enter", "\"1.0.0\"").unwrap(), Args::Type(Expr::Lit(v), None) if v == "1.0.0"));
/// ```
pub fn args(verb: &str, s: &str) -> Result<Args, ParseErr> {
    let s = s.trim();
    match verb {
        "exec" | "spawn" => shell_template(s).map(Args::Tmpl),
        "visit" | "call" | "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS" => {
            template(s).map(Args::Tmpl)
        }
        "click" | "dblclick" | "hover" | "check" | "uncheck" | "tap" | "focus" => {
            run(alt((terminated(loc, (ws, eof)), bare_loc(Head::Named, ""))).map(Args::Loc), s)
        }
        "fill" | "upload" => run(
            (
                alt(((loc, peek(kw("with"))).map(|(l, _)| l), bare_loc(Head::Field, " with "))),
                kw("with"),
                expr,
            )
                .map(|(l, _, v)| Args::LocVal(l, v)),
            s,
        ),
        "type" | "enter" => {
            let (text, target) = match s.rsplit_once(" into ") {
                Some((t, l)) => match locator(l) {
                    Ok(l) => (t, Some(l)),
                    Err(_) => (s, None),
                },
                None => (s, None),
            };
            let text = text
                .strip_prefix('"')
                .and_then(|t| t.strip_suffix('"'))
                .filter(|t| !t.contains('"'))
                .unwrap_or(text);
            Ok(Args::Type(segs_expr(template(text)?), target))
        }
        "press" => run(
            (
                keyseq,
                opt(terminated(preceded(ws, digit1.parse_to()), kw("times"))),
                opt(preceded(kw("on"), loc)),
            )
                .map(|(k, n, l)| Args::Press(k, n.unwrap_or(1), l)),
            s,
        ),
        "drag" => run((loc, kw("to"), loc).map(|(a, _, b)| Args::Drag(a, b)), s),
        "wait" => run(
            alt((
                preceded(kw("for"), separated(1.., event, kw("or"))),
                duration.map(|d| vec![Event::Dur(d)]),
                (condition, opt(preceded(kw("or"), duration))).map(|(c, d)| {
                    std::iter::once(Event::Cond(Box::new(c))).chain(d.map(Event::Dur)).collect()
                }),
            ))
            .map(Args::Wait),
            s,
        ),
        "expect" => run(
            (condition, opt(preceded(kw("within"), duration))).map(|(c, d)| Args::Expect(c, d)),
            s,
        ),
        "extract" => run((expr, kw("into"), ident).map(|(e, _, n)| Args::Extract(e, n)), s),
        "route" | "unroute" => Ok({
            let (m, p) = split_method(s);
            Args::Route(m, p)
        }),
        "shot" => run(
            (
                opt(preceded(ws, take_till(1.., |c: char| c.is_whitespace()))
                    .verify(|w: &str| w != "of")
                    .map(String::from)),
                opt(preceded(kw("of"), loc)),
            )
                .map(|(p, l)| Args::Shot(p.map(|p| template(&p).unwrap_or_default()), l)),
            s,
        ),
        "snapshot" => run(opt(loc).map(Args::Snapshot), s),
        "signal" => run((word, opt(preceded(kw("to"), ident))).map(|(n, t)| Args::Signal(n, t)), s),
        "resize" => run(
            (preceded(ws, digit1.parse_to()), 'x', digit1.parse_to())
                .map(|(w, _, h)| Args::Resize(w, h)),
            s,
        ),
        "trace" | "profile" | "coverage" | "record" => run(
            alt((
                kw("start").value(Args::Toggle(true, None)),
                preceded(kw("stop"), opt(preceded(kw("into"), ident)))
                    .map(|n| Args::Toggle(false, n)),
            )),
            s,
        ),
        "heap" => run(
            preceded((kw("snapshot"), kw("into")), ident).map(|n| Args::Toggle(true, Some(n))),
            s,
        ),
        _ => Ok(if s.is_empty() { Args::None } else { Args::Raw(s.into()) }),
    }
}

/// One aria-snapshot node line: `role "name" [state] [k=v]` (spec §8 `matches:`).
///
/// ```
/// use testkit::expr::parse::aria_line;
/// let (r, n, s) = aria_line(r#"heading "Orders" [level=1]"#).unwrap();
/// assert_eq!((r.as_str(), n.unwrap().to_string(), s), ("heading", "\"Orders\"".to_string(), vec!["level=1".to_string()]));
/// assert_eq!(aria_line("row /Alice/").unwrap().0, "row");
/// assert_eq!(aria_line("text: hello").unwrap().0, "text");
/// ```
pub fn aria_line(s: &str) -> Result<(String, Option<Name>, Vec<String>), ParseErr> {
    let s = s.trim().trim_start_matches("- ").trim_end_matches(':');
    if let Some(t) = s.strip_prefix("text:") {
        return Ok(("text".into(), Some(Name::Sub(t.trim().trim_matches('"').into())), vec![]));
    }
    run(
        (
            word,
            opt(name),
            repeat(
                0..,
                preceded(ws, delimited('[', take_till(1.., ']'), ']'))
                    .map(|x: &str| x.trim().to_string()),
            ),
        ),
        s,
    )
}
