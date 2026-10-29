//! The testkit micro-expression language: hyperscript-flavored values, conditions and locators.
pub mod eval;
pub mod parse;

use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum Expr {
    Lit(Value),
    Re(String, String),
    Var(String),
    It,
    Tmpl(Vec<Seg>),
    Path(String),
    Subj(Subject),
    Loc(Locator),
    In(Box<Expr>, String),
    Prop(Box<Expr>, Prop),
    Idx(Box<Expr>, Box<Expr>),
    Conv(Box<Expr>, Vec<String>),
    Where(Box<Expr>, Box<Cond>),
    Map(Box<Expr>, Box<Expr>),
    Sort(Box<Expr>, Box<Expr>, bool),
    Join(Box<Expr>, String),
    Arith(Box<Expr>, char, Box<Expr>),
    List(Vec<Expr>),
    Obj(Vec<(String, Expr)>),
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum Seg {
    Lit(String),
    Expr(Expr),
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum Prop {
    Name(String),
    Attr(String),
    Style(String),
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum Cond {
    Not(Box<Cond>),
    No(Expr),
    Some(Expr),
    Truthy(Expr),
    Cmp { lhs: Expr, neg: bool, op: Op, rhs: Option<Expr>, icase: bool },
    All(Vec<Cond>),
    Any(Vec<Cond>),
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum Op {
    Eq,
    Ne,
    Lt,
    Gt,
    Le,
    Ge,
    IsA(String),
    Empty,
    State(String),
    Between(Box<Expr>),
    Contains,
    Starts,
    Ends,
    Matches,
    Exists,
    Baseline(f64, String),
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum Pos {
    Latest,
    First,
    Last,
    Every,
    All,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum Subject {
    Page,
    Json,
    Status,
    Headers,
    Response,
    Screen,
    Output(bool),
    Stdout,
    Stderr,
    Exit,
    Cursor,
    Request(Pos, Option<String>, String),
    Console(bool, Option<String>),
    File(Box<Expr>),
    Files(Box<Expr>),
    Cookie(String),
    Focused,
    LongTasks(Option<f64>),
    A11y,
}

#[derive(Debug, Clone, PartialEq, Serialize, Default)]
pub struct Locator {
    pub head: Head,
    pub name: Option<Name>,
    pub filters: Vec<Filter>,
    pub nth: Option<i64>,
    pub first: Option<bool>,
    pub scope: Vec<Scope>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Default)]
pub enum Head {
    Role(String),
    Field,
    #[default]
    Text,
    Testid,
    Css(String),
    Line(i64),
    LastLine,
    Ref(u32),
    Closest(Box<Locator>, Box<Locator>),
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum Name {
    Sub(String),
    Exact(String),
    Re(String, String),
    /// A name with `${…}`, rendered by the runner just before resolution.
    Tmpl(Vec<Seg>),
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum Filter {
    Text(Name),
    Has(Box<Locator>),
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum Scope {
    Loc(Locator),
    Session(String),
    Frame(String),
}

/// Wait events (`wait: for …`).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum Event {
    Navigation,
    Popup(Option<String>),
    Download(Option<String>),
    Dialog,
    Request(Option<String>, String),
    Response(Option<String>, String),
    Text(Name, Option<String>),
    Console(Name),
    Cond(Box<Cond>),
    Dur(f64),
}

pub const STATES: &[&str] = &[
    "visible", "hidden", "checked", "disabled", "enabled", "focused", "expanded", "invalid",
    "editable",
];

pub const ROLES: &[&str] = &[
    "alert",
    "alertdialog",
    "application",
    "article",
    "banner",
    "blockquote",
    "button",
    "caption",
    "cell",
    "checkbox",
    "columnheader",
    "combobox",
    "complementary",
    "contentinfo",
    "definition",
    "dialog",
    "document",
    "feed",
    "figure",
    "form",
    "grid",
    "gridcell",
    "group",
    "heading",
    "img",
    "link",
    "list",
    "listbox",
    "listitem",
    "main",
    "marquee",
    "math",
    "menu",
    "menubar",
    "menuitem",
    "menuitemcheckbox",
    "menuitemradio",
    "meter",
    "navigation",
    "note",
    "option",
    "paragraph",
    "progressbar",
    "radio",
    "radiogroup",
    "region",
    "row",
    "rowgroup",
    "rowheader",
    "scrollbar",
    "search",
    "searchbox",
    "separator",
    "slider",
    "spinbutton",
    "status",
    "log",
    "switch",
    "tab",
    "table",
    "tablist",
    "tabpanel",
    "textbox",
    "timer",
    "toolbar",
    "tooltip",
    "tree",
    "treegrid",
    "treeitem",
];

impl Locator {
    pub fn role(r: &str, name: &str) -> Self {
        Locator {
            head: Head::Role(r.into()),
            name: Some(Name::Sub(name.into())),
            ..Default::default()
        }
    }
}

impl std::fmt::Display for Name {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Name::Sub(s) => write!(f, "{s:?}"),
            Name::Exact(s) => write!(f, "exactly {s:?}"),
            Name::Re(r, fl) => write!(f, "/{r}/{fl}"),
            Name::Tmpl(segs) => write!(
                f,
                "\"{}\"",
                segs.iter()
                    .map(|s| match s {
                        Seg::Lit(l) => l.clone(),
                        Seg::Expr(e) => format!("${{{e:?}}}"),
                    })
                    .collect::<String>()
            ),
        }
    }
}

/// Canonical text form, used by the recorder and error messages.
impl std::fmt::Display for Locator {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if let Some(first) = self.first {
            write!(f, "{} ", if first { "first" } else { "last" })?;
        }
        match &self.head {
            Head::Role(r) => write!(f, "{r}")?,
            Head::Field => write!(f, "field")?,
            Head::Text => write!(f, "text")?,
            Head::Testid => write!(f, "testid")?,
            Head::Css(c) => write!(f, "<{c}/>")?,
            Head::Line(n) => write!(f, "line {n}")?,
            Head::LastLine => write!(f, "last line")?,
            Head::Ref(n) => write!(f, "@e{n}")?,
            Head::Closest(a, b) => write!(f, "closest {a} to {b}")?,
        }
        if let Some(n) = &self.name {
            write!(f, " {n}")?;
        }
        for fl in &self.filters {
            match fl {
                Filter::Text(n) => write!(f, " with text {n}")?,
                Filter::Has(l) => write!(f, " has {l}")?,
            }
        }
        if let Some(n) = self.nth {
            write!(f, "[{n}]")?;
        }
        for s in &self.scope {
            match s {
                Scope::Loc(l) => write!(f, " in {l}")?,
                Scope::Session(s) => write!(f, " in {s}")?,
                Scope::Frame(s) => write!(f, " in frame {s:?}")?,
            }
        }
        Ok(())
    }
}
