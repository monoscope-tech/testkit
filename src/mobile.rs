//! Android surface over adb (spec §5.4): uiautomator dumps become ARIA-like elements, so
//! `tap: button "Sign in"` and `expect: text "Welcome" is visible` read the same as on the web.
use crate::expr::{Filter, Head, Locator, Name, Scope, INTERACTIVE};
use crate::runner::name_match;
use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};
use std::process::Command;
use winnow::ascii::multispace0;
use winnow::combinator::{alt, delimited, opt, preceded, repeat};
use winnow::prelude::*;
use winnow::token::{take_till, take_until, take_while};

#[derive(Debug, Default, Clone)]
pub struct Node {
    pub attrs: Vec<(String, String)>,
    pub kids: Vec<Node>,
}
impl Node {
    fn get(&self, k: &str) -> &str {
        self.attrs.iter().find(|(a, _)| a == k).map_or("", |(_, v)| v)
    }
}

fn ident<'a>(i: &mut &'a str) -> ModalResult<&'a str> {
    take_while(1.., |c: char| c.is_alphanumeric() || "-_:.".contains(c)).parse_next(i)
}
fn attr(i: &mut &str) -> ModalResult<(String, String)> {
    (multispace0, ident, '=', delimited('"', take_till(0.., '"'), '"'))
        .map(|(_, k, _, v): (_, &str, _, &str)| (k.to_string(), unescape(v)))
        .parse_next(i)
}
fn element(i: &mut &str) -> ModalResult<Node> {
    let (_, _, attrs): (_, _, Vec<_>) = ('<', ident, repeat(0.., attr)).parse_next(i)?;
    let closed = preceded(multispace0, alt(("/>".value(true), ">".value(false)))).parse_next(i)?;
    if closed {
        return Ok(Node { attrs, kids: vec![] });
    }
    let kids = repeat(0.., preceded(multispace0, element)).parse_next(i)?;
    (multispace0, "</", ident, '>').parse_next(i)?;
    Ok(Node { attrs, kids })
}
fn unescape(s: &str) -> String {
    [
        ("&#10;", "\n"),
        ("&lt;", "<"),
        ("&gt;", ">"),
        ("&quot;", "\""),
        ("&apos;", "'"),
        ("&amp;", "&"),
    ]
    .iter()
    .fold(s.to_string(), |s, (a, b)| s.replace(a, b))
}

/// Parses a `uiautomator dump` into its node tree (the trailing "dumped to" line is ignored).
///
/// ```
/// let x = r#"<?xml version='1.0' ?><hierarchy rotation="0"><node class="android.widget.Button" text="Sign &amp; go" bounds="[0,0][10,10]"/></hierarchy>
/// UI hierchary dumped to: /dev/tty"#;
/// let root = testkit::mobile::parse_dump(x).unwrap();
/// assert_eq!(root.kids[0].attrs[1].1, "Sign & go");
/// ```
pub fn parse_dump(xml: &str) -> Result<Node> {
    let end = xml.rfind('>').map_or(0, |i| i + 1);
    (opt(("<?", take_until(0.., "?>"), "?>")), multispace0, element, multispace0)
        .map(|(_, _, e, _)| e)
        .parse(&xml[..end])
        .map_err(|e| anyhow!("cannot read the uiautomator dump: {e}"))
}

fn role(n: &Node) -> &'static str {
    let c = n.get("class").rsplit('.').next().unwrap_or("");
    let flag = |k| n.get(k) == "true";
    match c {
        _ if c.ends_with("EditText") || c == "AutoCompleteTextView" => "textbox",
        _ if c.contains("Switch") || c == "ToggleButton" => "switch",
        "CheckBox" | "CheckedTextView" => "checkbox",
        "RadioButton" => "radio",
        _ if c.ends_with("Button") => "button",
        "SeekBar" => "slider",
        "Spinner" => "combobox",
        "ProgressBar" => "progressbar",
        "RecyclerView" | "ListView" | "GridView" => "list",
        "WebView" => "document",
        _ if flag("checkable") => "checkbox",
        _ if flag("clickable") => "button",
        "ImageView" => "img",
        "TextView" => "text",
        _ => "generic",
    }
}
fn texts(n: &Node, out: &mut Vec<String>) {
    for k in ["text", "content-desc"] {
        if !n.get(k).is_empty() {
            out.push(n.get(k).to_string())
        }
    }
    n.kids.iter().for_each(|k| texts(k, out))
}
fn bounds(s: &str) -> [i64; 4] {
    let n: Vec<i64> =
        s.split(|c: char| !c.is_ascii_digit() && c != '-').filter_map(|x| x.parse().ok()).collect();
    [0, 1, 2, 3].map(|i| n.get(i).copied().unwrap_or(0))
}

/// Flattens the tree into element JSON in document order: `{role, name, text, value, states, attrs, box, depth}`.
///
/// ```
/// use testkit::{expr::parse::locator, mobile};
/// let x = r#"<hierarchy><node class="android.widget.LinearLayout" clickable="true" bounds="[0,0][100,50]">
///   <node class="android.widget.TextView" text="Airplane mode" bounds="[0,0][80,50]"/>
///   <node class="android.widget.Switch" checkable="true" checked="true" enabled="true" bounds="[80,0][100,50]"/>
/// </node></hierarchy>"#;
/// let els = mobile::elements(&mobile::parse_dump(x).unwrap());
/// let sw = mobile::find(&els, &locator(r#"switch "airplane""#).unwrap()).unwrap();
/// assert_eq!(sw[0]["checked"], true);
/// assert_eq!(mobile::snapshot(&els, 10), "- button \"Airplane mode\" [disabled]\n- switch \"Airplane mode\" [checked]");
/// ```
pub fn elements(root: &Node) -> Vec<Value> {
    // `row` names nameless controls after the clickable row around them (a Settings switch)
    fn walk(n: &Node, depth: usize, row: &str, out: &mut Vec<Value>) {
        let r = role(n);
        let own = [n.get("text"), n.get("content-desc")]
            .into_iter()
            .find(|s| !s.is_empty())
            .unwrap_or("");
        let mut all = vec![];
        texts(n, &mut all);
        let name = match r {
            "textbox" => [n.get("hint"), n.get("content-desc")]
                .into_iter()
                .find(|s| !s.is_empty())
                .unwrap_or(""),
            "button" | "checkbox" | "switch" | "radio" if own.is_empty() && !all.is_empty() => {
                &all.join(" ")
            }
            "checkbox" | "switch" | "radio" if own.is_empty() => row,
            _ => own,
        };
        let row = if n.get("clickable") == "true" && !all.is_empty() {
            all.join(" ")
        } else {
            row.to_string()
        };
        let [x1, y1, x2, y2] = bounds(n.get("bounds"));
        if !n.get("class").is_empty() {
            out.push(json!({
                "role": r, "name": name, "text": if r == "textbox" { own.to_string() } else { all.join(" ") },
                "value": if r == "textbox" && n.get("password") != "true" { n.get("text") } else { "" },
                "visible": x2 > x1 && y2 > y1, "enabled": n.get("enabled") == "true", "disabled": n.get("enabled") != "true",
                "checked": n.get("checked") == "true", "focused": n.get("focused") == "true",
                "selected": n.get("selected") == "true", "editable": r == "textbox",
                "attrs": {"id": n.get("resource-id"), "class": n.get("class"), "package": n.get("package"), "type": if n.get("password") == "true" { "password" } else { "" }},
                "box": {"x": x1, "y": y1, "width": x2 - x1, "height": y2 - y1}, "depth": depth,
            }));
        }
        n.kids.iter().for_each(|k| walk(k, depth + 1, &row, out))
    }
    let mut out = vec![];
    walk(root, 0, "", &mut out);
    out
}

fn inside(a: &Value, b: &Value) -> bool {
    let g = |v: &Value, k: &str| v["box"][k].as_i64().unwrap_or(0);
    g(a, "x") >= g(b, "x")
        && g(a, "y") >= g(b, "y")
        && g(a, "x") + g(a, "width") <= g(b, "x") + g(b, "width")
        && g(a, "y") + g(a, "height") <= g(b, "y") + g(b, "height")
}

/// Resolves a locator against flattened elements (scopes and `has` use on-screen containment).
pub fn find(els: &[Value], l: &Locator) -> Result<Vec<Value>> {
    let s = |v: &Value, k: &str| v[k].as_str().unwrap_or("").to_string();
    let named =
        |e: &Value, n: &Option<Name>, k: &str| n.as_ref().is_none_or(|n| name_match(n, &s(e, k)));
    let mut hits: Vec<Value> = match &l.head {
        Head::Role(r) => els.iter().filter(|e| s(e, "role") == *r && named(e, &l.name, "name")).cloned().collect(),
        Head::Named => els.iter().filter(|e| INTERACTIVE.contains(&s(e, "role").as_str()) && named(e, &l.name, "name")).cloned().collect(),
        Head::Text => {
            let m: Vec<&Value> = els.iter().filter(|e| named(e, &l.name, "text") && e["visible"] == true).collect();
            // the smallest: drop matches that contain another match
            m.iter().filter(|e| !m.iter().any(|o| !std::ptr::eq(*o, **e) && inside(o, e))).map(|e| (*e).clone()).collect()
        }
        Head::Testid => els
            .iter()
            .filter(|e| {
                let id = e["attrs"]["id"].as_str().unwrap_or("");
                l.name.as_ref().is_some_and(|n| match n {
                    Name::Sub(x) | Name::Exact(x) => id == x || id.ends_with(&format!(":id/{x}")),
                    n => name_match(n, id),
                })
            })
            .cloned()
            .collect(),
        Head::Field => {
            let mut out = vec![];
            for (i, e) in els.iter().enumerate().filter(|(_, e)| e["role"] == "textbox") {
                let label = els[..i].iter().rev().find(|p| p["role"] == "text").map(|p| s(p, "name"));
                // without a hint attribute an empty field reports its placeholder as text
                let own = if s(e, "name").is_empty() { "value" } else { "name" };
                let id = e["attrs"]["id"].as_str().unwrap_or("").rsplit('/').next().unwrap_or("").replace('_', " ");
                if named(e, &l.name, own) && (l.name.is_none() || !s(e, own).is_empty())
                    || l.name.as_ref().is_some_and(|n| !id.is_empty() && name_match(n, &id))
                    || label.is_some_and(|t| l.name.as_ref().is_some_and(|n| name_match(n, &t)))
                {
                    out.push(e.clone())
                }
            }
            out
        }
        _ => bail!("`{l}` isn't supported on Android; use a role, `text`, `field` or `testid` (resource-id)"),
    };
    for f in &l.filters {
        match f {
            Filter::Text(n) => hits.retain(|e| name_match(n, &s(e, "text"))),
            Filter::Has(inner) => {
                let ins = find(els, inner)?;
                hits.retain(|e| ins.iter().any(|i| inside(i, e)))
            }
        }
    }
    for sc in &l.scope {
        if let Scope::Loc(outer) = sc {
            let outs = find(els, outer)?;
            hits.retain(|e| outs.iter().any(|o| o != e && inside(e, o)))
        }
    }
    if let Some(n) = l.nth {
        let i = if n < 0 { hits.len() as i64 + n } else { n - 1 };
        hits = hits.get(i.max(0) as usize).cloned().into_iter().collect();
    }
    if l.first.is_some() {
        let f = if l.first == Some(true) { hits.first() } else { hits.last() };
        hits = f.cloned().into_iter().collect();
    }
    Ok(hits)
}

/// Aria-snapshot-style lines: `- button "Wi-Fi" [checked]`, nameless containers folded away.
pub fn snapshot(els: &[Value], max: usize) -> String {
    let mut lines = vec![];
    let mut named: Vec<&Value> = vec![];
    for e in els {
        let (r, n) = (e["role"].as_str().unwrap_or(""), e["name"].as_str().unwrap_or(""));
        if r == "generic" || n.is_empty() && !["textbox", "list", "switch", "checkbox"].contains(&r)
        {
            continue;
        }
        // text already carried by the name of the control around it
        if r == "text"
            && named.iter().any(|c| inside(e, c) && c["name"].as_str().unwrap_or("").contains(n))
        {
            continue;
        }
        if r != "text" {
            named.push(e)
        }
        let mut l = format!("- {r}");
        if !n.is_empty() {
            l.push_str(&format!(" {:?}", n.chars().take(80).collect::<String>()))
        }
        for st in ["checked", "focused", "selected"] {
            if e[st] == true {
                l.push_str(&format!(" [{st}]"))
            }
        }
        if e["disabled"] == true {
            l.push_str(" [disabled]")
        }
        if r == "textbox" && !e["value"].as_str().unwrap_or("").is_empty() {
            l.push_str(&format!(": {}", e["value"].as_str().unwrap_or("")))
        }
        lines.push(l)
    }
    let more = lines.len().saturating_sub(max);
    lines.truncate(max);
    if more > 0 {
        lines.push(format!("… {more} more"))
    }
    lines.join("\n")
}

fn adb_path() -> String {
    let home = std::env::var("HOME").unwrap_or_default();
    ["ANDROID_HOME", "ANDROID_SDK_ROOT"]
        .iter()
        .filter_map(|k| std::env::var(k).ok())
        .chain([format!("{home}/Library/Android/sdk"), format!("{home}/Android/Sdk")])
        .map(|r| format!("{r}/platform-tools/adb"))
        .find(|p| std::path::Path::new(p).exists())
        .unwrap_or_else(|| "adb".into())
}

pub struct Device {
    pub serial: String,
    adb: String,
    /// The last dump, reused for 500ms until the next input (a dump takes ~2s).
    cache: std::sync::Mutex<Option<(std::time::Instant, Vec<Value>)>>,
}
impl Device {
    /// `ANDROID_SERIAL`, else the first attached device or emulator.
    pub fn connect() -> Result<Device> {
        let adb = adb_path();
        let serial = match std::env::var("ANDROID_SERIAL") {
            Ok(s) => s,
            Err(_) => {
                let out = Command::new(&adb)
                    .arg("devices")
                    .output()
                    .map_err(|e| anyhow!("cannot run adb ({adb}): {e}"))?;
                String::from_utf8_lossy(&out.stdout)
                    .lines()
                    .skip(1)
                    .find_map(|l| l.strip_suffix("\tdevice").map(String::from))
                    .ok_or_else(|| anyhow!("no Android device attached; start an emulator or plug in a device (`adb devices`)"))?
            }
        };
        Ok(Device { serial, adb, cache: Default::default() })
    }
    fn adb(&self, args: &[&str]) -> Result<Vec<u8>> {
        let o = Command::new(&self.adb).args(["-s", &self.serial]).args(args).output()?;
        if !o.status.success() {
            bail!("adb {}: {}", args.join(" "), String::from_utf8_lossy(&o.stderr).trim())
        }
        Ok(o.stdout)
    }
    pub fn shell(&self, cmd: &str) -> Result<String> {
        if !cmd.starts_with("uiautomator") {
            *self.cache.lock().unwrap() = None
        }
        Ok(String::from_utf8_lossy(&self.adb(&["shell", cmd])?).into())
    }
    pub fn elements(&self) -> Result<Vec<Value>> {
        if let Some((t, els)) = &*self.cache.lock().unwrap() {
            if t.elapsed().as_millis() < 500 {
                return Ok(els.clone());
            }
        }
        let mut last = String::new();
        for _ in 0..3 {
            let x =
                self.shell("uiautomator dump /sdcard/tk.xml >/dev/null && cat /sdcard/tk.xml")?;
            if x.contains("<hierarchy") {
                let els = elements(&parse_dump(&x)?);
                *self.cache.lock().unwrap() = Some((std::time::Instant::now(), els.clone()));
                return Ok(els);
            }
            last = x;
        }
        bail!("uiautomator could not dump the screen: {}", last.trim())
    }
    pub fn tap(&self, e: &Value) -> Result<()> {
        let g = |k: &str| e["box"][k].as_i64().unwrap_or(0);
        self.shell(&format!("input tap {} {}", g("x") + g("width") / 2, g("y") + g("height") / 2))
            .map(drop)
    }
    pub fn swipe(&self, dir: &str, within: Option<&Value>) -> Result<()> {
        let size = self.shell("wm size")?;
        let wh: Vec<i64> = size
            .rsplit(' ')
            .next()
            .unwrap_or("")
            .trim()
            .split('x')
            .filter_map(|n| n.parse().ok())
            .collect();
        let (x, y, w, h) = match within {
            Some(e) => {
                let g = |k: &str| e["box"][k].as_i64().unwrap_or(0);
                (g("x"), g("y"), g("width"), g("height"))
            }
            None => (0, 0, *wh.first().unwrap_or(&1080), *wh.get(1).unwrap_or(&1920)),
        };
        let (cx, cy) = (x + w / 2, y + h / 2);
        let (dx, dy) = match dir {
            "up" => (0, -h * 3 / 10),
            "down" => (0, h * 3 / 10),
            "left" => (-w * 3 / 10, 0),
            "right" => (w * 3 / 10, 0),
            d => bail!("swipe: `{d}`; expected up, down, left or right"),
        };
        self.shell(&format!("input swipe {} {} {} {} 300", cx - dx, cy - dy, cx + dx, cy + dy))
            .map(drop)
    }
    pub fn text(&self, s: &str) -> Result<()> {
        let s = s.replace('\'', "'\\''").replace(' ', "%s");
        self.shell(&format!("input text '{s}'")).map(drop)
    }
    /// Key names as in `press:` (`Enter`, `Backspace`, `ctrl+a`, `back`, `home`) or Android KEYCODE_ names.
    pub fn key(&self, combo: &str) -> Result<()> {
        let code = |k: &str| match k.to_lowercase().as_str() {
            "enter" | "return" => "66".into(),
            "back" | "escape" | "esc" => "4".into(),
            "home" => "3".into(),
            "tab" => "61".into(),
            "backspace" => "67".into(),
            "delete" => "112".into(),
            "space" => "62".into(),
            "up" => "19".into(),
            "down" => "20".into(),
            "left" => "21".into(),
            "right" => "22".into(),
            "ctrl" | "control" => "113".into(),
            "shift" => "59".into(),
            "alt" => "57".into(),
            k if k.len() == 1 && k.as_bytes()[0].is_ascii_lowercase() => {
                (29 + (k.as_bytes()[0] - b'a')).to_string()
            }
            _ => format!("KEYCODE_{}", k.to_uppercase()),
        };
        let codes: Vec<String> = combo.split('+').map(code).collect();
        if codes.len() > 1 {
            self.shell(&format!("input keycombination {}", codes.join(" "))).map(drop)
        } else {
            self.shell(&format!("input keyevent {}", codes[0])).map(drop)
        }
    }
    /// `com.acme` (launcher activity) or `com.acme/.MainActivity`; starts fresh and clears the crash log.
    pub fn launch(&self, app: &str) -> Result<()> {
        let pkg = app.split('/').next().unwrap_or(app);
        self.shell(&format!("input keyevent 3; am force-stop {pkg}; logcat -b crash -c"))?;
        let component = if app.contains('/') {
            app.to_string()
        } else {
            let r = self.shell(&format!(
                "cmd package resolve-activity --brief -c android.intent.category.LAUNCHER {pkg}"
            ))?;
            r.lines().last().unwrap_or("").trim().to_string()
        };
        if !component.contains('/') {
            bail!("cannot launch `{app}`: no launcher activity (is it installed? `adb shell pm list packages`)")
        }
        let out = self.shell(&format!("am start -W -f 0x10008000 -n {component}"))?;
        if out.contains("Error") || out.contains("No activities found") {
            bail!("cannot launch `{app}`: {}", out.trim())
        }
        Ok(())
    }
    pub fn deeplink(&self, url: &str) -> Result<()> {
        self.shell(&format!("am start -W -a android.intent.action.VIEW -d '{url}'")).map(drop)
    }
    pub fn screenshot(&self) -> Result<Vec<u8>> {
        self.adb(&["exec-out", "screencap", "-p"])
    }
    /// Crashes since `launch:` (the mobile equivalent of page errors).
    pub fn crashes(&self) -> String {
        self.shell("logcat -b crash -d")
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.starts_with("---"))
            .collect::<Vec<_>>()
            .join("\n")
    }
    pub fn foreground(&self) -> String {
        let s = self
            .shell("dumpsys activity activities | grep -m1 topResumedActivity")
            .unwrap_or_default();
        s.split_whitespace().find(|w| w.contains('/')).unwrap_or("").to_string()
    }
}
