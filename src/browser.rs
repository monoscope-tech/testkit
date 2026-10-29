//! Browser surface (spec §5.2): one Chrome, an isolated context per session, semantic locators via `inject.js`.
use crate::expr::{Locator, Scope};
use crate::item::scalar_text;
use anyhow::{anyhow, bail, Result};
use chromiumoxide::browser::{Browser, BrowserConfig, HeadlessMode};
use chromiumoxide::cdp::browser_protocol::{
    emulation, fetch, input, network as net, page as cpage, target,
};
use chromiumoxide::cdp::js_protocol::runtime;
use chromiumoxide::handler::viewport::Viewport;
use chromiumoxide::layout::Point;
use chromiumoxide::Page;
use futures_util::StreamExt;
use serde::Serialize;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const INJECT: &str = include_str!("inject.js");

pub struct Chrome {
    pub browser: Browser,
    pub ws: String,
    _handler: tokio::task::JoinHandle<()>,
    attached: bool,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct Req {
    pub seq: u64,
    #[serde(skip)]
    pub id: String,
    pub method: String,
    pub url: String,
    pub status: Option<i64>,
    pub ms: f64,
    pub size: f64,
    pub mocked: bool,
    pub failed: Option<String>,
    pub kind: String,
    pub req: Value,
    pub headers: Value,
    #[serde(skip)]
    pub body: Option<String>,
    #[serde(skip)]
    pub t0: f64,
    pub done: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Msg {
    pub seq: u64,
    pub level: String,
    pub text: String,
    pub source: String,
}

#[derive(Default)]
pub struct Log {
    pub seq: u64,
    pub reqs: Vec<Req>,
    pub console: Vec<Msg>,
    pub dialogs: Vec<String>,
    pub popups: Vec<target::TargetId>,
    pub downloads: Vec<String>,
}
impl Log {
    pub fn tick(&mut self) -> u64 {
        self.seq += 1;
        self.seq
    }
}

#[derive(Clone, Debug)]
pub struct Route {
    pub method: Option<String>,
    pub pat: String,
    pub respond: Option<Value>,
    pub modify: Option<Value>,
    pub abort: Option<String>,
    pub delay_ms: u64,
    pub times: Option<u32>,
    pub hits: u32,
}

impl Route {
    pub fn matches(&self, method: &str, url: &str, base: &str) -> bool {
        self.method.as_deref().is_none_or(|m| m.eq_ignore_ascii_case(method))
            && url_match(&self.pat, url, base)
            && self.times.is_none_or(|t| self.hits < t)
    }
}

/// `*` = one path segment, `**` = anything, `/re/` = regex; patterns are relative to `base`.
///
/// ```
/// use testkit::browser::url_match;
/// assert!(url_match("/api/orders/*", "http://x/api/orders/12", "http://x"));
/// assert!(!url_match("/api/orders/*", "http://x/api/orders/12/items", "http://x"));
/// assert!(url_match("/analytics/**", "http://x/analytics/a/b?q=1", "http://x"));
/// assert!(url_match("GET /api*", "http://x/api/me", "")== false);
/// assert!(url_match("/api/me", "http://x/api/me?x=1", "http://x"));
/// assert!(url_match("/\\/me$/", "http://x/api/me", ""));
/// ```
pub fn url_match(pat: &str, url: &str, base: &str) -> bool {
    if pat.len() > 2
        && pat.starts_with('/')
        && pat.ends_with('/')
        && pat[1..pat.len() - 1].contains(['\\', '^', '$', '(', '|', '+', '['])
    {
        return regex::Regex::new(&pat[1..pat.len() - 1]).is_ok_and(|r| r.is_match(url));
    }
    let path =
        url.split_once("://").map(|(_, r)| r.find('/').map_or("/", |i| &r[i..])).unwrap_or(url);
    let path_noq = path.split('?').next().unwrap_or(path);
    let full = pat.starts_with("http");
    let pat = if !full && !base.is_empty() && !pat.starts_with('/') {
        format!("/{pat}")
    } else {
        pat.to_string()
    };
    let mut re = String::from("^");
    let mut chars = pat.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '*' if chars.peek() == Some(&'*') => {
                chars.next();
                re.push_str(".*")
            }
            '*' => re.push_str("[^/?]*"),
            c => re.push_str(&regex::escape(&c.to_string())),
        }
    }
    re.push_str(if pat.contains('?') { "$" } else { "(\\?.*)?$" });
    regex::Regex::new(&re).is_ok_and(|r| {
        r.is_match(if full { url } else { path }) || (!pat.contains('?') && r.is_match(path_noq))
    })
}

fn find_chrome() -> Option<String> {
    if let Ok(p) = std::env::var("TESTKIT_CHROME") {
        return Some(p);
    }
    let home = std::env::var("HOME").unwrap_or_default();
    let cached = std::fs::read_dir(format!("{home}/.cache/testkit/chrome")).ok().and_then(|d| d.filter_map(|e| e.ok()).map(|e| e.path()).find_map(|p| {
        ["chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing", "chrome-mac-x64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing", "chrome-linux64/chrome"]
            .iter().map(|s| p.join(s)).find(|p| p.exists()).map(|p| p.to_string_lossy().to_string())
    }));
    cached
}

impl Chrome {
    pub async fn launch(headed: bool) -> Result<Self> {
        let dir = std::env::temp_dir().join(format!(
            "testkit-chrome-{}-{}",
            std::process::id(),
            rand_id()
        ));
        let mut b = BrowserConfig::builder()
            .window_size(1280, 800)
            .user_data_dir(&dir)
            .viewport(Viewport { width: 1280, height: 800, ..Default::default() })
            .request_timeout(Duration::from_secs(60))
            .args([
                "--disable-features=Translate,OptimizationHints,MediaRouter",
                "--no-first-run",
                "--hide-scrollbars",
                "--mute-audio",
            ]);
        b = if headed { b.with_head() } else { b.headless_mode(HeadlessMode::New) };
        if std::env::var("CI").is_ok() || std::env::var("TESTKIT_NO_SANDBOX").is_ok() {
            b = b.no_sandbox()
        }
        if let Some(p) = find_chrome() {
            b = b.chrome_executable(p)
        }
        let cfg = b.build().map_err(|e| {
            anyhow!("cannot configure Chrome: {e}. Install Chrome or run `testkit install chrome`.")
        })?;
        let (browser, mut handler) = Browser::launch(cfg).await.map_err(|e| {
            anyhow!("cannot launch Chrome: {e}. Install Chrome or run `testkit install chrome`.")
        })?;
        let ws = browser.websocket_address().clone();
        let h = tokio::spawn(async move {
            while let Some(e) = handler.next().await {
                if e.is_err() {
                    continue;
                }
            }
        });
        Ok(Chrome { browser, ws, _handler: h, attached: false })
    }
    pub async fn connect(url: &str) -> Result<Self> {
        let (mut browser, mut handler) =
            Browser::connect(url).await.map_err(|e| anyhow!("cannot attach to {url}: {e}"))?;
        let h = tokio::spawn(async move {
            while let Some(e) = handler.next().await {
                if e.is_err() {
                    continue;
                }
            }
        });
        browser.fetch_targets().await.ok();
        tokio::time::sleep(Duration::from_millis(300)).await;
        Ok(Chrome { ws: url.into(), browser, _handler: h, attached: true })
    }
    /// A new tab in its own browser context (cookies and storage isolated per session).
    pub async fn tab(&self, isolated: bool) -> Result<Tab> {
        if self.attached {
            if let Some(p) = self.browser.pages().await?.into_iter().next() {
                return Tab::wrap(p).await;
            }
        }
        let mut params = target::CreateTargetParams::builder().url("about:blank");
        if isolated {
            let ctx = self
                .browser
                .create_browser_context(target::CreateBrowserContextParams::default())
                .await?;
            use chromiumoxide::cdp::browser_protocol::browser as cb;
            let dir = std::env::current_dir().unwrap_or_default().join(".testkit/downloads");
            std::fs::create_dir_all(&dir).ok();
            if let Ok(cmd) = cb::SetDownloadBehaviorParams::builder()
                .behavior(cb::SetDownloadBehaviorBehavior::Allow)
                .browser_context_id(ctx.clone())
                .download_path(dir.to_string_lossy())
                .build()
            {
                self.browser.execute(cmd).await.ok();
            }
            params = params.browser_context_id(ctx);
        }
        let page = self.browser.new_page(params.build().map_err(|e| anyhow!(e))?).await?;
        Tab::wrap(page).await
    }
    pub async fn adopt(&self, id: target::TargetId) -> Result<Tab> {
        Tab::wrap(self.browser.get_page(id).await?).await
    }
    pub async fn close(mut self) {
        if !self.attached {
            self.browser.close().await.ok();
            self.browser.wait().await.ok();
        }
    }
}

pub fn rand_id() -> String {
    format!(
        "{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            ^ (std::process::id() as u128)
    )
}

pub struct Tab {
    pub page: Page,
    pub log: Arc<Mutex<Log>>,
    pub routes: Arc<Mutex<Vec<Route>>>,
    pub dialog: Arc<Mutex<(bool, Option<String>)>>,
    pub base: Arc<Mutex<String>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for Tab {
    fn drop(&mut self) {
        self.tasks.iter().for_each(|t| t.abort())
    }
}

fn obj_text(o: &runtime::RemoteObject) -> String {
    o.value.as_ref().map(scalar_text).or_else(|| o.description.clone()).unwrap_or_default()
}

impl Tab {
    async fn wrap(page: Page) -> Result<Self> {
        let log = Arc::new(Mutex::new(Log::default()));
        let routes: Arc<Mutex<Vec<Route>>> = Arc::default();
        let dialog = Arc::new(Mutex::new((false, None)));
        let base = Arc::new(Mutex::new(String::new()));
        page.execute(net::EnableParams::default()).await?;
        page.enable_runtime().await?;
        page.execute(cpage::EnableParams::default()).await?;
        page.execute(cpage::AddScriptToEvaluateOnNewDocumentParams::new(INJECT)).await?;
        let mut tasks = vec![];
        macro_rules! listen {
            ($ty:ty, |$e:ident, $l:ident| $body:block) => {{
                let mut s = page.event_listener::<$ty>().await?;
                let log = log.clone();
                tasks.push(tokio::spawn(async move {
                    while let Some($e) = s.next().await {
                        let mut $l = log.lock().unwrap();
                        $body
                    }
                }));
            }};
        }
        listen!(net::EventRequestWillBeSent, |e, l| {
            let seq = l.tick();
            let kind =
                e.r#type.as_ref().map(|t| format!("{t:?}").to_lowercase()).unwrap_or_default();
            l.reqs.push(Req { seq, id: e.request_id.inner().clone(), method: e.request.method.clone(), url: e.request.url.clone(), kind, t0: *e.timestamp.inner(),
                req: json!({"headers": e.request.headers.inner(), "has_body": e.request.has_post_data}), ..Default::default() });
        });
        listen!(net::EventResponseReceived, |e, l| {
            if let Some(r) = l.reqs.iter_mut().rev().find(|r| r.id == *e.request_id.inner()) {
                r.status = Some(e.response.status);
                r.headers = e.response.headers.inner().clone();
            }
        });
        listen!(net::EventLoadingFinished, |e, l| {
            if let Some(r) = l.reqs.iter_mut().rev().find(|r| r.id == *e.request_id.inner()) {
                r.done = true;
                r.size = e.encoded_data_length;
                r.ms = ((*e.timestamp.inner() - r.t0) * 1000.0).round();
            }
        });
        listen!(net::EventLoadingFailed, |e, l| {
            if let Some(r) = l.reqs.iter_mut().rev().find(|r| r.id == *e.request_id.inner()) {
                r.done = true;
                r.failed = Some(e.error_text.clone());
                r.ms = ((*e.timestamp.inner() - r.t0) * 1000.0).round();
            }
        });
        listen!(runtime::EventConsoleApiCalled, |e, l| {
            let seq = l.tick();
            let level = match format!("{:?}", e.r#type).to_lowercase().as_str() {
                "error" | "assert" => "error",
                "warning" => "warning",
                "debug" => "debug",
                _ => "log",
            }
            .to_string();
            let source = e
                .stack_trace
                .as_ref()
                .and_then(|s| s.call_frames.first())
                .map(|f| {
                    format!("{}:{}", f.url.rsplit('/').next().unwrap_or(""), f.line_number + 1)
                })
                .unwrap_or_default();
            l.console.push(Msg {
                seq,
                level,
                text: e.args.iter().map(obj_text).collect::<Vec<_>>().join(" "),
                source,
            });
        });
        listen!(runtime::EventExceptionThrown, |e, l| {
            let seq = l.tick();
            let d = &e.exception_details;
            let text = d
                .exception
                .as_ref()
                .and_then(|x| x.description.clone())
                .unwrap_or_else(|| d.text.clone());
            l.console.push(Msg {
                seq,
                level: "pageerror".into(),
                text: text.lines().next().unwrap_or("").into(),
                source: format!(
                    "{}:{}",
                    d.url.clone().unwrap_or_default().rsplit('/').next().unwrap_or(""),
                    d.line_number + 1
                ),
            });
        });
        {
            let mut s = page.event_listener::<cpage::EventJavascriptDialogOpening>().await?;
            let (p, log, dialog) = (page.clone(), log.clone(), dialog.clone());
            tasks.push(tokio::spawn(async move {
                while let Some(e) = s.next().await {
                    log.lock().unwrap().dialogs.push(e.message.clone());
                    let (accept, text) = dialog.lock().unwrap().clone();
                    let mut b = cpage::HandleJavaScriptDialogParams::builder().accept(accept);
                    if let Some(t) = text {
                        b = b.prompt_text(t)
                    }
                    if let Ok(cmd) = b.build() {
                        p.execute(cmd).await.ok();
                    }
                }
            }));
        }
        {
            use chromiumoxide::cdp::browser_protocol::browser as cb;
            let dir = std::env::current_dir().unwrap_or_default().join(".testkit/downloads");
            std::fs::create_dir_all(&dir).ok();
            if let Ok(cmd) = cb::SetDownloadBehaviorParams::builder()
                .behavior(cb::SetDownloadBehaviorBehavior::Allow)
                .download_path(dir.to_string_lossy())
                .build()
            {
                page.execute(cmd).await.ok();
            }
        }
        {
            let mut s = page.event_listener::<fetch::EventRequestPaused>().await?;
            let (p, routes, log, base) = (page.clone(), routes.clone(), log.clone(), base.clone());
            tasks.push(tokio::spawn(async move {
                while let Some(e) = s.next().await {
                    let base = base.lock().unwrap().clone();
                    let at_response = e.response_status_code.is_some();
                    let modifying = at_response
                        && routes.lock().unwrap().iter().any(|r| {
                            r.modify.is_some()
                                && r.matches(&e.request.method, &e.request.url, &base)
                        });
                    if at_response && !modifying {
                        if let Ok(b) =
                            p.execute(fetch::GetResponseBodyParams::new(e.request_id.clone())).await
                        {
                            use base64::Engine;
                            let body = if b.base64_encoded {
                                String::from_utf8_lossy(
                                    &base64::engine::general_purpose::STANDARD
                                        .decode(&b.body)
                                        .unwrap_or_default(),
                                )
                                .to_string()
                            } else {
                                b.body.clone()
                            };
                            let nid = e.network_id.as_ref().map(|n| n.inner().clone());
                            if let Some(r) = log.lock().unwrap().reqs.iter_mut().rev().find(|r| {
                                Some(&r.id) == nid.as_ref()
                                    || (nid.is_none() && r.url == e.request.url)
                            }) {
                                r.body = Some(body)
                            }
                        }
                        p.execute(fetch::ContinueResponseParams::new(e.request_id.clone()))
                            .await
                            .ok();
                        continue;
                    }
                    let route = {
                        let mut rs = routes.lock().unwrap();
                        let at_response = e.response_status_code.is_some();
                        let hit = rs.iter_mut().rev().find(|r| {
                            r.matches(&e.request.method, &e.request.url, &base)
                                && (r.modify.is_some() == at_response)
                        });
                        hit.map(|r| {
                            if r.modify.is_none() {
                                r.hits += 1
                            }
                            r.clone()
                        })
                    };
                    if route.as_ref().is_some_and(|r| r.modify.is_none()) {
                        let mut l = log.lock().unwrap();
                        if let Some(r) =
                            l.reqs.iter_mut().rev().find(|r| r.url == e.request.url && !r.done)
                        {
                            r.mocked = true
                        }
                    }
                    fulfil(&p, &e, route).await;
                }
            }));
        }
        let tab = Tab { page, log, routes, dialog, base, tasks };
        tab.eval_raw(INJECT).await.ok();
        Ok(tab)
    }

    pub async fn eval_raw(&self, js: &str) -> Result<Value> {
        let p = runtime::EvaluateParams::builder()
            .expression(js)
            .await_promise(true)
            .return_by_value(true)
            .build()
            .map_err(|e| anyhow!(e))?;
        let r = tokio::time::timeout(Duration::from_secs(30), self.page.execute(p))
            .await
            .map_err(|_| anyhow!("the page did not respond within 30s"))??;
        if let Some(ex) = &r.result.exception_details {
            bail!(
                "{}",
                ex.exception
                    .as_ref()
                    .and_then(|e| e.description.clone())
                    .unwrap_or_else(|| ex.text.clone())
            )
        }
        Ok(r.result.result.value.clone().unwrap_or(Value::Null))
    }
    /// Calls `window.__tk.<f>(...args)`, injecting the helper first when the page has none.
    pub async fn tk(&self, f: &str, args: &[Value]) -> Result<Value> {
        let a = args.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(",");
        let js = format!("(async () => {{ if (!window.__tk) {{ {INJECT} }} return await window.__tk.{f}({a}); }})()");
        self.eval_raw(&js).await
    }
    /// Fetch interception: routes at the request stage; fetch/XHR bodies captured at the response stage.
    pub async fn sync_routes(&self) -> Result<()> {
        let rs = self.routes.lock().unwrap().clone();
        let mut pats = vec![];
        for ty in [net::ResourceType::Fetch, net::ResourceType::Xhr] {
            pats.push(
                fetch::RequestPattern::builder()
                    .url_pattern("*")
                    .resource_type(ty)
                    .request_stage(fetch::RequestStage::Response)
                    .build(),
            )
        }
        if !rs.is_empty() {
            pats.push(
                fetch::RequestPattern::builder()
                    .url_pattern("*")
                    .request_stage(fetch::RequestStage::Request)
                    .build(),
            )
        }
        if rs.iter().any(|r| r.modify.is_some()) {
            pats.push(
                fetch::RequestPattern::builder()
                    .url_pattern("*")
                    .request_stage(fetch::RequestStage::Response)
                    .build(),
            )
        }
        self.page.execute(fetch::EnableParams::builder().patterns(pats).build()).await?;
        Ok(())
    }
    pub async fn goto(&self, url: &str) -> Result<()> {
        if let Some(b) = url
            .split_once("://")
            .map(|(s, r)| format!("{s}://{}", r.split('/').next().unwrap_or("")))
        {
            *self.base.lock().unwrap() = b
        }
        let nav = cpage::NavigateParams::builder().url(url).build().map_err(|e| anyhow!(e))?;
        let r = self.page.execute(nav).await?;
        if let Some(err) = &r.error_text {
            bail!("navigation to {url} failed: {err}")
        }
        self.wait_load().await;
        Ok(())
    }
    pub async fn wait_load(&self) {
        let t = Instant::now();
        let mut errors = 0;
        while t.elapsed() < Duration::from_secs(15) {
            match tokio::time::timeout(Duration::from_secs(2), self.eval_raw("document.readyState"))
                .await
            {
                Ok(Ok(Value::String(s))) if s == "complete" => break,
                Ok(Ok(_)) => {}
                _ => {
                    errors += 1;
                    if errors > 3 {
                        break;
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    pub async fn url(&self) -> String {
        self.eval_raw("location.href").await.map(|v| scalar_text(&v)).unwrap_or_default()
    }
    pub async fn page_state(&self) -> Value {
        self.eval_raw("({url: location.href, title: document.title, path: location.pathname + location.search})").await.unwrap_or(Value::Null)
    }
    pub async fn resolve(&self, loc: &Locator) -> Result<Vec<Value>> {
        let v = self.tk("resolve", &[loc_json(loc)]).await?;
        Ok(v.as_array().cloned().unwrap_or_default())
    }
    pub async fn locator_for(&self, r: i64) -> Option<String> {
        self.eval_raw(&format!("window.__tk && window.__tk.refs.get({r}) ? window.__tk.locatorFor(window.__tk.refs.get({r})) : null")).await.ok().and_then(|v| v.as_str().map(String::from))
    }
    pub async fn click_at(
        &self,
        x: f64,
        y: f64,
        count: i64,
        button: input::MouseButton,
    ) -> Result<()> {
        let t = Instant::now();
        self.page.move_mouse(Point { x, y }).await?;
        log::debug!(target: "testkit", "mouse moved {}ms", t.elapsed().as_millis());
        for n in 1..=count {
            for ty in [
                input::DispatchMouseEventType::MousePressed,
                input::DispatchMouseEventType::MouseReleased,
            ] {
                let cmd = input::DispatchMouseEventParams::builder()
                    .x(x)
                    .y(y)
                    .button(button.clone())
                    .buttons(1)
                    .click_count(n)
                    .r#type(ty)
                    .build()
                    .map_err(|e| anyhow!(e))?;
                self.page.execute(cmd).await?;
                log::debug!(target: "testkit", "mouse {n} event {}ms", t.elapsed().as_millis());
            }
        }
        Ok(())
    }
    pub async fn insert_text(&self, s: &str) -> Result<()> {
        self.page.execute(input::InsertTextParams::new(s)).await?;
        Ok(())
    }
    pub async fn key(&self, combo: &str) -> Result<()> {
        let parts: Vec<&str> = combo.split('+').collect();
        let (mods, key) = parts.split_at(parts.len() - 1);
        let m = mods
            .iter()
            .map(|m| match m.to_lowercase().as_str() {
                "alt" => 1,
                "ctrl" | "control" => 2,
                "meta" | "cmd" => 4,
                "shift" => 8,
                _ => 0,
            })
            .sum::<i64>();
        let (k, code, vk, txt) = key_def(key[0]);
        let txt = if m & 7 != 0 { None } else { txt };
        for ty in [input::DispatchKeyEventType::KeyDown, input::DispatchKeyEventType::KeyUp] {
            let mut b = input::DispatchKeyEventParams::builder()
                .r#type(ty.clone())
                .key(k.clone())
                .code(code.clone())
                .windows_virtual_key_code(vk)
                .modifiers(m);
            if ty == input::DispatchKeyEventType::KeyDown {
                if let Some(t) = &txt {
                    b = b.text(t.clone())
                }
            }
            self.page.execute(b.build().map_err(|e| anyhow!(e))?).await?;
        }
        Ok(())
    }
    pub async fn type_text(&self, s: &str) -> Result<()> {
        for c in s.chars() {
            self.key(&c.to_string()).await?
        }
        Ok(())
    }
    pub async fn screenshot(&self, scale: f64) -> Result<Vec<u8>> {
        let p =
            cpage::CaptureScreenshotParams::builder().format(cpage::CaptureScreenshotFormat::Png);
        let p = if scale < 1.0 {
            let vp = self.eval_raw("({w: innerWidth, h: innerHeight})").await?;
            p.clip(cpage::Viewport {
                x: 0.0,
                y: 0.0,
                width: vp["w"].as_f64().unwrap_or(1280.0),
                height: vp["h"].as_f64().unwrap_or(800.0),
                scale,
            })
        } else {
            p
        };
        let r = self.page.execute(p.build()).await?;
        use base64::Engine;
        Ok(base64::engine::general_purpose::STANDARD.decode(AsRef::<str>::as_ref(&r.data))?)
    }
    pub async fn set_files(&self, r: i64, files: Vec<String>) -> Result<()> {
        let obj = self
            .page
            .execute(
                runtime::EvaluateParams::builder()
                    .expression(format!("window.__tk.refs.get({r})"))
                    .return_by_value(false)
                    .build()
                    .map_err(|e| anyhow!(e))?,
            )
            .await?;
        let id =
            obj.result.result.object_id.clone().ok_or_else(|| anyhow!("file input is detached"))?;
        self.page
            .execute(
                chromiumoxide::cdp::browser_protocol::dom::SetFileInputFilesParams::builder()
                    .files(files)
                    .object_id(id)
                    .build()
                    .map_err(|e| anyhow!(e))?,
            )
            .await?;
        Ok(())
    }
    pub async fn emulate(&self, what: &str) -> Result<()> {
        use emulation::*;
        let w = what.trim().to_lowercase();
        match w.as_str() {
            "dark" | "light" => {
                self.page
                    .execute(
                        SetEmulatedMediaParams::builder()
                            .features(vec![MediaFeature::new("prefers-color-scheme", w.clone())])
                            .build(),
                    )
                    .await?;
            }
            "reduced-motion" => {
                self.page
                    .execute(
                        SetEmulatedMediaParams::builder()
                            .features(vec![MediaFeature::new("prefers-reduced-motion", "reduce")])
                            .build(),
                    )
                    .await?;
            }
            "desktop" => {
                self.page.execute(ClearDeviceMetricsOverrideParams::default()).await?;
            }
            d => {
                let (wd, h, dpr) = match d {
                    s if s.contains("iphone") => (390, 844, 3.0),
                    s if s.contains("pixel") || s.contains("android") => (412, 915, 2.6),
                    s if s.contains("ipad") => (820, 1180, 2.0),
                    s => {
                        let (a, b) = s.split_once('x').ok_or_else(|| anyhow!("unknown device `{s}`; use iPhone 15, Pixel 8, iPad, desktop, dark, light, reduced-motion or WIDTHxHEIGHT"))?;
                        (a.trim().parse()?, b.trim().parse()?, 1.0)
                    }
                };
                self.page
                    .execute(SetDeviceMetricsOverrideParams::new(wd, h, dpr, wd < 700))
                    .await?;
                self.page.execute(SetTouchEmulationEnabledParams::new(wd < 700)).await?;
            }
        }
        Ok(())
    }
    pub async fn throttle(&self, s: &str) -> Result<()> {
        let n: f64 = s
            .trim()
            .trim_start_matches("cpu")
            .trim()
            .trim_end_matches('x')
            .trim()
            .parse()
            .map_err(|_| anyhow!("use `throttle: cpu 4x`"))?;
        self.page.execute(emulation::SetCpuThrottlingRateParams::new(n)).await?;
        Ok(())
    }
    pub async fn network(&self, s: &str) -> Result<()> {
        let (off, lat, down, up) = match s.trim().to_lowercase().as_str() {
            "offline" => (true, 0.0, -1.0, -1.0),
            "online" => (false, 0.0, -1.0, -1.0),
            "slow 3g" => (false, 400.0, 50_000.0, 50_000.0),
            "fast 3g" => (false, 150.0, 200_000.0, 90_000.0),
            o => bail!("unknown network profile `{o}`; use slow 3g, fast 3g, offline or online"),
        };
        self.page.execute(net::EmulateNetworkConditionsParams::new(off, lat, down, up)).await?;
        Ok(())
    }
}

async fn fulfil(p: &Page, e: &fetch::EventRequestPaused, route: Option<Route>) {
    let id = e.request_id.clone();
    let Some(r) = route else {
        p.execute(fetch::ContinueRequestParams::new(id)).await.ok();
        return;
    };
    if r.delay_ms > 0 {
        tokio::time::sleep(Duration::from_millis(r.delay_ms)).await
    }
    if let Some(reason) = &r.abort {
        let er = match reason.as_str() {
            "timedout" => net::ErrorReason::TimedOut,
            "connectionrefused" => net::ErrorReason::ConnectionRefused,
            _ => net::ErrorReason::Failed,
        };
        p.execute(fetch::FailRequestParams::new(id, er)).await.ok();
        return;
    }
    let (status, body, headers) = if let Some(m) = &r.modify {
        let body = p
            .execute(fetch::GetResponseBodyParams::new(id.clone()))
            .await
            .ok()
            .map(|b| {
                use base64::Engine;
                if b.base64_encoded {
                    String::from_utf8_lossy(
                        &base64::engine::general_purpose::STANDARD
                            .decode(&b.body)
                            .unwrap_or_default(),
                    )
                    .to_string()
                } else {
                    b.body.clone()
                }
            })
            .unwrap_or_default();
        let mut j: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
        if let Some(patch) = m.get("json") {
            merge(&mut j, patch)
        }
        let status = m
            .get("status")
            .and_then(Value::as_i64)
            .unwrap_or(e.response_status_code.unwrap_or(200));
        (status, j.to_string(), vec![("content-type".to_string(), "application/json".to_string())])
    } else {
        response_parts(r.respond.as_ref().unwrap_or(&json!({})))
    };
    use base64::Engine;
    let hs = headers.into_iter().map(|(k, v)| fetch::HeaderEntry::new(k, v)).collect::<Vec<_>>();
    let cmd = fetch::FulfillRequestParams::builder()
        .request_id(id)
        .response_code(status)
        .response_headers(hs)
        .body(base64::engine::general_purpose::STANDARD.encode(body))
        .build();
    if let Ok(c) = cmd {
        p.execute(c).await.ok();
    }
}

/// `respond:` → (status, body, headers). A string is a fixture file path.
pub fn response_parts(v: &Value) -> (i64, String, Vec<(String, String)>) {
    if let Value::String(path) = v {
        let body = std::fs::read_to_string(path).unwrap_or_else(|e| format!("fixture {path}: {e}"));
        let ct = if path.ends_with(".json") {
            "application/json"
        } else if path.ends_with(".html") {
            "text/html"
        } else {
            "text/plain"
        };
        return (200, body, vec![("content-type".into(), ct.into())]);
    }
    let status = v.get("status").and_then(Value::as_i64).unwrap_or(200);
    let mut hs: Vec<(String, String)> = v
        .get("headers")
        .and_then(Value::as_object)
        .map(|o| o.iter().map(|(k, v)| (k.clone(), scalar_text(v))).collect())
        .unwrap_or_default();
    let body = if let Some(j) = v.get("json") {
        hs.push(("content-type".into(), "application/json".into()));
        j.to_string()
    } else {
        v.get("body").map(scalar_text).unwrap_or_default()
    };
    (status, body, hs)
}

pub fn merge(a: &mut Value, b: &Value) {
    match (a, b) {
        (Value::Object(a), Value::Object(b)) => {
            for (k, v) in b {
                merge(a.entry(k.clone()).or_insert(Value::Null), v)
            }
        }
        (Value::Array(a), Value::Object(_)) => a.iter_mut().for_each(|x| merge(x, b)),
        (a, b) => *a = b.clone(),
    }
}

/// Locators are sent to the page as JSON; session scopes are resolved on the Rust side.
pub fn loc_json(l: &Locator) -> Value {
    let mut l = l.clone();
    l.scope.retain(|s| !matches!(s, Scope::Session(_)));
    serde_json::to_value(&l).unwrap_or(Value::Null)
}

fn key_def(k: &str) -> (String, String, i64, Option<String>) {
    let named = |key: &str, code: &str, vk: i64, t: Option<&str>| {
        (key.to_string(), code.to_string(), vk, t.map(String::from))
    };
    match k.to_lowercase().as_str() {
        "enter" | "return" => named("Enter", "Enter", 13, Some("\r")),
        "tab" => named("Tab", "Tab", 9, None),
        "escape" | "esc" => named("Escape", "Escape", 27, None),
        "backspace" => named("Backspace", "Backspace", 8, None),
        "delete" | "del" => named("Delete", "Delete", 46, None),
        "space" => named(" ", "Space", 32, Some(" ")),
        "up" | "arrowup" => named("ArrowUp", "ArrowUp", 38, None),
        "down" | "arrowdown" => named("ArrowDown", "ArrowDown", 40, None),
        "left" | "arrowleft" => named("ArrowLeft", "ArrowLeft", 37, None),
        "right" | "arrowright" => named("ArrowRight", "ArrowRight", 39, None),
        "home" => named("Home", "Home", 36, None),
        "end" => named("End", "End", 35, None),
        "pageup" => named("PageUp", "PageUp", 33, None),
        "pagedown" => named("PageDown", "PageDown", 34, None),
        _ => {
            let c = k.chars().next().unwrap_or(' ');
            let code = if c.is_ascii_alphabetic() {
                format!("Key{}", c.to_ascii_uppercase())
            } else if c.is_ascii_digit() {
                format!("Digit{c}")
            } else {
                String::new()
            };
            (k.to_string(), code, c.to_ascii_uppercase() as i64, Some(k.to_string()))
        }
    }
}
