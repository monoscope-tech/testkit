//! Terminal surface (spec §5.3): one-shot `exec` and long-lived PTY sessions with a vt100 screen.
use anyhow::{anyhow, Result};
use portable_pty::{native_pty_system, Child, CommandBuilder, MasterPty, PtySize};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Strips ANSI escape sequences.
///
/// ```
/// assert_eq!(testkit::term::strip_ansi("\x1b[31mred\x1b[0m ok"), "red ok");
/// ```
pub fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\x1b' {
            match it.peek() {
                Some('[') => {
                    it.next();
                    while let Some(&n) = it.peek() {
                        it.next();
                        if ('@'..='~').contains(&n) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    it.next();
                    while let Some(n) = it.next() {
                        if n == '\x07' || n == '\x1b' {
                            if n == '\x1b' {
                                it.next();
                            }
                            break;
                        }
                    }
                }
                _ => {
                    it.next();
                }
            }
        } else if c != '\r' {
            out.push(c)
        }
    }
    out
}

fn shell(cmd: &str) -> (String, Vec<String>) {
    if cfg!(windows) {
        ("cmd".into(), vec!["/C".into(), cmd.into()])
    } else {
        ("sh".into(), vec!["-c".into(), cmd.into()])
    }
}

/// Runs a command to completion: `{exit, stdout, stderr, duration, rss}`.
pub async fn exec(
    cmd: &str,
    cwd: Option<&str>,
    env: &[(String, String)],
    timeout: Duration,
) -> Result<Value> {
    let (sh, args) = shell(cmd);
    let mut c = tokio::process::Command::new(sh);
    c.args(args)
        .kill_on_drop(true)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    if let Some(d) = cwd {
        c.current_dir(d);
    }
    c.envs(env.iter().cloned());
    let t = Instant::now();
    let mut child = c.spawn()?;
    // Read the pipes concurrently; don't wait for EOF after exit, since background
    // grandchildren (dev servers, browser helpers) may keep them open forever.
    let drain = |mut r: Box<dyn tokio::io::AsyncRead + Unpin + Send>| {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let b = buf.clone();
        let h = tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut chunk = [0u8; 8192];
            while let Ok(n) = r.read(&mut chunk).await {
                if n == 0 {
                    break;
                }
                b.lock().unwrap().extend_from_slice(&chunk[..n]);
            }
        });
        (buf, h)
    };
    let (out_buf, out_h) = drain(Box::new(child.stdout.take().unwrap()));
    let (err_buf, err_h) = drain(Box::new(child.stderr.take().unwrap()));
    let status = tokio::time::timeout(timeout, child.wait()).await.map_err(|_| {
        anyhow!("E_TIMEOUT `{cmd}` did not finish within {}ms", timeout.as_millis())
    })??;
    for h in [out_h, err_h] {
        tokio::time::timeout(Duration::from_millis(500), h).await.ok();
    }
    let raw = String::from_utf8_lossy(&out_buf.lock().unwrap()).to_string();
    let err = String::from_utf8_lossy(&err_buf.lock().unwrap()).to_string();
    Ok(json!({
        "exit": status.code().unwrap_or(-1), "stdout": strip_ansi(&raw).trim_end(), "stderr": strip_ansi(&err).trim_end(),
        "raw": raw, "duration": t.elapsed().as_millis() as u64, "rss": child_rss(), "command": cmd,
    }))
}

#[cfg(unix)]
fn child_rss() -> Value {
    let mut u: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_CHILDREN, &mut u) };
    let kb = if cfg!(target_os = "macos") { u.ru_maxrss / 1024 } else { u.ru_maxrss };
    json!(kb * 1024)
}
#[cfg(not(unix))]
fn child_rss() -> Value {
    Value::Null
}

#[derive(Default)]
pub struct Buf {
    pub output: String,
    pub seq_marks: Vec<usize>,
    pub exit: Option<i64>,
    pub last_out: Option<Instant>,
}

pub struct Pty {
    pub cmd: String,
    pub parser: Arc<Mutex<vt100::Parser>>,
    pub buf: Arc<Mutex<Buf>>,
    pub prompt: Option<regex::Regex>,
    pub started: Instant,
    pub cast: Arc<Mutex<Vec<(f64, String)>>>,
    writer: Box<dyn Write + Send>,
    child: Arc<Mutex<Box<dyn Child + Send + Sync>>>,
    master: Box<dyn MasterPty + Send>,
}

impl Pty {
    pub fn spawn(
        cmd: &str,
        cwd: Option<&str>,
        env: &[(String, String)],
        size: (u16, u16),
        prompt: Option<&str>,
    ) -> Result<Self> {
        let pty = native_pty_system().openpty(PtySize {
            rows: size.1,
            cols: size.0,
            pixel_width: 0,
            pixel_height: 0,
        })?;
        let (sh, args) = shell(cmd);
        let mut c = CommandBuilder::new(sh);
        c.args(args);
        c.cwd(cwd.map(String::from).unwrap_or_else(|| {
            std::env::current_dir().map(|p| p.to_string_lossy().to_string()).unwrap_or_default()
        }));
        c.env("TERM", "xterm-256color");
        env.iter().for_each(|(k, v)| c.env(k, v));
        let child = Arc::new(Mutex::new(pty.slave.spawn_command(c)?));
        drop(pty.slave);
        let parser = Arc::new(Mutex::new(vt100::Parser::new(size.1, size.0, 2000)));
        let buf: Arc<Mutex<Buf>> = Arc::default();
        let cast: Arc<Mutex<Vec<(f64, String)>>> = Arc::default();
        let mut reader = pty.master.try_clone_reader()?;
        let (p, b, ch, ca) = (parser.clone(), buf.clone(), child.clone(), cast.clone());
        let started = Instant::now();
        std::thread::spawn(move || {
            let mut chunk = [0u8; 8192];
            loop {
                match reader.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let s = String::from_utf8_lossy(&chunk[..n]).to_string();
                        p.lock().unwrap().process(&chunk[..n]);
                        ca.lock().unwrap().push((started.elapsed().as_secs_f64(), s.clone()));
                        let mut b = b.lock().unwrap();
                        b.output.push_str(&strip_ansi(&s));
                        b.last_out = Some(Instant::now());
                    }
                }
            }
            let code = ch.lock().unwrap().wait().map(|s| s.exit_code() as i64).unwrap_or(-1);
            b.lock().unwrap().exit = Some(code);
        });
        let writer = pty.master.take_writer()?;
        let prompt = prompt.map(regex::Regex::new).transpose()?;
        Ok(Pty {
            cmd: cmd.into(),
            parser,
            buf,
            prompt,
            started,
            cast,
            writer,
            child,
            master: pty.master,
        })
    }
    pub fn write(&mut self, s: &str) -> Result<()> {
        self.cast.lock().unwrap().push((self.started.elapsed().as_secs_f64(), String::new()));
        self.writer.write_all(s.as_bytes())?;
        self.writer.flush()?;
        Ok(())
    }
    pub fn key(&mut self, combo: &str) -> Result<()> {
        let k = combo.to_lowercase();
        let seq = match k.as_str() {
            "enter" | "return" => "\r".to_string(),
            "tab" => "\t".into(),
            "escape" | "esc" => "\x1b".into(),
            "backspace" => "\x7f".into(),
            "space" => " ".into(),
            "up" | "arrowup" => "\x1b[A".into(),
            "down" | "arrowdown" => "\x1b[B".into(),
            "right" | "arrowright" => "\x1b[C".into(),
            "left" | "arrowleft" => "\x1b[D".into(),
            "home" => "\x1b[H".into(),
            "end" => "\x1b[F".into(),
            "delete" | "del" => "\x1b[3~".into(),
            "pageup" => "\x1b[5~".into(),
            "pagedown" => "\x1b[6~".into(),
            k if k.starts_with("ctrl+") && k.len() == 6 => {
                ((k.as_bytes()[5].to_ascii_lowercase() - b'a' + 1) as char).to_string()
            }
            k if k.starts_with("alt+") => format!("\x1b{}", &combo[4..]),
            _ => combo.to_string(),
        };
        self.write(&seq)
    }
    pub fn mark(&self) -> usize {
        self.buf.lock().unwrap().output.len()
    }
    pub fn output_since(&self, at: usize) -> String {
        let b = self.buf.lock().unwrap();
        b.output.get(at..).unwrap_or("").to_string()
    }
    pub fn screen(&self) -> String {
        let p = self.parser.lock().unwrap();
        p.screen()
            .contents()
            .lines()
            .map(|l| l.trim_end().to_string())
            .collect::<Vec<_>>()
            .join("\n")
            .trim_end()
            .to_string()
    }
    pub fn snapshot(&self, styles: bool) -> String {
        let p = self.parser.lock().unwrap();
        let s = p.screen();
        let (rows, cols) = s.size();
        let (cr, cc) = s.cursor_position();
        let mut out = vec![];
        for r in 0..rows {
            let mut line = String::new();
            let mut style = String::new();
            for c in 0..cols {
                let Some(cell) = s.cell(r, c) else { continue };
                // `--styles` annotates runs: `[red]ERROR[/] plain`, `[bold]Title[/]`
                let st = match (cell.fgcolor(), cell.bold()) {
                    _ if !styles || cell.contents().trim().is_empty() => String::new(),
                    (vt100::Color::Default, true) => "bold".into(),
                    (col, b) if col != vt100::Color::Default => {
                        format!("{}{}", color_name(col), if b { " bold" } else { "" })
                    }
                    _ => String::new(),
                };
                if st != style {
                    if !style.is_empty() {
                        line.push_str("[/]")
                    }
                    if !st.is_empty() {
                        line.push_str(&format!("[{st}]"))
                    }
                    style = st;
                }
                line.push_str(&cell.contents());
            }
            if !style.is_empty() {
                line.push_str("[/]")
            }
            let line = line.trim_end().to_string();
            out.push(if r == cr { format!("{line}  ⟵ cursor col {}", cc + 1) } else { line });
        }
        while out.last().is_some_and(|l| l.is_empty()) {
            out.pop();
        }
        out.join("\n")
    }
    /// Text elements matching `pred` on the visible screen, with their style.
    pub fn find(&self, pred: &dyn Fn(&str) -> bool) -> Vec<Value> {
        let p = self.parser.lock().unwrap();
        let s = p.screen();
        let (rows, cols) = s.size();
        let mut found = vec![];
        for r in 0..rows {
            let line: String = (0..cols)
                .filter_map(|c| {
                    s.cell(r, c).map(|x| {
                        if x.contents().is_empty() {
                            " ".to_string()
                        } else {
                            x.contents()
                        }
                    })
                })
                .collect();
            if pred(line.trim_end()) {
                let col = line.find(|c: char| !c.is_whitespace()).unwrap_or(0) as u16;
                let cell = s.cell(r, col);
                let color = cell.map(|c| color_name(c.fgcolor())).unwrap_or("default".into());
                found.push(json!({"__el": true, "text": line.trim(), "row": r + 1, "visible": true, "color": color, "bold": cell.is_some_and(|c| c.bold()),
                    "styles": {"color": color}}));
            }
        }
        found
    }
    pub fn line(&self, n: i64) -> Value {
        let screen = self.screen();
        let lines: Vec<&str> = screen.lines().collect();
        let i = if n < 0 { lines.len() as i64 + n } else { n - 1 };
        lines
            .get(i.max(0) as usize)
            .map(|l| json!({"__el": true, "text": l.trim_end(), "row": i + 1, "visible": true}))
            .unwrap_or(Value::Null)
    }
    pub fn cursor(&self) -> Value {
        let (r, c) = self.parser.lock().unwrap().screen().cursor_position();
        json!({"row": r + 1, "col": c + 1})
    }
    pub fn exit(&self) -> Option<i64> {
        if let Some(e) = self.buf.lock().unwrap().exit {
            return Some(e);
        }
        self.child.lock().unwrap().try_wait().ok().flatten().map(|s| s.exit_code() as i64)
    }
    pub fn resize(&mut self, cols: u16, rows: u16) -> Result<()> {
        self.master.resize(PtySize { rows, cols, pixel_width: 0, pixel_height: 0 })?;
        self.parser.lock().unwrap().set_size(rows, cols);
        Ok(())
    }
    #[cfg_attr(not(unix), allow(unused_variables))]
    pub fn signal(&mut self, sig: &str) -> Result<()> {
        #[cfg(unix)]
        if let Some(pid) = self.child.lock().unwrap().process_id() {
            let n = match sig.to_uppercase().trim_start_matches("SIG") {
                "INT" => libc::SIGINT,
                "KILL" => libc::SIGKILL,
                "HUP" => libc::SIGHUP,
                "QUIT" => libc::SIGQUIT,
                "USR1" => libc::SIGUSR1,
                _ => libc::SIGTERM,
            };
            unsafe {
                libc::kill(-(pid as i32), n);
                libc::kill(pid as i32, n);
            }
            return Ok(());
        }
        self.child.lock().unwrap().kill()?;
        Ok(())
    }
    pub fn quiet_for(&self) -> Duration {
        self.buf.lock().unwrap().last_out.map(|t| t.elapsed()).unwrap_or(self.started.elapsed())
    }
    pub fn state(&self) -> Value {
        json!({"screen": self.screen(), "output": self.buf.lock().unwrap().output.clone(), "exit": self.exit(), "cursor": self.cursor(), "command": self.cmd})
    }
}

impl Drop for Pty {
    fn drop(&mut self) {
        if self.exit().is_none() {
            self.child.lock().unwrap().kill().ok();
        }
    }
}

fn color_name(c: vt100::Color) -> String {
    match c {
        vt100::Color::Default => "default".into(),
        vt100::Color::Idx(i) => {
            ["black", "red", "green", "yellow", "blue", "magenta", "cyan", "white"]
                .get((i % 8) as usize)
                .unwrap_or(&"default")
                .to_string()
        }
        vt100::Color::Rgb(r, g, b) => format!("rgb({r},{g},{b})"),
    }
}
