use anyhow::{anyhow, bail, Result};
use clap::Parser;
use serde_json::{json, Value};
use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Instant;
use testkit::cli::{Cli, Cmd, RunOpts, SessionCmd};
use testkit::item::scalar_text;
use testkit::runner::{Config, Runner, StepResult};
use testkit::{receipt, report, session};

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    let cli = Cli::parse();
    tokio::spawn(async {
        #[cfg(unix)]
        {
            let mut term =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("signal");
            tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} }
        }
        #[cfg(not(unix))]
        tokio::signal::ctrl_c().await.ok();
        // Chrome children don't die with us; their profile dirs carry our pid.
        std::process::Command::new("pkill")
            .args(["-f", &format!("testkit-chrome-{}-", std::process::id())])
            .status()
            .ok();
        std::process::exit(130);
    });
    env_logger::Builder::from_default_env()
        .format_timestamp(None)
        .filter_level(log::LevelFilter::from_str(&cli.log_level).unwrap_or(log::LevelFilter::Warn))
        .filter_module(
            "chromiumoxide",
            if cli.log_level == "trace" {
                log::LevelFilter::Debug
            } else {
                log::LevelFilter::Error
            },
        )
        .init();
    let code = match run(cli).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            2
        }
    };
    std::process::exit(code);
}

/// testkit.yaml + profile (ci when CI=true) + CLI flags.
fn config(o: &RunOpts) -> Config {
    let mut c = Config::default();
    let file: Value = std::fs::read_to_string("testkit.yaml")
        .ok()
        .and_then(|s| serde_yaml::from_str(&s).ok())
        .unwrap_or_default();
    let profile = o.profile.clone().or_else(|| std::env::var("CI").ok().map(|_| "ci".into()));
    let mut layers = vec![file.clone()];
    if let Some(p) = profile {
        layers.push(file["profiles"][p].clone())
    }
    if std::env::var("CI").is_ok() {
        c.deterministic = true
    }
    for l in layers.iter().filter(|l| l.is_object()) {
        if let Some(v) = l["base_url"].as_str() {
            c.base_url = Some(v.into())
        }
        if let Some(v) = l["headed"].as_bool() {
            c.headed = v
        }
        if let Some(v) = l["deterministic"].as_bool() {
            c.deterministic = v
        }
        if let Some(v) = l["timeout"].as_u64() {
            c.action_ms = v * 1000;
            c.expect_ms = v * 1000
        }
        if let Some(v) = l["fail_on"].as_array() {
            c.fail_on = v.iter().map(scalar_text).collect()
        }
        if let Some(v) = l["ignore"].as_array() {
            c.ignore = v.iter().map(scalar_text).collect()
        }
        if let Some(v) = l["secret"].as_array().or(l["secrets"].as_array()) {
            c.secrets = v.iter().map(scalar_text).collect()
        }
    }
    if let Ok(u) = std::env::var("TESTKIT_BASE_URL") {
        c.base_url = Some(u)
    }
    if o.base_url.is_some() {
        c.base_url = o.base_url.clone()
    }
    if o.headed || std::env::var("TESTKIT_HEADED").is_ok() {
        c.headed = true
    }
    c
}

fn find_files(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_entry(|e| {
            !matches!(e.file_name().to_str(), Some("target" | "node_modules" | ".git" | ".testkit"))
        })
        .filter_map(|e| e.ok())
        .map(|e| e.into_path())
        .filter(|p| p.to_string_lossy().ends_with(".tk.yaml"))
        .collect();
    v.sort();
    v
}

fn print_results(results: &[Value], verbose: bool) -> bool {
    let mut ok = true;
    for r in results {
        let r: StepResult = from_value(r);
        ok &= r.ok();
        println!("{}", report::step_text(&r, verbose));
    }
    ok
}
fn from_value(r: &Value) -> StepResult {
    StepResult {
        verb: scalar_text(&r["verb"]),
        text: scalar_text(&r["text"]),
        status: scalar_text(&r["status"]),
        ms: r["ms"].as_u64().unwrap_or(0),
        file: scalar_text(&r["file"]),
        line: r["line"].as_u64().unwrap_or(0) as usize,
        report: r["report"].clone(),
        step_log: scalar_text(&r["step_log"]),
        step_name: r["step_name"].as_str().map(String::from),
        step_error: r["step_error"].as_str().map(String::from),
        it: r["it"].clone(),
        ..Default::default()
    }
}

async fn daemon_args(o: &RunOpts) -> Vec<String> {
    let mut a = vec![];
    if o.headed {
        a.push("--headed".into())
    }
    if let Some(u) = &o.base_url {
        a.extend(["--base-url".into(), u.clone()])
    }
    a
}

/// Sends an operation to the session daemon (starting it if needed) and prints the reply.
async fn session_op(o: &RunOpts, output: &str, mut req: Value) -> Result<i32> {
    session::ensure(&o.session, &daemon_args(o).await).await?;
    if let Some(r) = &o.record {
        req["record"] = json!(std::fs::canonicalize(
            r.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."))
        )
        .unwrap_or_default()
        .join(r.file_name().unwrap_or_default()))
    }
    let reply = session::send(&o.session, &req).await?;
    Ok(show(&reply, output))
}
fn show(reply: &Value, output: &str) -> i32 {
    let ok = reply["ok"] != false;
    if output == "json" {
        println!("{}", serde_json::to_string_pretty(reply).unwrap_or_default());
        return if ok { 0 } else { 1 };
    }
    if let Some(e) = reply["error"].as_str() {
        eprintln!("✗ {e}");
        return 1;
    }
    if let Some(rs) = reply["results"].as_array() {
        print_results(rs, false);
    }
    for n in reply["notes"].as_array().into_iter().flatten() {
        println!("  {}", scalar_text(n))
    }
    for k in ["text", "md"] {
        if let Some(t) = reply[k].as_str() {
            println!("{t}")
        }
    }
    if let Some(f) = reply["found"].as_array() {
        for x in f {
            println!("{}  {}", scalar_text(&x["locator"]), scalar_text(&x["role"]))
        }
        if f.is_empty() {
            println!("nothing found")
        }
    }
    if let Some(s) = reply["suggestions"].as_array() {
        for (i, x) in s.iter().enumerate() {
            println!("{}. expect: {}", i + 1, scalar_text(x))
        }
        if !s.is_empty() {
            println!("record with: testkit suggest --accept 1,2 --record <file>")
        }
    }
    if reply.get("ast").is_some() {
        println!(
            "{}\nresolves: {}\ncurrently: {}",
            scalar_text(&reply["ast"]),
            serde_json::to_string_pretty(&reply["resolves"]).unwrap_or_default(),
            reply["currently"]
        )
    }
    if let Some(v) = reply.get("value") {
        println!("{}", serde_json::to_string_pretty(v).unwrap_or_default())
    }
    if let Some(d) = reply["receipt"].as_str() {
        println!("receipt → {d}/receipt.html")
    }
    if reply.get("pid").is_some() {
        println!(
            "● session pid {} · tabs {} · terminals {} · {} steps",
            reply["pid"], reply["tabs"], reply["terminals"], reply["steps"]
        )
    }
    if ok {
        0
    } else {
        1
    }
}

async fn run(cli: Cli) -> Result<i32> {
    let o = cli.opts.clone();
    let out = cli.output.clone();
    let cmd = cli.command.unwrap_or(Cmd::Test {
        files: vec![],
        file: None,
        filter: None,
        update_golden: false,
        retries: 0,
        fail_on_flaky: false,
        repeat: 1,
        jobs: 1,
        shard: None,
        timeout_scale: 1.0,
        verbose: false,
    });
    match cmd {
        Cmd::Test {
            mut files,
            file,
            filter,
            update_golden,
            retries,
            fail_on_flaky,
            repeat,
            jobs,
            shard,
            timeout_scale,
            verbose,
        } => {
            files.extend(file);
            if files.is_empty() {
                files = find_files(Path::new("."))
            }
            let files: Vec<PathBuf> = files
                .into_iter()
                .flat_map(|f| if f.is_dir() { find_files(&f) } else { vec![f] })
                .collect();
            let mut files: Vec<PathBuf> = files
                .into_iter()
                .filter(|f| {
                    filter.as_ref().is_none_or(|q| f.to_string_lossy().contains(q.as_str()))
                })
                .collect();
            if let Some(s) = shard {
                let (i, n) = s
                    .split_once('/')
                    .and_then(|(i, n)| Some((i.parse::<usize>().ok()?, n.parse::<usize>().ok()?)))
                    .ok_or_else(|| anyhow!("--shard i/n"))?;
                files = files
                    .into_iter()
                    .enumerate()
                    .filter(|(k, _)| k % n == i - 1)
                    .map(|(_, f)| f)
                    .collect();
            }
            if files.is_empty() {
                bail!("no *.tk.yaml files found")
            }
            let mut cfg = config(&o);
            cfg.update_golden = update_golden;
            cfg.should_log = true;
            for x in [&mut cfg.action_ms, &mut cfg.expect_ms, &mut cfg.nav_ms] {
                *x = (*x as f64 * timeout_scale) as u64
            }
            let t0 = Instant::now();
            let live = out == "plain" && jobs <= 1;
            let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(jobs.max(1)));
            let chrome: testkit::runner::SharedChrome = Default::default();
            let mut handles = vec![];
            for f in files.clone() {
                let (cfg, chrome) = (cfg.clone(), chrome.clone());
                let permit = sem.clone().acquire_owned().await?;
                handles.push(tokio::spawn(async move {
                    let _p = permit;
                    let mut all = vec![];
                    let mut claims = vec![];
                    for rep in 0..repeat {
                        let mut attempt = 0;
                        loop {
                            let mut r = Runner::new(cfg.clone());
                            r.share(chrome.clone());
                            if live {
                                println!(
                                    "\n▶ {}{}",
                                    f.display(),
                                    if repeat > 1 {
                                        format!(" (run {})", rep + 1)
                                    } else {
                                        String::new()
                                    }
                                );
                                r.on_step = Some(Box::new(move |s| {
                                    println!("{}", report::step_text(s, verbose))
                                }));
                            }
                            let res = r.run_file(&f).await;
                            r.close().await;
                            let mut res = match res {
                                Ok(x) => x,
                                Err(e) => return Err((f.clone(), e.to_string())),
                            };
                            let failed = res.iter().any(|x| x.status == "fail");
                            if failed && attempt < retries {
                                attempt += 1;
                                if live {
                                    println!("  ↻ retry {attempt}/{retries}")
                                }
                                continue;
                            }
                            if !failed && attempt > 0 {
                                res.iter_mut().for_each(|x| {
                                    if x.status == "pass" {
                                        x.status = "flaky".into()
                                    }
                                })
                            }
                            claims = r.claims.clone();
                            all.extend(res);
                            break;
                        }
                    }
                    Ok((f, all, claims))
                }));
            }
            let mut per_file = vec![];
            let mut code = 0;
            for h in handles {
                match h.await? {
                    Ok((f, rs, cl)) => per_file.push((f.to_string_lossy().to_string(), rs, cl)),
                    Err((f, e)) => {
                        eprintln!("✗ {}: {e}", f.display());
                        code = 2;
                    }
                }
            }
            if let Some(c) = std::sync::Arc::try_unwrap(chrome).ok().and_then(|c| c.into_inner()) {
                c.close().await
            }
            let all: Vec<StepResult> = per_file.iter().flat_map(|x| x.1.clone()).collect();
            let claims: Vec<_> = per_file.iter().flat_map(|x| x.2.clone()).collect();
            match out.as_str() {
                "json" => println!("{}", report::json(&all)),
                "junit" => println!(
                    "{}",
                    report::junit(
                        &per_file.iter().map(|x| (x.0.clone(), x.1.clone())).collect::<Vec<_>>()
                    )
                ),
                "tap" => println!("{}", report::tap(&all)),
                "github" => {
                    print!("{}", report::github(&all, &claims));
                }
                _ => {
                    if !live {
                        for (f, rs, _) in &per_file {
                            println!("\n▶ {f}");
                            for r in rs {
                                println!("{}", report::step_text(r, verbose))
                            }
                        }
                    }
                    if repeat > 1 {
                        println!("\npass rates over {repeat} runs:");
                        let mut seen: Vec<(String, usize, usize)> = vec![];
                        for r in &all {
                            let k = format!("{}:{} {}", r.file, r.line, r.line_text());
                            match seen.iter_mut().find(|x| x.0 == k) {
                                Some(x) => {
                                    x.1 += r.ok() as usize;
                                    x.2 += 1
                                }
                                None => seen.push((k, r.ok() as usize, 1)),
                            }
                        }
                        for (k, p, n) in seen.iter().filter(|x| x.1 < x.2) {
                            println!("  {p}/{n}  {k}")
                        }
                    }
                    println!("\n{}", report::summary(&all, &claims, t0.elapsed().as_millis()));
                }
            }
            let flaky = all.iter().any(|r| r.status == "flaky");
            if flaky && out == "plain" {
                println!("⚠ flaky: some steps passed only after a retry")
            }
            if all.iter().any(|r| r.status == "fail") || (flaky && fail_on_flaky) {
                code = code.max(1)
            }
            Ok(code)
        }
        Cmd::Prove { file, no_video, open } => {
            let mut cfg = config(&o);
            cfg.frames = !no_video;
            let mut r = Runner::new(cfg);
            let t0 = Instant::now();
            r.on_step = Some(Box::new(|s| println!("{}", report::step_text(s, false))));
            r.run_file(&file).await?;
            let dir = receipt::write(&mut r, &file.to_string_lossy(), t0, false).await?;
            r.close().await;
            let md = std::fs::read_to_string(dir.join("receipt.md"))?;
            println!("\n{md}\nreceipt → {}", dir.join("receipt.html").display());
            if open {
                open_path(&dir.join("receipt.html"))
            }
            Ok(if r.claims.iter().all(|c| c.status == "pass") && r.results.iter().all(|x| x.ok()) {
                0
            } else {
                1
            })
        }
        Cmd::Receipt { id, md, verify, open } => {
            let dir = receipt::find(id.as_deref())?;
            if verify {
                let bad = receipt::verify(&dir)?;
                if bad.is_empty() {
                    println!("✓ verified {}: every artifact matches the manifest and the chain is intact", dir.display());
                    return Ok(0);
                }
                println!(
                    "✗ verification failed for {}: changed after the receipt was written:\n  {}",
                    dir.display(),
                    bad.join("\n  ")
                );
                return Ok(1);
            }
            if open {
                open_path(&dir.join("receipt.html"))
            }
            if md || !open {
                println!("{}", std::fs::read_to_string(dir.join("receipt.md"))?)
            }
            Ok(0)
        }
        Cmd::Session { action } => match action {
            SessionCmd::Start { url, idle } => {
                session::ensure(
                    &o.session,
                    &[daemon_args(&o).await, vec!["--idle".into(), idle]].concat(),
                )
                .await?;
                if let Some(u) = url {
                    return session_op(
                        &o,
                        &out,
                        json!({"op": "step", "verb": "visit", "args": [u]}),
                    )
                    .await;
                }
                println!("● session {} ready (.testkit/sessions/{}.sock)", o.session, o.session);
                Ok(0)
            }
            SessionCmd::Attach { url } => {
                session::send(&o.session, &json!({"op": "stop"})).await.ok();
                session::ensure(&o.session, &["--attach".into(), url.clone()]).await?;
                println!("● session {} attached to {url}", o.session);
                Ok(0)
            }
            SessionCmd::Stop => {
                match session::send(&o.session, &json!({"op": "stop"})).await {
                    Ok(_) => println!("● session {} stopped", o.session),
                    Err(_) => println!("no session {}", o.session),
                }
                Ok(0)
            }
            SessionCmd::Status => match session::send(&o.session, &json!({"op": "status"})).await {
                Ok(v) => Ok(show(&v, &out)),
                Err(_) => {
                    println!("no session {} running", o.session);
                    Ok(1)
                }
            },
            SessionCmd::List => {
                for e in std::fs::read_dir(".testkit/sessions").into_iter().flatten().flatten() {
                    let n = e.file_name().to_string_lossy().to_string();
                    if let Some(n) = n.strip_suffix(".sock") {
                        let up = session::send(n, &json!({"op": "status"})).await.is_ok();
                        println!("{} {n}", if up { "●" } else { "○" })
                    }
                }
                Ok(0)
            }
        },
        Cmd::Run { file } => {
            let yaml = if file.as_os_str() == "-" {
                let mut s = String::new();
                std::io::stdin().read_to_string(&mut s)?;
                s
            } else {
                std::fs::read_to_string(&file)?
            };
            session_op(&o, &out, json!({"op": "step", "yaml": yaml})).await
        }
        Cmd::Repl => repl(&o, &out).await,
        Cmd::Snapshot { locator, all } => {
            session_op(
                &o,
                &out,
                json!({"op": "snapshot", "locator": locator.join(" "), "all": all}),
            )
            .await
        }
        Cmd::Find { text } => {
            session_op(&o, &out, json!({"op": "find", "text": text.join(" ")})).await
        }
        Cmd::Explain { expr } => {
            session_op(&o, &out, json!({"op": "explain", "expr": expr.join(" ")})).await
        }
        Cmd::Observe { kind, all } => {
            session_op(&o, &out, json!({"op": "observe", "kind": kind, "all": all})).await
        }
        Cmd::Suggest { accept } => {
            session_op(&o, &out, json!({"op": "suggest", "accept": accept})).await
        }
        Cmd::Claim { title } => {
            session_op(&o, &out, json!({"op": "claim", "title": title.join(" ")})).await
        }
        Cmd::Grammar => {
            print!("{}", testkit::mcp::GRAMMAR);
            Ok(0)
        }
        Cmd::Init { agents } => {
            if !agents {
                bail!("use `testkit init --agents`")
            }
            let target = ["CLAUDE.md", "AGENTS.md"]
                .into_iter()
                .find(|f| Path::new(f).exists())
                .unwrap_or("AGENTS.md");
            let mut f = std::fs::OpenOptions::new().create(true).append(true).open(target)?;
            writeln!(f, "\n<!-- testkit -->\n## Operating and proving this app with testkit\n\nUse `testkit` (CLI or `testkit mcp`) to drive the app, read results semantically and prove features.\n\n{}", testkit::mcp::GRAMMAR)?;
            std::fs::create_dir_all(".claude/skills/testkit")?;
            std::fs::write(".claude/skills/testkit/SKILL.md", format!("---\nname: testkit\ndescription: Operate, test and prove this app (API, browser, terminal) with the testkit grammar and produce receipts.\n---\n\n{}", testkit::mcp::GRAMMAR))?;
            println!("wrote the grammar to {target} and .claude/skills/testkit/SKILL.md");
            Ok(0)
        }
        Cmd::Mcp => {
            testkit::mcp::serve(config(&o)).await?;
            Ok(0)
        }
        Cmd::Baseline { action, file } => {
            if action != "update" {
                bail!("use `testkit baseline update <file>`")
            }
            let mut cfg = config(&o);
            cfg.update_baselines = true;
            let mut r = Runner::new(cfg);
            r.baselines = testkit::runner::load_baselines();
            r.run_file(&file).await?;
            r.close().await;
            std::fs::create_dir_all(".testkit")?;
            std::fs::write(".testkit/baselines.json", serde_json::to_string_pretty(&r.baselines)?)?;
            println!(
                "baselines → .testkit/baselines.json\n{}",
                serde_json::to_string_pretty(&r.baselines)?
            );
            Ok(0)
        }
        Cmd::Install { what } => {
            if what != "chrome" {
                bail!("only `testkit install chrome` is supported")
            }
            install_chrome().await
        }
        Cmd::Migrate { file } => {
            let s = std::fs::read_to_string(&file)?;
            let s2 = regex::Regex::new(r"\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}")?
                .replace_all(&s, "$${$1}")
                .to_string();
            let s2 = regex::Regex::new(r"\$\.env\.([A-Za-z_][A-Za-z0-9_]*)")?
                .replace_all(&s2, "$${env.$1}")
                .to_string();
            std::fs::write(&file, &s2)?;
            println!(
                "migrated {} ({} lines changed)",
                file.display(),
                s.lines().zip(s2.lines()).filter(|(a, b)| a != b).count()
            );
            Ok(0)
        }
        Cmd::New { file, test_type } => {
            let path = file.unwrap_or_else(|| PathBuf::from("example.tk.yaml"));
            let api = "- title: API example\n  GET: https://jsonplaceholder.typicode.com/posts/1\n  asserts:\n    - ok: its status is 200\n    - ok: its json's id is 1\n";
            let browser = "- meta: { base_url: \"https://example.com\" }\n- visit: /\n- expect: heading \"Example Domain\" is visible\n- expect: no console errors\n";
            std::fs::write(
                &path,
                match test_type.as_str() {
                    "api" => api.to_string(),
                    "browser" => browser.to_string(),
                    _ => format!("{browser}{api}"),
                },
            )?;
            println!("created {}", path.display());
            Ok(0)
        }
        Cmd::Daemon { attach, idle } => {
            let mut cfg = config(&o);
            cfg.attach = attach;
            session::serve(&o.session, cfg, session::parse_idle(&idle)).await?;
            Ok(0)
        }
        Cmd::Step(words) => {
            // flags after an external subcommand reach us as plain words
            let (mut o, mut out, mut rest) = (o, out, vec![]);
            let mut it = words.into_iter();
            let verb = it.next().ok_or_else(|| anyhow!("missing verb"))?;
            while let Some(w) = it.next() {
                match w.as_str() {
                    "--record" => o.record = it.next().map(PathBuf::from),
                    "--value" => o.value = it.next(),
                    "--session" => o.session = it.next().unwrap_or(o.session),
                    "--base-url" => o.base_url = it.next(),
                    "--headed" => o.headed = true,
                    "-o" | "--output" => out = it.next().unwrap_or(out),
                    _ => rest.push(w),
                }
            }
            let verb = verb.trim_end_matches(':');
            session_op(
                &o,
                &out,
                json!({"op": "step", "verb": verb, "args": rest, "value": o.value}),
            )
            .await
        }
    }
}

async fn repl(o: &RunOpts, out: &str) -> Result<i32> {
    session::ensure(&o.session, &daemon_args(o).await).await?;
    let mut record = o.record.clone();
    eprintln!("testkit repl · session {} · one step per line (`click button \"Save\"`), :help for commands", o.session);
    let stdin = std::io::stdin();
    loop {
        eprint!("testkit› ");
        std::io::stderr().flush().ok();
        let mut line = String::new();
        if stdin.lock().read_line(&mut line)? == 0 {
            break;
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut words = line.splitn(2, char::is_whitespace);
        let head = words.next().unwrap_or("");
        let rest = words.next().unwrap_or("").trim().to_string();
        let req = match head {
            ":quit" | ":q" | ":exit" => break,
            ":help" => {
                eprintln!(":snapshot [loc] · :find text · :explain expr · :observe console|network|output · :suggest · :claim title|end · :call file · :record file · :undo · :quit");
                continue;
            }
            ":record" => {
                record = Some(PathBuf::from(rest));
                eprintln!("recording → {}", record.as_ref().unwrap().display());
                continue;
            }
            ":undo" => {
                if let Some(p) = &record {
                    let s = std::fs::read_to_string(p).unwrap_or_default();
                    let mut lines: Vec<&str> = s.lines().collect();
                    while lines.last().is_some_and(|l| l.starts_with("  ")) {
                        lines.pop();
                    }
                    let removed = lines.pop();
                    std::fs::write(p, lines.iter().map(|l| format!("{l}\n")).collect::<String>())?;
                    eprintln!("removed: {}", removed.unwrap_or("(nothing)"));
                }
                continue;
            }
            ":snapshot" => json!({"op": "snapshot", "locator": rest}),
            ":find" => json!({"op": "find", "text": rest}),
            ":explain" => json!({"op": "explain", "expr": rest}),
            ":observe" => json!({"op": "observe", "kind": rest}),
            ":suggest" => json!({"op": "suggest"}),
            ":claim" => json!({"op": "claim", "title": rest}),
            ":call" => json!({"op": "step", "verb": "call", "args": [rest]}),
            h => {
                let verb = h.trim_end_matches(':');
                json!({"op": "step", "verb": verb, "args": [rest]})
            }
        };
        let mut req = req;
        if let Some(r) = &record {
            req["record"] = json!(r)
        }
        match session::send(&o.session, &req).await {
            Ok(v) => {
                show(&v, out);
            }
            Err(e) => eprintln!("✗ {e}"),
        }
    }
    if let Some(r) = record {
        eprintln!("recorded steps → {}", r.display())
    }
    Ok(0)
}

fn open_path(p: &Path) {
    let cmd = if cfg!(target_os = "macos") {
        "open"
    } else if cfg!(windows) {
        "explorer"
    } else {
        "xdg-open"
    };
    std::process::Command::new(cmd).arg(p).spawn().ok();
}

async fn install_chrome() -> Result<i32> {
    let platform = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => "mac-arm64",
        ("macos", _) => "mac-x64",
        ("linux", _) => "linux64",
        ("windows", _) => "win64",
        _ => bail!("unsupported platform"),
    };
    let meta: Value = reqwest::get("https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json").await?.json().await?;
    let stable = &meta["channels"]["Stable"];
    let url = stable["downloads"]["chrome"]
        .as_array()
        .and_then(|a| a.iter().find(|d| d["platform"] == platform))
        .and_then(|d| d["url"].as_str())
        .ok_or_else(|| anyhow!("no download for {platform}"))?;
    let dir = PathBuf::from(std::env::var("HOME")?)
        .join(".cache/testkit/chrome")
        .join(scalar_text(&stable["version"]));
    std::fs::create_dir_all(&dir)?;
    println!("downloading Chrome for Testing {} ({platform})…", scalar_text(&stable["version"]));
    let bytes = reqwest::get(url).await?.bytes().await?;
    let zip = dir.join("chrome.zip");
    std::fs::write(&zip, &bytes)?;
    let st = std::process::Command::new("unzip")
        .args(["-q", "-o"])
        .arg(&zip)
        .arg("-d")
        .arg(&dir)
        .status()?;
    if !st.success() {
        bail!("unzip failed")
    }
    std::fs::remove_file(zip).ok();
    println!("installed into {}", dir.display());
    Ok(0)
}
