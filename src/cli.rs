//! Command line (spec §12): file runs, per-step verbs against a session daemon, discovery, proofs and CI.
use clap::{Args as ClapArgs, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "testkit",
    version,
    about = "Operate, test and prove apps (API · browser · terminal) with one small grammar.",
    after_help = "Steps are lines of the grammar: `testkit click 'button \"Save\"'`, `testkit expect 'no console errors'`.\nRun `testkit grammar` for the cheat sheet."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Cmd>,
    /// Log level (trace, debug, info, warn, error)
    #[arg(short, long, global = true, default_value = "warn")]
    pub log_level: String,
    /// Output format: plain, json, junit, tap or github
    #[arg(short, long, global = true, default_value = "plain")]
    pub output: String,
    #[command(flatten)]
    pub opts: RunOpts,
}

#[derive(ClapArgs, Clone, Default)]
pub struct RunOpts {
    /// Session name for CLI steps (default: TESTKIT_SESSION or "default")
    #[arg(long, global = true, env = "TESTKIT_SESSION", default_value = "default")]
    pub session: String,
    /// Base URL for relative paths
    #[arg(long, global = true)]
    pub base_url: Option<String>,
    /// Show the browser window
    #[arg(long, global = true)]
    pub headed: bool,
    /// Append successful steps to this .tk.yaml file
    #[arg(long, global = true)]
    pub record: Option<PathBuf>,
    /// Value for fill/select/type (avoids shell quoting)
    #[arg(long, global = true)]
    pub value: Option<String>,
    /// Use a config profile from testkit.yaml (ci is chosen automatically when CI=true)
    #[arg(long, global = true)]
    pub profile: Option<String>,
}

#[derive(Subcommand)]
pub enum Cmd {
    /// Run test files (default: every *.tk.yaml under the current directory)
    Test {
        files: Vec<PathBuf>,
        #[arg(short, long)]
        file: Option<PathBuf>,
        /// Only run files whose path contains this text
        #[arg(short = 'q', long)]
        filter: Option<String>,
        /// Refresh golden files instead of comparing
        #[arg(long)]
        update_golden: bool,
        /// Retry failing files N times; a pass after a retry is reported as flaky
        #[arg(long, default_value_t = 0)]
        retries: u32,
        #[arg(long)]
        fail_on_flaky: bool,
        /// Run every file N times and report per-step pass rates
        #[arg(long, default_value_t = 1)]
        repeat: u32,
        /// Files to run in parallel
        #[arg(short = 'j', long, default_value_t = 1)]
        jobs: usize,
        /// Run shard i of n, e.g. 2/4
        #[arg(long)]
        shard: Option<String>,
        /// Multiply every default timeout
        #[arg(long, default_value_t = 1.0)]
        timeout_scale: f64,
        /// Print every step's report
        #[arg(short, long)]
        verbose: bool,
    },
    /// Run a file and write a proof receipt (never retries)
    Prove {
        file: PathBuf,
        /// Skip video/GIF capture
        #[arg(long)]
        no_video: bool,
        #[arg(long)]
        open: bool,
        /// Sign the receipt's hash chain with this SSH private key (ssh-keygen -Y sign)
        #[arg(long, env = "TESTKIT_SIGN_KEY")]
        sign: Option<PathBuf>,
    },
    /// Show or verify a receipt (latest when no id)
    Receipt {
        id: Option<String>,
        #[arg(long)]
        md: bool,
        #[arg(long)]
        verify: bool,
        #[arg(long)]
        open: bool,
    },
    /// Manage CLI sessions (the background daemon that keeps browsers and terminals alive)
    Session {
        #[command(subcommand)]
        action: SessionCmd,
    },
    /// Run YAML items from a file or stdin (`-`) in the current session
    Run { file: PathBuf },
    /// Interactive prompt: one step per line, `:help` for commands
    Repl,
    /// Print the page (or terminal) as an aria snapshot whose lines are locators (--all: every node; terminal colors)
    Snapshot {
        locator: Vec<String>,
        #[arg(long)]
        all: bool,
    },
    /// Find elements by text and print their stable locators
    Find { text: Vec<String> },
    /// Show how an expression parses and what it resolves to
    Explain { expr: Vec<String> },
    /// Print console, network or terminal output since the last step (or --all)
    Observe {
        kind: String,
        #[arg(long)]
        all: bool,
    },
    /// Suggest assertions from what the last step changed
    Suggest {
        /// Record the suggestions with these numbers (e.g. 1,3)
        #[arg(long)]
        accept: Option<String>,
    },
    /// Start a claim in the session (`testkit claim end` writes the receipt)
    Claim { title: Vec<String> },
    /// Print the grammar cheat sheet
    Grammar,
    /// Write the grammar cheat sheet for agents (AGENTS.md / CLAUDE.md)
    Init {
        #[arg(long)]
        agents: bool,
    },
    /// Run the MCP server on stdio (tools: step, snapshot, find, observe, claim, receipt, session)
    Mcp,
    /// Record perf baselines by running a file
    Baseline { action: String, file: PathBuf },
    /// Download a pinned Chrome for Testing into ~/.cache/testkit
    Install {
        what: String,
        /// Print what would be downloaded and where, without downloading
        #[arg(long)]
        dry_run: bool,
    },
    /// Rewrite legacy syntax ({{var}}, $.env.X) in a file
    Migrate { file: PathBuf },
    /// Create a starter test file
    New {
        #[arg(short, long)]
        file: Option<PathBuf>,
        #[arg(short, long, default_value = "both")]
        test_type: String,
    },
    #[command(hide = true, name = "__daemon")]
    Daemon {
        #[arg(long)]
        attach: Option<String>,
        #[arg(long, default_value = "30m")]
        idle: String,
    },
    /// Any step verb: visit, click, fill, expect, exec, spawn, enter, press, wait, GET, …
    #[command(external_subcommand)]
    Step(Vec<String>),
}

#[derive(Subcommand)]
pub enum SessionCmd {
    Start {
        #[arg(long)]
        url: Option<String>,
        #[arg(long, default_value = "30m")]
        idle: String,
    },
    /// Drive an already-running Chrome (ws://… or http://localhost:9222)
    Attach {
        url: String,
    },
    Stop,
    Status,
    List,
}
