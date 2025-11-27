// src/base_cli.rs

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "testkit",
    author = "APIToolkit. <hello@apitoolkit.io>",
    version = "1.0",
    about = "Manually and Automated testing starting with APIs and Browser automation",
    long_about = None
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Sets the log level (trace, debug, info, warn, error)
    #[arg(short, long, global = true, default_value = "info")]
    pub log_level: String,

    /// Optional filter to only run tests whose title contains this substring.
    #[arg(short = 'q', long, global = true)]
    pub filter: Option<String>,

    /// Output format: plain or json (for CI systems)
    #[arg(short, long, global = true, default_value = "plain")]
    pub output: String,

    /// Enable verbose mode to show curl representation of requests and responses
    #[arg(short, long, global = true)]
    pub verbose: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Run tests from a YAML test configuration file.
    Test {
        /// Path to the YAML test configuration file.
        #[arg(short, long)]
        file: Option<PathBuf>,
    },
    /// Create a new boilerplate test file.
    New {
        /// Path where the boilerplate file should be created (default: boilerplate_test.yaml).
        #[arg(short, long)]
        file: Option<PathBuf>,
        /// Type of test file to create: "api", "browser", or "both" (default: both).
        #[arg(short, long, default_value = "both")]
        test_type: String,
    },
    /// Run the application mode (not implemented yet).
    App {},
}
