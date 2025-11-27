// src/main.rs

mod base_browser;
mod base_cli;
mod base_request;

use anyhow::Result;
use base_cli::{Cli, Commands};
use base_request::TestContext;
use clap::Parser;
use dotenv::dotenv;
use log::LevelFilter;
use std::{
    fs,
    path::{Path, PathBuf},
    str::FromStr, // For LevelFilter::from_str
    sync::Arc,
};
use walkdir::WalkDir;

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    let cli_instance = Cli::parse();

    let mut builder = env_logger::Builder::from_default_env();
    builder
        .format_timestamp(None)
        .format_target(true)
        .filter_level(LevelFilter::from_str(&cli_instance.log_level).unwrap_or(LevelFilter::Info))
        .init();

    match &cli_instance.command {
        None | Some(Commands::App {}) => {
            println!("App mode not implemented. Use the 'test' or 'new' command.");
        }
        Some(Commands::Test { file }) => {
            cli_run_test(
                file.clone(),
                &cli_instance.filter,
                &cli_instance.output,
                cli_instance.verbose,
            )
            .await?;
        }
        Some(Commands::New { file, test_type }) => {
            create_boilerplate(file.clone(), test_type)?;
        }
    }
    Ok(())
}

async fn cli_run_test(
    file_op: Option<PathBuf>,
    _filter: &Option<String>,
    output: &str,
    verbose: bool,
) -> Result<()> {
    if let Some(file) = file_op {
        let content = fs::read_to_string(file.clone())?;
        let ctx = TestContext {
            file: Arc::new(file.to_str().unwrap().to_string()),
            file_source: Arc::new(content.clone()),
            should_log: true,
            verbose,
            ..Default::default()
        };
        let results = base_request::run(ctx, content).await?;
        output_results(results, output);
    } else {
        let files = find_tk_yaml_files(Path::new("."));
        for file in files {
            let content = fs::read_to_string(file.clone())?;
            let ctx = TestContext {
                file: Arc::new(file.to_str().unwrap().to_string()),
                file_source: Arc::new(content.clone()),
                should_log: true,
                verbose,
                ..Default::default()
            };
            let results = base_request::run(ctx, content).await?;
            output_results(results, output);
        }
    }
    Ok(())
}

fn create_boilerplate(file_op: Option<PathBuf>, test_type: &str) -> Result<()> {
    let path = match file_op {
        Some(path) => path,
        None => PathBuf::from("boilerplate_test.yaml"),
    };

    let content = match test_type {
        "api" => {
            r#"
- title: "API: GET Example"
  request:
    GET: "https://jsonplaceholder.typicode.com/posts/1"
  asserts:
    - ok: "$.resp.status == 200"
"#
        }
        "browser" => {
            r#"
- title: "Browser: Open Home Page"
  browser:
    action: "navigate"
    url: "https://example.com"
"#
        }
        _ => {
            r#"
- title: "API: GET Example"
  request:
    GET: "https://jsonplaceholder.typicode.com/posts/1"
  asserts:
    - ok: "$.resp.status == 200"

- title: "Browser: Open Home Page"
  browser:
    action: "navigate"
    url: "https://example.com"
"#
        }
    };

    fs::write(&path, content.trim_start())?;
    println!("Boilerplate test file created at: {:?}", path);
    Ok(())
}

fn find_tk_yaml_files(dir: &Path) -> Vec<PathBuf> {
    let mut result = Vec::new();
    for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() {
            if let Some(extension) = entry.path().extension() {
                if extension == "yaml"
                    && entry
                        .path()
                        .file_stem()
                        .and_then(|n| n.to_str())
                        .unwrap_or("")
                        .contains(".tk")
                {
                    result.push(entry.path().to_path_buf());
                }
            }
        }
    }
    result
}

fn output_results(results: Vec<base_request::RequestResult>, output: &str) {
    match output {
        "json" => {
            if let Ok(colored_str) = colored_json::to_colored_json_auto(&results) {
                println!("{}", colored_str);
            } else if let Ok(json) = serde_json::to_string_pretty(&results) {
                println!("{}", json);
            }
        }
        _ => {
            for res in results {
                println!("{:#?}", res);
            }
        }
    }
}
