// src/base_browser.rs

use anyhow::Result;
use chromiumoxide::browser::{Browser, BrowserConfig, HeadlessMode};
use chromiumoxide::page::ScreenshotParams;
use futures_util::stream::StreamExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// Define the supported browser actions.
#[derive(Debug, Serialize, Deserialize)]
pub enum BrowserAction {
    /// Navigate to a URL.
    Navigate { url: String },
    /// Click an element specified by a CSS selector.
    Click { selector: String },
    /// Fill out form fields and then click the submit element.
    FillAndSubmit {
        fields: HashMap<String, String>,
        submit_selector: String,
    },
}

// A browser test item combines an optional title with a browser action.
#[derive(Debug, Serialize, Deserialize)]
pub struct BrowserTestItem {
    pub title: Option<String>,
    pub browser: BrowserAction,
}

// Import the DSL browser configuration from base_request.
use crate::base_request::BrowserTestConfig;

impl BrowserTestItem {
    /// Converts a DSL browser configuration (BrowserTestConfig) into a BrowserTestItem.
    pub fn from_config(title: Option<String>, config: &BrowserTestConfig) -> Self {
        let action = match config.action.as_str() {
            "navigate" => BrowserAction::Navigate {
                url: config.url.clone().unwrap_or_default(),
            },
            "click" => BrowserAction::Click {
                selector: config.selector.clone().unwrap_or_default(),
            },
            "fillAndSubmit" => BrowserAction::FillAndSubmit {
                fields: config.fields.clone().unwrap_or_default(),
                submit_selector: config.submit_selector.clone().unwrap_or_default(),
            },
            _ => BrowserAction::Navigate { url: "".into() },
        };
        BrowserTestItem {
            title,
            browser: action,
        }
    }
}

/// Runs the browser action defined by the BrowserTestItem.
pub async fn run_browser_action(item: BrowserTestItem) -> Result<()> {
    log::info!("Running browser test: {:?}", item);

    let (mut browser, mut handler) = Browser::launch(
        BrowserConfig::builder()
            .headless_mode(HeadlessMode::True)
            .build()
            .map_err(|e| anyhow::anyhow!(e))?,
    )
    .await?;

    // Process browser events in a spawned task.
    tokio::spawn(async move {
        while let Some(event) = handler.next().await {
            log::debug!("Browser event: {:?}", event);
        }
    });

    let page = browser.new_page("about:blank").await?;

    match item.browser {
        BrowserAction::Navigate { url } => {
            page.goto(&url).await?;
            page.wait_for_navigation().await?;
        }
        BrowserAction::Click { selector } => {
            let element = page.find_element(&selector).await?;
            element.click().await?;
        }
        BrowserAction::FillAndSubmit {
            fields,
            submit_selector,
        } => {
            for (field_selector, value) in fields {
                let element = page.find_element(&field_selector).await?;
                element.type_str(&value).await?;
            }
            let submit_element = page.find_element(&submit_selector).await?;
            submit_element.click().await?;
            page.wait_for_navigation().await?;
        }
    }

    let screenshot = page.screenshot(ScreenshotParams::default()).await?;
    log::info!("Screenshot taken ({} bytes)", screenshot.len());

    page.close().await?;
    browser.close().await?;
    Ok(())
}
