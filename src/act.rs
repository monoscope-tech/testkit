//! Natural-language `act:` — an instruction becomes concrete steps, resolved by Claude
//! (or by `TESTKIT_ACT_CMD`), run, cached in `.testkit/act/` and recorded as the concrete steps.
use crate::item::{parse_yaml, Item};
use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};
use std::io::Write;
use std::process::{Command, Stdio};

const RULES: &str =
    "You turn one instruction into concrete testkit steps for the app's current state.
Reply with only a YAML list of steps: no prose, no code fences.
- Use locators that appear in the snapshot (`button \"Save\"`, `field \"Email\"`), never `@e` refs.
- Use `${name}` for the listed variables and `${env.NAME}` for secrets you were not given.
- Never use `act`, `claim`, `meta`, `call`, `exec` or `spawn`.
- End with an `expect:` that proves the instruction took effect, when the outcome is visible.
- If a previous attempt failed, fix it using the error and the new snapshot.";

/// Parses a resolver reply into steps, tolerating code fences. Shell steps need `shell`
/// (`policy.exec: allow`), since the model wrote them.
///
/// ```
/// use testkit::act::steps;
/// let s = steps("```yaml\n- click: button \"Save\"\n- expect: alert \"Saved\" is visible\n```", false).unwrap();
/// assert_eq!(s.len(), 2);
/// assert!(steps("- act: do it again", false).unwrap_err().to_string().contains("cannot use `act`"));
/// assert!(steps("- exec: rm -rf /", false).is_err());
/// assert!(steps("- exec: ls", true).is_ok());
/// assert!(steps("", false).is_err());
/// ```
pub fn steps(reply: &str, shell: bool) -> Result<Vec<Item>> {
    let y = reply.trim().trim_start_matches("```yaml").trim_start_matches("```");
    let items = parse_yaml(y.trim_end_matches("```"))?;
    let banned: &[&str] = if shell {
        &["act", "claim", "meta", "call"]
    } else {
        &["act", "claim", "meta", "call", "exec", "spawn"]
    };
    if let Some(i) = items.iter().find(|i| banned.contains(&i.verb.as_str())) {
        let hint = if shell { "" } else { " (set policy.exec: allow to permit shell steps)" };
        bail!("resolved steps cannot use `{}`{hint}", i.verb)
    }
    if items.is_empty() {
        bail!("the resolver returned no steps")
    }
    Ok(items)
}

pub async fn resolve(goal: &str, context: &str, error: Option<&str>) -> Result<String> {
    if let Ok(cmd) = std::env::var("TESTKIT_ACT_CMD") {
        let q = json!({"goal": goal, "context": context, "error": error, "rules": RULES});
        let mut c = Command::new("sh")
            .args(["-c", &cmd])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
        c.stdin.take().unwrap().write_all(q.to_string().as_bytes())?;
        let o = c.wait_with_output()?;
        if !o.status.success() {
            bail!("TESTKIT_ACT_CMD `{cmd}` exited with {}", o.status)
        }
        return Ok(String::from_utf8_lossy(&o.stdout).into());
    }
    let mut prompt = format!("Instruction: {goal}\n\nCurrent state:\n{context}");
    if let Some(e) = error {
        prompt.push_str(&format!("\n\nThe previous attempt failed:\n{e}"))
    }
    claude(&format!("{RULES}\n\n{}", crate::mcp::GRAMMAR), &prompt).await
}

async fn claude(system: &str, prompt: &str) -> Result<String> {
    let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    let model = env("TESTKIT_ACT_MODEL").unwrap_or_else(|| "claude-opus-5".into());
    let base = env("ANTHROPIC_BASE_URL").unwrap_or_else(|| "https://api.anthropic.com".into());
    let mut betas = vec![];
    let mut req = reqwest::Client::new()
        .post(format!("{}/v1/messages", base.trim_end_matches('/')))
        .header("anthropic-version", "2023-06-01")
        .timeout(std::time::Duration::from_secs(300));
    req = match (env("ANTHROPIC_API_KEY"), env("ANTHROPIC_AUTH_TOKEN")) {
        (Some(k), _) => req.header("x-api-key", k),
        (_, Some(t)) => {
            betas.push("oauth-2025-04-20");
            req.bearer_auth(t)
        }
        _ => bail!("E_ACT needs ANTHROPIC_API_KEY (or TESTKIT_ACT_CMD for another resolver)"),
    };
    let mut body = json!({
        "model": model, "max_tokens": 16000, "thinking": {"type": "adaptive"},
        "system": system, "messages": [{"role": "user", "content": prompt}],
    });
    if model.starts_with("claude-opus-5") {
        betas.push("server-side-fallback-2026-07-01");
        body["fallbacks"] = json!("default");
    }
    if !betas.is_empty() {
        req = req.header("anthropic-beta", betas.join(","))
    }
    let resp = req.json(&body).send().await?;
    let status = resp.status();
    let v: Value = resp.json().await.map_err(|e| anyhow!("E_ACT bad response ({status}): {e}"))?;
    if !status.is_success() {
        bail!(
            "E_ACT Claude API {status}: {}",
            v["error"]["message"].as_str().unwrap_or(&v.to_string())
        )
    }
    if v["stop_reason"] == "refusal" {
        bail!("E_ACT the model declined to resolve this instruction")
    }
    Ok(v["content"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|b| b["type"] == "text")
        .filter_map(|b| b["text"].as_str())
        .collect())
}
