//! Agent safety policy (spec §13): everything is allowed unless `policy:` is configured.
//!
//! ```
//! use testkit::policy::Policy;
//! let p: Policy = serde_yaml::from_str("origins: [localhost:*, '*.acme.com']\nforbid: ['request \"DELETE /api/**\"', 'exec /rm -rf/']\nmutations: local").unwrap();
//! assert!(p.navigate("http://localhost:3000/login").is_ok());
//! assert!(p.navigate("https://app.acme.com/").is_ok());
//! assert!(p.navigate("https://evil.example/").unwrap_err().to_string().starts_with("E_POLICY"));
//! assert!(p.request("DELETE", "http://localhost:3000/api/orders/1", "").is_err());
//! assert!(p.request("POST", "https://app.acme.com/api/orders", "").is_err());
//! assert!(p.request("POST", "http://127.0.0.1:3000/api/orders", "").is_ok());
//! assert!(p.command("rm -rf /tmp/x").is_err());
//! assert!(p.command("ls").is_ok());
//! ```
use crate::browser::url_match;
use anyhow::{bail, Result};
use serde::Deserialize;

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Policy {
    /// Hosts that `visit:` may open: `localhost:*`, `127.0.0.1:*`, `*.acme.com`.
    pub origins: Option<Vec<String>>,
    /// `request "METHOD /pattern"` or `exec /regex/` entries that always fail.
    #[serde(default)]
    pub forbid: Vec<String>,
    /// `allow` (default) or `deny` for `exec:`/`spawn:`.
    pub exec: Option<String>,
    /// `allow` (default), `deny`, or `local` (only to localhost/127.0.0.1) for POST/PUT/PATCH/DELETE.
    pub mutations: Option<String>,
}

fn host(url: &str) -> String {
    url.split_once("://")
        .map(|(_, r)| r)
        .unwrap_or(url)
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .to_lowercase()
}
fn glob(pat: &str, s: &str) -> bool {
    let re = format!("^{}$", regex::escape(pat).replace("\\*", ".*"));
    regex::Regex::new(&re).is_ok_and(|r| r.is_match(s))
}
fn local(url: &str) -> bool {
    let h = host(url);
    let name = h.split(':').next().unwrap_or("");
    name == "localhost" || name == "127.0.0.1" || name == "[::1]"
}

impl Policy {
    pub fn navigate(&self, url: &str) -> Result<()> {
        let Some(origins) = &self.origins else { return Ok(()) };
        if url.starts_with("about:") || url.starts_with("data:") {
            return Ok(());
        }
        let h = host(url);
        let bare = h.split(':').next().unwrap_or("").to_string();
        if !origins.iter().any(|o| glob(o, &h) || glob(o, &bare)) {
            bail!("E_POLICY navigation to {url} is outside policy.origins {origins:?}\n  allow it by adding `{h}` under policy.origins in testkit.yaml");
        }
        Ok(())
    }
    pub fn request(&self, method: &str, url: &str, base: &str) -> Result<()> {
        for f in &self.forbid {
            let Some(rest) = f.strip_prefix("request ") else { continue };
            let (m, pat) = crate::expr::parse::split_method(rest.trim().trim_matches('"'));
            if m.as_deref().is_none_or(|m| m.eq_ignore_ascii_case(method))
                && url_match(&pat, url, base)
            {
                bail!("E_POLICY {method} {url} is forbidden by policy.forbid `{f}`\n  remove that entry from testkit.yaml to allow it");
            }
        }
        let mutating = ["POST", "PUT", "PATCH", "DELETE"].contains(&method.to_uppercase().as_str());
        match self.mutations.as_deref() {
            Some("deny") if mutating => bail!("E_POLICY {method} {url}: mutating requests are denied (policy.mutations: deny)\n  set `mutations: allow` or `mutations: local` under policy in testkit.yaml"),
            Some("local") if mutating && !local(url) => bail!("E_POLICY {method} {url}: mutations are only allowed against localhost (policy.mutations: local)\n  set `mutations: allow` under policy in testkit.yaml"),
            _ => Ok(()),
        }
    }
    pub fn command(&self, cmd: &str) -> Result<()> {
        if self.exec.as_deref() == Some("deny") {
            bail!("E_POLICY `{cmd}`: shell commands are denied (policy.exec: deny)\n  set `exec: allow` under policy in testkit.yaml");
        }
        for f in &self.forbid {
            let Some(rest) = f.strip_prefix("exec ") else { continue };
            let re = rest.trim().trim_matches('/');
            if regex::Regex::new(re).is_ok_and(|r| r.is_match(cmd)) {
                bail!("E_POLICY `{cmd}` is forbidden by policy.forbid `{f}`\n  remove that entry from testkit.yaml to allow it");
            }
        }
        Ok(())
    }
}
