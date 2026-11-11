//! Mobile verbs: the same locators and steps, driven through `crate::mobile::Device` (adb).
use super::*;
use crate::mobile::{self, Device};

impl Runner {
    pub(crate) fn device(&mut self) -> Result<&Device> {
        if self.device.is_none() {
            self.device = Some(Device::connect()?)
        }
        Ok(self.device.as_ref().unwrap())
    }
    pub(crate) fn device_find(&mut self, l: &Locator) -> Result<Vec<Value>> {
        let l = self.bind(l)?;
        mobile::find(&self.device()?.elements()?, &l)
    }
    pub(crate) fn device_snapshot(&mut self, loc: Option<&Locator>) -> Result<String> {
        let max = self.snapshot_lines(0.9);
        let d = self.device()?;
        let mut els = d.elements()?;
        if let Some(l) = loc {
            let scope = mobile::find(&els, l)?;
            let s = scope
                .first()
                .ok_or_else(|| anyhow!("E_NOT_FOUND `snapshot {l}`: nothing on screen matches it"))?
                .clone();
            let d0 = s["depth"].as_u64().unwrap_or(0);
            let i = els.iter().position(|e| *e == s).unwrap_or(0);
            let n =
                els[i + 1..].iter().take_while(|e| e["depth"].as_u64().unwrap_or(0) > d0).count();
            els = els[i..=i + n].to_vec();
        }
        Ok(format!("# {}\n{}", d.foreground(), mobile::snapshot(&els, max)))
    }

    /// Waits until the locator matches exactly one element (exact-name tie-break), like browser actions.
    async fn device_one(&mut self, l: &Locator, timeout: Option<u64>) -> Result<Value> {
        let t0 = Instant::now();
        let limit = timeout.unwrap_or(self.cfg.action_ms);
        loop {
            let mut hits = self.device_find(l)?;
            if hits.len() > 1 {
                if let Some(Name::Sub(n)) = &l.name {
                    let exact: Vec<Value> = hits
                        .iter()
                        .filter(|e| {
                            e["name"]
                                .as_str()
                                .is_some_and(|s| s.trim().eq_ignore_ascii_case(n.trim()))
                        })
                        .cloned()
                        .collect();
                    if exact.len() == 1 {
                        hits = exact
                    }
                }
            }
            match hits.len() {
                1 => return Ok(hits.remove(0)),
                0 if t0.elapsed().as_millis() as u64 >= limit => {
                    let els = self.device()?.elements()?;
                    let near: Vec<String> = els
                        .iter()
                        .filter(|e| e["name"] != "" && e["role"] != "generic")
                        .take(12)
                        .map(|e| {
                            format!("{} {:?}", scalar_text(&e["role"]), scalar_text(&e["name"]))
                        })
                        .collect();
                    bail!(
                        "E_NOT_FOUND `{l}` matched nothing within {limit}ms\n  on screen: {}",
                        near.join(", ")
                    )
                }
                0 => tokio::time::sleep(Duration::from_millis(250)).await,
                _ => {
                    let c: Vec<String> = hits
                        .iter()
                        .enumerate()
                        .map(|(i, e)| {
                            format!(
                                "{l}[{}]  ({} {:?})",
                                i + 1,
                                scalar_text(&e["role"]),
                                scalar_text(&e["name"])
                            )
                        })
                        .collect();
                    bail!(
                        "E_AMBIGUOUS `{l}` matched {} elements:\n  {}",
                        hits.len(),
                        c.join("\n  ")
                    )
                }
            }
        }
    }

    pub(crate) async fn device_exec(&mut self, item: &Item, timeout: Option<u64>) -> Result<Value> {
        self.last = Surf::Mobile;
        let v = item.verb.as_str();
        let text = self.render(&item.text)?;
        let out = match (&item.args, v) {
            (_, "launch") if text.is_empty() => json!({"app": self.device()?.foreground()}),
            (_, "launch") => {
                self.device()?.launch(&text)?;
                json!({"app": text})
            }
            (_, "deeplink") => {
                self.device()?.deeplink(&text)?;
                json!({"url": text})
            }
            (_, "home" | "back") => {
                self.device()?.key(v)?;
                json!({})
            }
            (_, "swipe") => {
                let (dir, on) =
                    text.split_once(" on ").map_or((text.as_str(), None), |(d, l)| (d, Some(l)));
                let within = match on {
                    Some(l) => Some(
                        self.device_one(&parse::locator(l).map_err(|e| anyhow!("{e}"))?, timeout)
                            .await?,
                    ),
                    None => None,
                };
                self.device()?.swipe(dir.trim(), within.as_ref())?;
                json!({"direction": dir.trim()})
            }
            (Args::Loc(l), "check" | "uncheck") => {
                let e = self.device_one(l, timeout).await?;
                if (e["checked"] == true) != (v == "check") {
                    self.device()?.tap(&e)?
                }
                e
            }
            (Args::Loc(l), "focus") => self.device_one(l, timeout).await?,
            (Args::Loc(l), _) => {
                let e = self.device_one(l, timeout).await?;
                self.device()?.tap(&e)?;
                if v == "dblclick" {
                    self.device()?.tap(&e)?
                }
                e
            }
            (Args::LocVal(l, val), "fill") => {
                let s = to_str(&self.value(val).await?);
                let e = self.device_one(l, timeout).await?;
                let d = self.device()?;
                d.tap(&e)?;
                d.key("ctrl+a")?;
                d.key("Backspace")?;
                d.text(&s)?;
                e
            }
            (Args::Type(e, l), "type") => {
                let s = to_str(&self.value(e).await?);
                match l {
                    Some(l) => {
                        let el = self.device_one(l, timeout).await?;
                        self.device()?.tap(&el)?
                    }
                    None => {
                        let focused =
                            Locator { head: Head::Role("textbox".into()), ..Default::default() };
                        let t0 = Instant::now();
                        while !self.device_find(&focused)?.iter().any(|e| e["focused"] == true) {
                            if t0.elapsed().as_millis() as u64
                                > timeout.unwrap_or(self.cfg.action_ms)
                            {
                                bail!("E_NOT_ACTIONABLE `type: {s}`: no text field has focus; tap one first or write `type: … into field \"…\"`")
                            }
                            tokio::time::sleep(Duration::from_millis(200)).await
                        }
                    }
                }
                self.device()?.text(&s)?;
                Value::String(s)
            }
            (Args::Press(keys, n, l), _) => {
                if let Some(l) = l {
                    let el = self.device_one(l, timeout).await?;
                    self.device()?.tap(&el)?
                }
                for _ in 0..*n {
                    for k in keys {
                        self.device()?.key(k)?
                    }
                }
                json!(keys)
            }
            _ => bail!("`{v}` isn't supported on Android yet"),
        };
        let crash = self.device()?.crashes();
        if !crash.is_empty() {
            bail!(
                "E_CRASH the app crashed during `{}`:\n  {}",
                format!("{}: {}", item.verb, item.text),
                crash.lines().take(8).collect::<Vec<_>>().join("\n  ")
            )
        }
        Ok(out)
    }
}
