//! Proof receipts (spec §10): manifest, markdown, self-contained HTML, per-claim GIFs, redaction and a hash chain.
use crate::runner::{Runner, StepResult};
use anyhow::{anyhow, bail, Result};
use base64::Engine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::Instant;

const HTML: &str = include_str!("receipt.html");
pub fn root() -> PathBuf {
    PathBuf::from(".testkit/receipts")
}

fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn git(args: &[&str]) -> Option<String> {
    std::process::Command::new("git")
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

/// Secrets to mask: values of env vars referenced by the source plus `secret:` entries and password fills.
fn secrets(src: &str, r: &Runner) -> Vec<(String, String)> {
    let re = regex::Regex::new(r"(?:\$\{env\.|\$\.env\.)([A-Za-z_][A-Za-z0-9_]*)").unwrap();
    let mut out: Vec<(String, String)> = re
        .captures_iter(src)
        .filter_map(|c| {
            std::env::var(&c[1])
                .ok()
                .filter(|v| v.len() >= 3)
                .map(|v| (format!("env.{}", &c[1]), v))
        })
        .collect();
    for s in &r.cfg.secrets {
        if let Some(v) = r.vars.get(s).map(crate::item::scalar_text) {
            out.push((s.clone(), v))
        }
    }
    out.sort();
    out.dedup();
    out
}
fn redact(
    s: &str,
    secrets: &[(String, String)],
    counts: &mut std::collections::BTreeMap<String, usize>,
) -> String {
    let mut s = s.to_string();
    for (name, v) in secrets {
        let n = s.matches(v.as_str()).count();
        if n > 0 {
            *counts.entry(name.clone()).or_default() += n;
            s = s.replace(v.as_str(), "••••••")
        }
    }
    let auth =
        regex::Regex::new(r#"(?i)("?(authorization|cookie|set-cookie)"?\s*[:=]\s*\[?")[^"]+"#)
            .unwrap();
    let hits = auth.find_iter(&s).count();
    if hits > 0 {
        *counts.entry("headers".into()).or_default() += hits;
        s = auth.replace_all(&s, "${1}••••••").to_string()
    }
    s
}

/// PNG frames → RGBA (frames of a different size than the first are dropped).
fn decode(frames: &[&Vec<u8>]) -> Vec<(u32, u32, Vec<u8>)> {
    let decoded: Vec<(u32, u32, Vec<u8>)> = frames
        .iter()
        .filter_map(|png| {
            let mut r = png::Decoder::new(std::io::Cursor::new(png.as_slice())).read_info().ok()?;
            let mut buf = vec![0; r.output_buffer_size()];
            let info = r.next_frame(&mut buf).ok()?;
            let rgba = match info.color_type {
                png::ColorType::Rgba => buf[..info.buffer_size()].to_vec(),
                png::ColorType::Rgb => buf[..info.buffer_size()]
                    .chunks(3)
                    .flat_map(|p| [p[0], p[1], p[2], 255])
                    .collect(),
                _ => return None,
            };
            Some((info.width, info.height, rgba))
        })
        .collect();
    let first = decoded.first().map(|d| (d.0, d.1));
    decoded.into_iter().filter(|d| Some((d.0, d.1)) == first).collect()
}

#[cfg(not(feature = "video"))]
fn mp4(_: &[&Vec<u8>]) -> Option<Vec<u8>> {
    None
}

/// H.264 in MP4 (bundled openh264 encoder, pure-Rust muxer); one frame per step, 900ms each.
#[cfg(feature = "video")]
fn mp4(frames: &[&Vec<u8>]) -> Option<Vec<u8>> {
    use openh264::encoder::{Encoder, EncoderConfig};
    use openh264::formats::{RgbSliceU8, YUVBuffer};
    let decoded = decode(frames);
    let (w0, h0, _) = decoded.first()?.clone();
    let (w, h) = ((w0 & !1) as usize, (h0 & !1) as usize);
    let mut enc =
        Encoder::with_api_config(openh264::OpenH264API::from_source(), EncoderConfig::new())
            .ok()?;
    let (mut sps, mut pps, mut samples) = (None, None, vec![]);
    for (_, _, rgba) in &decoded {
        let rgb: Vec<u8> = (0..h)
            .flat_map(|y| {
                (0..w).flat_map(move |x| {
                    let i = (y * w0 as usize + x) * 4;
                    [i, i + 1, i + 2]
                })
            })
            .map(|i| rgba[i])
            .collect();
        let yuv = YUVBuffer::from_rgb_source(RgbSliceU8::new(&rgb, (w, h)));
        let data = enc.encode(&yuv).ok()?.to_vec();
        let (mut sample, mut sync) = (vec![], false);
        for nal in openh264::nal_units(&data) {
            let start = nal.iter().position(|&b| b == 1)? + 1;
            let body = &nal[start..];
            match body.first().map(|b| b & 0x1f) {
                Some(7) => sps = Some(body.to_vec()),
                Some(8) => pps = Some(body.to_vec()),
                Some(t) => {
                    sync |= t == 5;
                    sample.extend_from_slice(&(body.len() as u32).to_be_bytes());
                    sample.extend_from_slice(body)
                }
                None => {}
            }
        }
        samples.push((sample, sync));
    }
    let brand = |s: &str| s.parse::<mp4::FourCC>().ok();
    let cfg = mp4::Mp4Config {
        major_brand: brand("isom")?,
        minor_version: 512,
        compatible_brands: vec![brand("isom")?, brand("iso2")?, brand("avc1")?, brand("mp41")?],
        timescale: 1000,
    };
    let mut wr = mp4::Mp4Writer::write_start(std::io::Cursor::new(Vec::new()), &cfg).ok()?;
    wr.add_track(&mp4::TrackConfig {
        track_type: mp4::TrackType::Video,
        timescale: 1000,
        language: "und".into(),
        media_conf: mp4::MediaConfig::AvcConfig(mp4::AvcConfig {
            width: w as u16,
            height: h as u16,
            seq_param_set: sps?,
            pic_param_set: pps?,
        }),
    })
    .ok()?;
    for (i, (bytes, sync)) in samples.into_iter().enumerate() {
        wr.write_sample(
            1,
            &mp4::Mp4Sample {
                start_time: i as u64 * 900,
                duration: 900,
                rendering_offset: 0,
                is_sync: sync,
                bytes: bytes::Bytes::from(bytes),
            },
        )
        .ok()?;
    }
    wr.write_end().ok()?;
    Some(wr.into_writer().into_inner())
}

fn gif(frames: &[&Vec<u8>]) -> Option<Vec<u8>> {
    let decoded = decode(frames);
    let (w, h, _) = decoded.first()?.clone();
    let step = (w / 480).max(1);
    let (ow, oh) = (w / step, h / step);
    let mut out = vec![];
    {
        let mut enc = gif::Encoder::new(&mut out, ow as u16, oh as u16, &[]).ok()?;
        enc.set_repeat(gif::Repeat::Infinite).ok()?;
        for (fw, fh, px) in decoded.iter().filter(|(fw, fh, _)| *fw == w && *fh == h) {
            let mut small = Vec::with_capacity((ow * oh * 4) as usize);
            for y in 0..oh {
                for x in 0..ow {
                    let i = (((y * step) * fw + x * step) * 4) as usize;
                    small.extend_from_slice(&px[i..i + 4]);
                }
            }
            let _ = fh;
            let mut f = gif::Frame::from_rgba_speed(ow as u16, oh as u16, &mut small, 20);
            f.delay = 90;
            enc.write_frame(&f).ok()?;
        }
    }
    Some(out)
}

/// Writes `.testkit/receipts/<id>/` and returns the directory.
pub async fn write(
    r: &mut Runner,
    source: &str,
    started: Instant,
    session: bool,
) -> Result<PathBuf> {
    let id =
        format!("rcpt_{}", &crate::browser::rand_id()[..10.min(crate::browser::rand_id().len())]);
    let dir = root().join(&id);
    std::fs::create_dir_all(dir.join("media"))?;
    let src_text = std::fs::read_to_string(source).unwrap_or_default();
    let secrets = secrets(&src_text, r);
    let mut counts = Default::default();
    let mut artifacts: Vec<(String, Vec<u8>)> = vec![];
    if !src_text.is_empty() {
        artifacts.push(("source.tk.yaml".into(), src_text.clone().into_bytes()))
    }
    let results: Vec<StepResult> = r.results.clone();
    let mut claims = r.claims.clone();
    if claims.is_empty() {
        claims.push(crate::runner::Claim {
            title: format!(
                "All steps in {}",
                Path::new(source)
                    .file_name()
                    .map(|f| f.to_string_lossy().to_string())
                    .unwrap_or(source.into())
            ),
            status: if results.iter().all(|x| x.ok()) { "pass".into() } else { "fail".into() },
            steps: (0..results.len()).collect(),
            ..Default::default()
        });
    }
    let mut claim_json = vec![];
    for (ci, c) in claims.iter().enumerate() {
        let steps: Vec<&StepResult> = c.steps.iter().filter_map(|&i| results.get(i)).collect();
        let frames: Vec<&Vec<u8>> = steps.iter().filter_map(|s| s.frame.as_ref()).collect();
        let mut ev = json!({});
        if !frames.is_empty() {
            for (k, f) in [("before", frames.first()), ("after", frames.last())] {
                if let Some(f) = f {
                    let p = format!("media/claim{}-{k}.png", ci + 1);
                    artifacts.push((p.clone(), (*f).clone()));
                    ev[k] = json!(p)
                }
            }
            if let Some(v) = mp4(&frames) {
                let p = format!("media/claim{}.mp4", ci + 1);
                artifacts.push((p.clone(), v));
                ev["video"] = json!(p)
            }
            if let Some(g) = gif(&frames) {
                let p = format!("media/claim{}.gif", ci + 1);
                artifacts.push((p.clone(), g));
                ev["gif"] = json!(p)
            }
        }
        let step_json: Vec<Value> = steps.iter().map(|s| {
            let mut v = json!({"verb": s.verb, "expr": s.text, "file": s.file, "line": s.line, "status": s.status, "ms": s.ms, "report": s.report,
                "error": s.step_error, "log": s.step_log, "name": s.step_name});
            if let Some(f) = &s.frame { v["frame"] = json!(format!("data:image/png;base64,{}", base64::engine::general_purpose::STANDARD.encode(f))) }
            v
        }).collect();
        claim_json.push(json!({"title": c.title, "status": c.status, "line": c.line, "ms": steps.iter().map(|s| s.ms).sum::<u64>(), "evidence": ev, "steps": step_json}));
    }
    artifacts.push(("network.har".into(), serde_json::to_vec_pretty(&r.har())?));
    for (name, p) in &r.ptys {
        let cast = p
            .cast
            .lock()
            .unwrap()
            .iter()
            .map(|(t, s)| json!([t, "o", s]).to_string())
            .collect::<Vec<_>>()
            .join("\n");
        let header = json!({"version": 2, "width": 120, "height": 40, "title": p.cmd}).to_string();
        artifacts.push((format!("media/{name}.cast"), format!("{header}\n{cast}\n").into_bytes()));
    }
    let setup: Vec<Value> = results
        .iter()
        .filter(|s| {
            s.claim.is_none() && !claims.iter().any(|c| c.steps.contains(&(s.step_index as usize)))
        })
        .map(|s| json!({"expr": s.line_text(), "status": s.status, "ms": s.ms}))
        .collect();
    let guard = results
        .iter()
        .filter(|s| s.step_error.as_deref().is_some_and(|e| e.starts_with("E_GUARD")))
        .count();
    let status = if claims.iter().all(|c| c.status == "pass") { "proven" } else { "not proven" };
    let env = json!({
        "git": {"sha": git(&["rev-parse", "--short", "HEAD"]), "dirty": git(&["status", "--porcelain"]).is_some_and(|s| !s.is_empty())},
        "base_url": r.vars.get("base_url").cloned().or(r.cfg.base_url.clone().map(Value::String)),
        "testkit": env!("CARGO_PKG_VERSION"), "os": format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
    });
    let mut manifest = json!({
        "id": id, "status": status, "created": chrono::Utc::now().to_rfc3339(), "duration_ms": started.elapsed().as_millis() as u64,
        "source": {"file": source, "sha256": sha(src_text.as_bytes())}, "session": session, "env": env, "setup": setup, "claims": claim_json,
        "guard": {"errors": guard},
    });
    let redacted = redact(&manifest.to_string(), &secrets, &mut counts);
    manifest = serde_json::from_str(&redacted)?;
    manifest["redactions"] =
        json!(counts.iter().map(|(k, v)| json!({"source": k, "count": v})).collect::<Vec<_>>());
    let md = markdown(&manifest);
    artifacts.push(("receipt.md".into(), md.clone().into_bytes()));
    let mut list: Vec<Value> = vec![];
    for (p, bytes) in &artifacts {
        let bytes = if p.ends_with(".cast") || p.ends_with(".yaml") || p.ends_with(".har") {
            redact(&String::from_utf8_lossy(bytes), &secrets, &mut Default::default()).into_bytes()
        } else {
            bytes.clone()
        };
        std::fs::write(dir.join(p), &bytes)?;
        list.push(json!({"path": p, "sha256": sha(&bytes)}));
    }
    let manifest_wo = manifest.clone();
    manifest["artifacts"] = json!(list);
    manifest["chain"] = json!(chain(&list, &manifest_wo));
    std::fs::write(dir.join("receipt.json"), serde_json::to_vec_pretty(&manifest)?)?;
    let mut page = manifest.clone();
    page["md"] = json!(md);
    let html = HTML.replace("__DATA__", &serde_json::to_string(&page)?.replace("</", "<\\/"));
    std::fs::write(dir.join("receipt.html"), html)?;
    Ok(dir)
}

fn chain(list: &[Value], manifest: &Value) -> String {
    let mut m = manifest.clone();
    if let Some(o) = m.as_object_mut() {
        o.remove("artifacts");
        o.remove("chain");
        o.remove("signature");
    }
    let body = list
        .iter()
        .map(|a| {
            format!(
                "{}:{}",
                crate::item::scalar_text(&a["path"]),
                crate::item::scalar_text(&a["sha256"])
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    sha(format!("{body}\n{m}").as_bytes())
}

pub fn markdown(m: &Value) -> String {
    let s = |v: &Value| crate::item::scalar_text(v);
    let icon = |st: &str| match st {
        "pass" => "✅",
        "skip" => "⏭",
        _ => "❌",
    };
    let claims = m["claims"].as_array().cloned().unwrap_or_default();
    let proven = claims.iter().filter(|c| c["status"] == "pass").count();
    let mut out = format!("## {} · {} · {proven}/{} claims\n`{}` · {} · git `{}`{} · {} · testkit {}\n\n| | Claim | Evidence |\n|---|---|---|\n",
        if m["status"] == "proven" { "✅ Proven" } else { "❌ Not proven" }, Path::new(&s(&m["source"]["file"])).file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or_default(),
        claims.len(), s(&m["id"]), &s(&m["created"])[..16.min(s(&m["created"]).len())], s(&m["env"]["git"]["sha"]), if m["env"]["git"]["dirty"] == true { " (dirty)" } else { "" },
        s(&m["env"]["base_url"]), s(&m["env"]["testkit"]));
    for c in &claims {
        let steps = c["steps"].as_array().cloned().unwrap_or_default();
        let ev = if c["status"] == "skip" {
            "not run (an earlier claim or setup failed)".to_string()
        } else {
            let mut e = vec![];
            if let Some(g) = c["evidence"]["gif"].as_str() {
                e.push(format!("![]({g})"))
            }
            let nets: Vec<String> = steps
                .iter()
                .flat_map(|st| st["report"]["network"].as_array().cloned().unwrap_or_default())
                .map(|n| s(&n))
                .filter(|n| !n.starts_with("GET /") || n.contains("/api"))
                .take(2)
                .collect();
            if !nets.is_empty() {
                e.push(nets.iter().map(|n| format!("`{n}`")).collect::<Vec<_>>().join(" · "))
            }
            e.push(format!(
                "{} steps · {:.1}s",
                steps.len(),
                c["ms"].as_f64().unwrap_or(0.0) / 1000.0
            ));
            e.join(" · ")
        };
        out.push_str(&format!(
            "| {} | {} | {ev} |\n",
            icon(c["status"].as_str().unwrap_or("")),
            s(&c["title"]).replace('|', "\\|")
        ));
    }
    let setup = m["setup"].as_array().map(|a| a.len()).unwrap_or(0);
    if setup > 0 {
        out.push_str(&format!(
            "\nSetup {} {} steps",
            if m["setup"].as_array().unwrap().iter().all(|x| x["status"] != "fail") {
                "✓"
            } else {
                "✗"
            },
            setup
        ))
    }
    out.push_str(&format!(
        "\nGuard {} · redacted {} value(s) · chain `{}`\n",
        if m["guard"]["errors"] == 0 {
            "✓ clean".into()
        } else {
            format!("⚠ {} error(s)", m["guard"]["errors"])
        },
        m["redactions"]
            .as_array()
            .map(|a| a.iter().map(|x| x["count"].as_u64().unwrap_or(0)).sum::<u64>())
            .unwrap_or(0),
        "see receipt.json"
    ));
    for c in claims.iter().filter(|c| c["status"] == "fail") {
        let steps = c["steps"].as_array().cloned().unwrap_or_default();
        if let Some((i, st)) = steps.iter().enumerate().find(|(_, x)| x["status"] == "fail") {
            out.push_str(&format!(
                "\n### ❌ {} · {}:{}\n```\n{} {}\n{}\n",
                s(&c["title"]),
                s(&st["file"]),
                st["line"],
                s(&st["verb"]),
                s(&st["expr"]),
                s(&st["error"])
                    .lines()
                    .chain(s(&st["log"]).lines().filter(|l| l.starts_with('❌')))
                    .take(12)
                    .collect::<Vec<_>>()
                    .join("\n")
            ));
            for h in hints(&steps[..=i]) {
                out.push_str(&format!("hint      {h}\n"))
            }
            out.push_str("```\n");
        }
    }
    out.push_str(&format!("\nFull receipt: `.testkit/receipts/{}/receipt.html` · verify: `testkit receipt {} --verify`\n", s(&m["id"]), s(&m["id"])));
    out
}

/// Built-in correlations for a failing claim (spec §10): failed requests, console errors and the
/// last write the UI made, so a reader (or an LLM) knows where to look first.
fn hints(steps: &[Value]) -> Vec<String> {
    let s = |v: &Value| crate::item::scalar_text(v);
    let nets: Vec<String> = steps
        .iter()
        .flat_map(|st| st["report"]["network"].as_array().cloned().unwrap_or_default())
        .map(|n| s(&n))
        .filter(|n| !n.contains("favicon"))
        .collect();
    let mut out = vec![];
    if let Some(bad) = nets.iter().rev().find(|n| {
        n.split_whitespace().nth(2).and_then(|c| c.parse::<u16>().ok()).is_some_and(|c| c >= 400)
            || n.contains("net::")
    }) {
        out.push(format!("a request failed during this claim: {bad}"));
    }
    if let Some(w) = nets
        .iter()
        .rev()
        .find(|n| ["POST", "PUT", "PATCH", "DELETE"].iter().any(|m| n.starts_with(m)))
    {
        out.push(format!("last write: {w}; check that it changed what the failing step expects"));
    }
    if let Some(e) = steps
        .iter()
        .flat_map(|st| st["report"]["console"].as_array().cloned().unwrap_or_default())
        .map(|c| s(&c))
        .find(|c| c.starts_with("error") || c.starts_with("pageerror"))
    {
        out.push(format!("console: {e}"));
    }
    out
}

const NAMESPACE: &str = "testkit-receipt";

/// Signs the chain hash with an SSH key (`ssh-keygen -Y sign`); returns the signer fingerprint.
pub fn sign(dir: &Path, key: &Path) -> Result<String> {
    let m: Value = serde_json::from_slice(&std::fs::read(dir.join("receipt.json"))?)?;
    std::fs::write(dir.join("chain.txt"), format!("{}\n", crate::item::scalar_text(&m["chain"])))?;
    let pubkey = std::process::Command::new("ssh-keygen").args(["-y", "-f"]).arg(key).output()?;
    if !pubkey.status.success() {
        bail!(
            "cannot read the public key of {}: {}",
            key.display(),
            String::from_utf8_lossy(&pubkey.stderr)
        )
    }
    std::fs::write(dir.join("signer.pub"), &pubkey.stdout)?;
    let out = std::process::Command::new("ssh-keygen")
        .args(["-Y", "sign", "-n", NAMESPACE, "-f"])
        .arg(key)
        .arg(dir.join("chain.txt"))
        .output()?;
    if !out.status.success() {
        bail!("ssh-keygen -Y sign failed: {}", String::from_utf8_lossy(&out.stderr))
    }
    fingerprint(&dir.join("signer.pub"))
}
fn fingerprint(pubkey: &Path) -> Result<String> {
    let o = std::process::Command::new("ssh-keygen").arg("-lf").arg(pubkey).output()?;
    Ok(String::from_utf8_lossy(&o.stdout).trim().to_string())
}
/// `Ok(None)` when unsigned; otherwise checks the signature and that it covers this receipt's chain.
pub fn check_signature(dir: &Path) -> Result<Option<String>> {
    let sig = dir.join("chain.txt.sig");
    if !sig.exists() {
        return Ok(None);
    }
    let m: Value = serde_json::from_slice(&std::fs::read(dir.join("receipt.json"))?)?;
    let signed = std::fs::read_to_string(dir.join("chain.txt"))?;
    if signed.trim() != crate::item::scalar_text(&m["chain"]) {
        bail!("the signature covers a different chain than receipt.json")
    }
    let mut c = std::process::Command::new("ssh-keygen");
    c.args(["-Y", "check-novalidate", "-n", NAMESPACE, "-s"])
        .arg(&sig)
        .stdin(std::fs::File::open(dir.join("chain.txt"))?);
    let o = c.output()?;
    if !o.status.success() {
        bail!("{}", String::from_utf8_lossy(&o.stderr).trim())
    }
    // the key ssh-keygen verified, not whatever signer.pub claims
    Ok(Some(format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout).trim(),
        String::from_utf8_lossy(&o.stderr).trim()
    )))
}

pub fn latest() -> Result<PathBuf> {
    let mut d: Vec<_> = std::fs::read_dir(root())?
        .filter_map(|e| e.ok())
        .filter_map(|e| Some((e.metadata().ok()?.modified().ok()?, e.path())))
        .collect();
    d.sort();
    d.pop().map(|x| x.1).ok_or_else(|| anyhow!("no receipts yet; run `testkit prove <file>`"))
}
pub fn find(id: Option<&str>) -> Result<PathBuf> {
    match id {
        Some(i) if Path::new(i).is_dir() => Ok(i.into()),
        Some(i) => Ok(root().join(i)),
        None => latest(),
    }
}

/// Re-hashes every artifact and the chain; returns the changed paths.
pub fn verify(dir: &Path) -> Result<Vec<String>> {
    let m: Value = serde_json::from_slice(&std::fs::read(dir.join("receipt.json"))?)?;
    let list = m["artifacts"].as_array().ok_or_else(|| anyhow!("receipt has no artifacts"))?;
    let mut bad = vec![];
    for a in list {
        let p = crate::item::scalar_text(&a["path"]);
        match std::fs::read(dir.join(&p)) {
            Ok(b) if sha(&b) == crate::item::scalar_text(&a["sha256"]) => {}
            _ => bad.push(p),
        }
    }
    let mut base = m.clone();
    if let Some(o) = base.as_object_mut() {
        o.remove("artifacts");
        o.remove("chain");
    }
    if chain(list, &base) != crate::item::scalar_text(&m["chain"]) && bad.is_empty() {
        bad.push("receipt.json (manifest edited)".into())
    }
    if !dir.join("receipt.json").exists() {
        bail!("not a receipt directory")
    }
    Ok(bad)
}
