//! Target fingerprinting — PHP version, server stack, Brotli support, CDN/WAF detection.

use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Fingerprint {
    /// Raw Server header value
    pub server: Option<String>,
    /// X-Powered-By header (often "PHP/x.y.z")
    pub x_powered_by: Option<String>,
    /// PHP version extracted from headers
    pub php_version: Option<String>,
    /// Whether server accepts Content-Encoding: br
    pub accepts_brotli: Option<bool>,
    /// Whether server sends Brotli-encoded responses
    pub sends_brotli: Option<bool>,
    /// CDN / WAF detection (Cloudflare, nginx, Apache, etc.)
    pub cdn_waf: Vec<String>,
    /// HTTP status of baseline GET
    pub baseline_status: Option<u16>,
    /// Final URL after redirects
    pub effective_url: Option<String>,
}

impl Fingerprint {
    pub fn summary(&self) -> String {
        let mut parts: Vec<String> = Vec::new();

        if let Some(s) = &self.server {
            parts.push(format!("Server: {}", s));
        }
        if let Some(p) = &self.php_version {
            parts.push(format!("PHP {}", p));
        }
        if let Some(xpb) = &self.x_powered_by {
            if self.php_version.is_none() {
                parts.push(format!("X-Powered-By: {}", xpb));
            }
        }
        if let Some(br) = self.sends_brotli {
            parts.push(format!("Brotli-response: {}", if br { "yes" } else { "no" }));
        }
        if let Some(ab) = self.accepts_brotli {
            parts.push(format!("Brotli-accept: {}", if ab { "yes" } else { "no" }));
        }
        if !self.cdn_waf.is_empty() {
            parts.push(format!("CDN/WAF: {}", self.cdn_waf.join(", ")));
        }
        if parts.is_empty() {
            parts.push("(no identifying headers)".to_string());
        }
        parts.join(" | ")
    }

    /// Best-effort Node.js version from Server / X-Powered-By (rarely exposed).
    pub fn node_version(&self) -> Option<String> {
        for field in [&self.server, &self.x_powered_by] {
            if let Some(v) = field {
                let l = v.to_lowercase();
                if let Some(i) = l.find("node") {
                    let rest = &v[i..];
                    // find first digit after "node" and take the version run
                    if let Some(dstart) = rest.find(|c: char| c.is_ascii_digit()) {
                        let ver: String = rest[dstart..]
                            .chars()
                            .take_while(|c| c.is_ascii_digit() || *c == '.')
                            .collect();
                        if ver.contains('.') {
                            return Some(ver);
                        }
                    }
                }
            }
        }
        None
    }

    /// True if we could determine PHP is present
    pub fn is_php(&self) -> bool {
        self.php_version.is_some()
            || self
                .x_powered_by
                .as_deref()
                .map(|v| v.to_lowercase().contains("php"))
                .unwrap_or(false)
    }

    /// True if likely behind Cloudflare (attenuates Node2Shell exposure)
    pub fn behind_cloudflare(&self) -> bool {
        self.cdn_waf.iter().any(|v| v.to_lowercase().contains("cloudflare"))
    }

    /// True if likely behind nginx (nginx default body-size limit blocks ~23 MB trigger)
    pub fn behind_nginx(&self) -> bool {
        self.cdn_waf.iter().any(|v| v.to_lowercase().contains("nginx"))
            || self.server.as_deref().map(|s| s.to_lowercase().starts_with("nginx")).unwrap_or(false)
    }
}

pub async fn fingerprint(client: &Client, target: &str) -> Fingerprint {
    let mut fp = Fingerprint::default();

    // ── Baseline GET ────────────────────────────────────────────────────────
    let baseline = client
        .get(target)
        .header("Accept-Encoding", "gzip, br, identity")
        .header("User-Agent", "shellproof/0.1 (VertexElite Security Research)")
        .send()
        .await;

    if let Ok(resp) = baseline {
        fp.baseline_status = Some(resp.status().as_u16());
        fp.effective_url = Some(resp.url().to_string());

        let hdrs = resp.headers();

        // Server header
        if let Some(s) = hdrs.get("server") {
            let sv = s.to_str().unwrap_or("").to_string();
            detect_cdn_waf(&sv, &mut fp);
            fp.server = Some(sv);
        }

        // X-Powered-By / PHP version
        if let Some(xpb) = hdrs.get("x-powered-by") {
            let v = xpb.to_str().unwrap_or("").to_string();
            if let Some(php_ver) = extract_php_version(&v) {
                fp.php_version = Some(php_ver);
            }
            fp.x_powered_by = Some(v);
        }

        // Brotli response detection
        if let Some(ce) = hdrs.get("content-encoding") {
            fp.sends_brotli = Some(ce.to_str().unwrap_or("").contains("br"));
        }

        // Cloudflare / CDN from other headers
        for h in ["cf-ray", "cf-cache-status", "x-amz-cf-id", "x-cache", "via"] {
            if let Some(val) = hdrs.get(h) {
                detect_cdn_waf_header(h, val.to_str().unwrap_or(""), &mut fp);
            }
        }
    }

    // ── Brotli accept probe: HEAD with Accept-Encoding: br only ─────────────
    let br_probe = client
        .head(target)
        .header("Accept-Encoding", "br")
        .header("User-Agent", "shellproof/0.1 (VertexElite Security Research)")
        .send()
        .await;

    if let Ok(resp) = br_probe {
        let ce = resp.headers()
            .get("content-encoding")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        fp.accepts_brotli = Some(ce.contains("br"));
    }

    fp
}

fn extract_php_version(header: &str) -> Option<String> {
    let lower = header.to_lowercase();
    if !lower.contains("php") {
        return None;
    }
    // "PHP/8.3.35" → "8.3.35"
    if let Some(start) = lower.find("php/") {
        let rest = &header[start + 4..];
        let end = rest.find(|c: char| !c.is_ascii_digit() && c != '.').unwrap_or(rest.len());
        let ver = &rest[..end];
        if !ver.is_empty() {
            return Some(ver.to_string());
        }
    }
    Some(header.to_string())
}

fn detect_cdn_waf(server: &str, fp: &mut Fingerprint) {
    let s = server.to_lowercase();
    if s.contains("cloudflare") { fp.cdn_waf.push("Cloudflare".into()); }
    if s.contains("nginx")      { fp.cdn_waf.push("nginx".into()); }
    if s.contains("apache")     { fp.cdn_waf.push("Apache".into()); }
    if s.contains("litespeed")  { fp.cdn_waf.push("LiteSpeed".into()); }
    if s.contains("openresty")  { fp.cdn_waf.push("OpenResty".into()); }
    if s.contains("fastly")     { fp.cdn_waf.push("Fastly".into()); }
    if s.contains("akamai")     { fp.cdn_waf.push("Akamai".into()); }
    if s.contains("caddy")      { fp.cdn_waf.push("Caddy".into()); }
}

fn already_have(fp: &Fingerprint, s: &str) -> bool {
    fp.cdn_waf.iter().any(|v| v.to_lowercase() == s)
}

fn detect_cdn_waf_header(name: &str, value: &str, fp: &mut Fingerprint) {
    match name {
        "cf-ray" | "cf-cache-status" if !already_have(fp, "cloudflare") => {
            fp.cdn_waf.push("Cloudflare".into());
        }
        "x-amz-cf-id" if !already_have(fp, "aws cloudfront") => {
            fp.cdn_waf.push("AWS CloudFront".into());
        }
        "via" | "x-cache" => {
            let v = value.to_lowercase();
            if v.contains("fastly") && !already_have(fp, "fastly") { fp.cdn_waf.push("Fastly".into()); }
            if v.contains("varnish") && !already_have(fp, "varnish") { fp.cdn_waf.push("Varnish".into()); }
            if v.contains("squid") && !already_have(fp, "squid") { fp.cdn_waf.push("Squid".into()); }
        }
        _ => {}
    }
}
