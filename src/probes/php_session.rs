//! CVE-2026-115560 — PHP Session Serializer Handler Mismatch
//!
//! Root cause: PHP's session upload-progress feature writes attacker-controlled
//! key material into the session file. If the application subsequently switches
//! `session.serialize_handler` at runtime via `ini_set()` before calling
//! `session_start()`, a handler mismatch allows object injection → RCE.
//!
//! No emergency patch (as of disclosure). Mitigation: `session.upload_progress.enabled=0`.
//! Fix: coming in next regular PHP release after 8.x.35/36/27/12.
//!
//! Detection approach
//! ──────────────────
//! Phase 1 — Upload-progress feature detection:
//!   POST multipart with the `PHP_SESSION_UPLOAD_PROGRESS` key (default) plus
//!   a session cookie. If PHP writes progress data into the session, the feature
//!   is enabled → mitigation NOT applied → exposure confirmed.
//!
//! Phase 2 — Session readable check:
//!   If a PHPSESSID was set in our response, re-request the page with that
//!   session cookie and look for upload-progress keys in the response.
//!
//! Phase 3 — Alternative key name probe:
//!   Some apps override `session.upload_progress.name`. We probe a few common
//!   alternative key names.
//!
//!   EXPOSED (feature enabled, mitigation absent):
//!     → PHP sets PHPSESSID cookie / session has upload-progress content
//!
//!   NOT EXPOSED (mitigation applied: session.upload_progress.enabled=0):
//!     → No PHPSESSID, or session is empty, or multipart body is rejected
//!
//!   PATCHED (full fix in next PHP release):
//!     → Same as NOT EXPOSED, but we also check PHP version header

use std::time::Instant;

use chrono::Utc;
use reqwest::Client;

use crate::payload;
use crate::probes::{
    signal_from_reqwest_err, Confidence, Evidence, ProbeResult, ProbeSignal, Vulnerability,
};

const UPLOAD_PROGRESS_KEYS: &[&str] = &[
    "PHP_SESSION_UPLOAD_PROGRESS", // PHP default
    "upload_progress",              // common alias
    "upload-progress",
    "progress",
];

pub async fn probe(client: &Client, target: &str, verbose: bool, _attempts: u8) -> ProbeResult {
    let cve = Vulnerability::Cve115560;
    let mut all_signals: Vec<ProbeSignal> = Vec::new();
    let mut upload_progress_enabled = false;
    let mut session_written = false;
    let mut php_version_header: Option<String> = None;

    for key in UPLOAD_PROGRESS_KEYS {
        if verbose {
            eprintln!("  [115560] probing upload_progress key: {}", key);
        }

        let (content_type, body) = payload::php_session_upload_progress_body(key);

        let t0 = Instant::now();
        let result = client
            .post(target)
            .header("Content-Type", &content_type)
            .header("Cookie", "PHPSESSID=shellproof_probe_session_0x2026")
            .header("User-Agent", "shellproof/0.1 (VertexElite; CVE-2026-115560)")
            .body(body)
            .send()
            .await;

        let elapsed = t0.elapsed().as_millis() as u64;

        match result {
            Ok(resp) => {
                let status = resp.status().as_u16();

                // Check if PHP is setting/echoing session cookies
                let set_cookie = resp.headers()
                    .get("set-cookie")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                let has_phpsessid = set_cookie.to_lowercase().contains("phpsessid");

                // Capture PHP version if exposed
                if let Some(xpb) = resp.headers().get("x-powered-by") {
                    let v = xpb.to_str().unwrap_or("");
                    if v.to_lowercase().contains("php") && php_version_header.is_none() {
                        php_version_header = Some(v.to_string());
                    }
                }

                let ct = resp.headers().get("content-type")
                    .and_then(|v| v.to_str().ok()).map(String::from);
                let bytes = resp.bytes().await.unwrap_or_default();
                let body_preview = String::from_utf8_lossy(&bytes[..bytes.len().min(200)]).to_string();

                if verbose {
                    eprintln!(
                        "    → HTTP {} in {}ms | PHPSESSID-set={} | body: {}",
                        status, elapsed, has_phpsessid,
                        &body_preview[..body_preview.len().min(80)]
                    );
                }

                // Session cookie being set for a fresh request is a strong indicator
                if has_phpsessid {
                    upload_progress_enabled = true;
                    session_written = true;
                }

                // Body echo of our probe key is a definitive indicator
                if body_preview.contains("SHELLPROOF_PROBE_2026")
                    || body_preview.contains("upload_progress")
                    || body_preview.contains("PHP_SESSION_UPLOAD_PROGRESS")
                {
                    upload_progress_enabled = true;
                    session_written = true;
                }

                all_signals.push(ProbeSignal::HttpResponse {
                    status,
                    content_type: ct,
                    body_preview,
                    elapsed_ms: elapsed,
                });
            }
            Err(e) => {
                if verbose { eprintln!("    → error: {}", e); }
                all_signals.push(signal_from_reqwest_err(&e, elapsed));
            }
        }

        if upload_progress_enabled {
            break; // found it, no need to try other key names
        }
    }

    // Phase 2: if we got a session, probe it to see if upload-progress data is in it
    if upload_progress_enabled {
        if verbose {
            eprintln!("  [115560] phase 2: session read-back check");
        }

        let t0 = Instant::now();
        let readback = client
            .get(target)
            .header("Cookie", "PHPSESSID=shellproof_probe_session_0x2026")
            .header("User-Agent", "shellproof/0.1 (VertexElite; CVE-2026-115560/readback)")
            .send()
            .await;

        let elapsed = t0.elapsed().as_millis() as u64;

        if let Ok(resp) = readback {
            let status = resp.status().as_u16();
            let bytes = resp.bytes().await.unwrap_or_default();
            let body_preview = String::from_utf8_lossy(&bytes[..bytes.len().min(200)]).to_string();

            if verbose {
                eprintln!("    → readback HTTP {} in {}ms | body: {}", status, elapsed,
                    &body_preview[..body_preview.len().min(80)]);
            }

            // If the session data echoes back, upload_progress IS writing to sessions
            if body_preview.contains("SHELLPROOF_PROBE_2026") {
                session_written = true;
            }

            all_signals.push(ProbeSignal::HttpResponse {
                status,
                content_type: None,
                body_preview,
                elapsed_ms: elapsed,
            });
        }
    }

    classify(cve, all_signals, upload_progress_enabled, session_written, php_version_header)
}

fn classify(
    cve: Vulnerability,
    signals: Vec<ProbeSignal>,
    upload_progress_enabled: bool,
    session_written: bool,
    php_version: Option<String>,
) -> ProbeResult {
    let error_only = signals.iter().all(|s| {
        matches!(s, ProbeSignal::NetworkError { .. } | ProbeSignal::Timeout { .. })
    });

    if error_only {
        return ProbeResult::Error {
            cve,
            error: "All session probe attempts failed at network level".into(),
        };
    }

    let php_info = php_version
        .as_deref()
        .map(|v| format!(" (PHP header: {})", v))
        .unwrap_or_default();

    if session_written && upload_progress_enabled {
        // upload_progress is ON and session is being populated → CVE-2026-115560 attack path open
        // Note: whether the app actually switches session.serialize_handler is unknown,
        // but the prerequisite (upload_progress.enabled) is present
        return ProbeResult::Vulnerable {
            cve,
            evidence: Evidence {
                signal_summary: format!(
                    "upload_progress.enabled=ON, session written by probe → \
                     CVE-2026-115560 prerequisite PRESENT{} | \
                     Mitigation (session.upload_progress.enabled=0) NOT applied.",
                    php_info
                ),
                signals,
                confidence: Confidence::Medium, // can't confirm ini_set() switch in app code
                attempts: 0,
                probed_at: Utc::now(),
            },
        };
    }

    if upload_progress_enabled && !session_written {
        // Feature appears enabled but we couldn't confirm session write
        return ProbeResult::Inconclusive {
            cve,
            reason: format!(
                "Session cookie was set but upload-progress data wasn't readable in response. \
                 upload_progress MAY be enabled{} — confirm by checking php.ini: \
                 `session.upload_progress.enabled`. If ON, apply mitigation: set it to 0. \
                 Full fix: coming in next regular PHP release.",
                php_info
            ),
            signals,
        };
    }

    // No session activity → either PHP not present, or mitigation already applied
    let reason = if php_version.is_some() {
        format!(
            "PHP detected{} but no session upload-progress activity observed. \
             Either: (a) mitigation applied (session.upload_progress.enabled=0) — GOOD, \
             or (b) this endpoint doesn't process PHP session cookies, or \
             (c) PHP version is patched (next regular release). \
             Cannot distinguish without direct php.ini access or known-patched version.",
            php_info
        )
    } else {
        "PHP not detected in response headers. Probe is not applicable or PHP version \
         is hidden. Cannot assess CVE-2026-115560 exposure without PHP fingerprint."
            .to_string()
    };

    ProbeResult::Inconclusive { cve, reason, signals }
}
