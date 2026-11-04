//! CVE-2026-109618 — PHP2Shell OOM Corruption
//!
//! Root cause: when PHP runs out of memory mid-request, the OOM handler
//! previously left request data in a half-initialized state. The cleanup
//! step then treated broken data as valid, producing a write primitive.
//! Fix: proper cleanup in the OOM path (PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12).
//!
//! Detection approach
//! ──────────────────
//! Send POST requests with increasingly deep nested JSON bodies designed to
//! stress PHP's allocator. Observe the failure mode:
//!
//!   Patched  → clean 500 / 413 / memory-limit error with response body
//!   Unpatched → connection reset (worker crash) or 502 (upstream saw crash)
//!
//! Note: this probe is LOW-confidence by design. The OOM trigger is
//! memory_limit-dependent and app-dependent. PHP-FPM is harder to crash
//! reliably than mod_php. INCONCLUSIVE is the expected result for most
//! well-configured servers — that's honest, not a bug.

use std::time::Instant;

use chrono::Utc;
use reqwest::Client;

use crate::payload;
use crate::probes::{
    signal_from_reqwest_err, Confidence, Evidence, ProbeResult, ProbeSignal, Vulnerability,
};

/// PHP OOM probe — escalating body sizes up to `attempts` rounds.
pub async fn probe(client: &Client, target: &str, verbose: bool, attempts: u8) -> ProbeResult {
    let cve = Vulnerability::Cve109618;

    // If target doesn't look like PHP, mark N/A (fingerprint check happens in main
    // so here we do a quick header check ourselves)
    let php_check = client
        .head(target)
        .header("User-Agent", "shellproof/0.1 (VertexElite; CVE-2026-109618)")
        .send()
        .await;

    let looks_like_php = match &php_check {
        Ok(r) => {
            let xpb = r.headers().get("x-powered-by")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            xpb.to_lowercase().contains("php")
        }
        Err(_) => false,
    };

    // Depths: 500 → 2000 → 5000 → 10000 (aggressive nesting)
    let depths: &[usize] = &[500, 2_000, 5_000, 10_000, 20_000];
    let mut signals: Vec<ProbeSignal> = Vec::new();

    for attempt in 0..attempts {
        let depth = depths[(attempt as usize).min(depths.len() - 1)];
        let body = payload::php_oom_pressure_body(depth);

        if verbose {
            eprintln!(
                "  [109618] attempt {}/{} depth={} body={}B",
                attempt + 1,
                attempts,
                depth,
                body.len()
            );
        }

        let t0 = Instant::now();
        let result = client
            .post(target)
            .header("Content-Type", "application/json")
            .header("User-Agent", "shellproof/0.1 (VertexElite; CVE-2026-109618)")
            .body(body)
            .send()
            .await;

        let elapsed = t0.elapsed().as_millis() as u64;

        let signal = match result {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let content_type = resp.headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .map(String::from);
                let bytes = resp.bytes().await.unwrap_or_default();
                let body_preview =
                    String::from_utf8_lossy(&bytes[..bytes.len().min(200)]).to_string();

                if verbose {
                    eprintln!("    → HTTP {} in {}ms", status, elapsed);
                }

                match status {
                    502 | 503 => ProbeSignal::GatewayError { status, elapsed_ms: elapsed },
                    _ => ProbeSignal::HttpResponse { status, content_type, body_preview, elapsed_ms: elapsed },
                }
            }
            Err(e) => {
                if verbose { eprintln!("    → error: {}", e); }
                signal_from_reqwest_err(&e, elapsed)
            }
        };

        signals.push(signal);
    }

    classify(cve, signals, looks_like_php)
}

fn classify(cve: Vulnerability, signals: Vec<ProbeSignal>, is_php: bool) -> ProbeResult {
    let crash_count = signals.iter().filter(|s| {
        matches!(s, ProbeSignal::ConnectionReset { .. } | ProbeSignal::GatewayError { .. })
    }).count();

    let clean_500_count = signals.iter().filter(|s| {
        matches!(s, ProbeSignal::HttpResponse { status: 500, .. })
    }).count();

    let body_limit_count = signals.iter().filter(|s| {
        matches!(s, ProbeSignal::HttpResponse { status: 413, .. })
    }).count();

    let error_count = signals.iter().filter(|s| {
        matches!(s, ProbeSignal::NetworkError { .. } | ProbeSignal::Timeout { .. })
    }).count();

    if error_count == signals.len() {
        return ProbeResult::Error {
            cve,
            error: "All OOM probe attempts failed at network level".into(),
        };
    }

    // A clean 413 means the server rejects oversized bodies before PHP sees them —
    // which is also protection, but we can't confirm patch status
    if body_limit_count > 0 && crash_count == 0 {
        return ProbeResult::NotApplicable {
            cve,
            reason: format!(
                "Server returned 413 (Request Entity Too Large) — body size limit blocks \
                 OOM trigger before PHP allocator is reached. PHP patch status unknown. \
                 PHP detected: {}.",
                is_php
            ),
        };
    }

    let evidence = Evidence {
        signal_summary: format!(
            "crashes={} clean-500s={} body-limits={} errors={} | php-detected={}",
            crash_count, clean_500_count, body_limit_count, error_count, is_php
        ),
        signals: signals.clone(),
        confidence: Confidence::Low, // OOM probe is always low-confidence without knowing memory_limit
        attempts: signals.len() as u8,
        probed_at: Utc::now(),
    };

    if crash_count >= 2 {
        // Multiple crashes → likely vulnerable
        // (single crash could be unrelated transient issue)
        ProbeResult::Vulnerable { cve, evidence }
    } else if clean_500_count > 0 && crash_count == 0 {
        // Clean error responses suggest OOM is handled properly
        // But low confidence — we can't be sure we hit the exact OOM path
        ProbeResult::Inconclusive {
            cve,
            reason: format!(
                "Server returned clean 500s ({} times) with no crashes. \
                 This suggests patched OOM handling, but confidence is LOW — \
                 the specific OOM trigger path is memory_limit-dependent. \
                 Recommend: verify PHP version directly (patched: 8.2.35+ / 8.3.36+ / 8.4.27+ / 8.5.12+). \
                 PHP detected from headers: {}.",
                clean_500_count, is_php
            ),
            signals,
        }
    } else {
        ProbeResult::Inconclusive {
            cve,
            reason: format!(
                "Ambiguous signals — could not trigger discriminating OOM condition. \
                 Server may have strict body-size limits, non-standard memory_limit, \
                 or the app does not JSON-decode request bodies. \
                 PHP detected: {}. Manual version check recommended.",
                is_php
            ),
            signals,
        }
    }
}
