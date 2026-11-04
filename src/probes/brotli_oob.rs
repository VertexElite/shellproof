//! CVE-2026-111497 — Node2Shell / HTTP2Shell
//!
//! OOB write in Google Brotli decoder (`c/dec/decode.c`).
//! Reachable remotely because Express 5 / body-parser 2.x transparently
//! decompress `Content-Encoding: br` request bodies.
//!
//! Detection approach
//! ──────────────────
//! Send four malformed Brotli streams (payload.rs) with `Content-Encoding: br`
//! and observe the server's response pattern:
//!
//!   Patched  (Brotli >= 1.2.1 / Node.js >= 22.23.4):
//!     → Clean HTTP 4xx response (decoder rejects malformed stream gracefully)
//!
//!   Unpatched:
//!     → ConnectionReset  — decoder OOB write → process crash
//!     → Timeout           — process hangs after OOB
//!     → GatewayError 502  — nginx/LB upstream sees crash
//!
//!   Not applicable (CF edge / nginx at origin already rejects Content-Encoding: br):
//!     → HTTP 400 immediately with CF or nginx error body

use std::time::Instant;

use anyhow::Result;
use chrono::Utc;
use reqwest::Client;

use crate::payload;
use crate::probes::{
    signal_from_reqwest_err, Confidence, Evidence, ProbeResult, ProbeSignal, Vulnerability,
};

/// Run the CVE-2026-111497 probe.
///
/// Sends all four Brotli probe variants. Each variant targets a slightly
/// different code path in the decoder. A majority-crash verdict is used
/// to reduce false positives from transient network issues.
pub async fn probe(client: &Client, target: &str, verbose: bool, attempts: u8) -> ProbeResult {
    let cve = Vulnerability::Cve111497;
    let mut signals: Vec<ProbeSignal> = Vec::new();

    let payloads: &[(&str, fn() -> bytes::Bytes)] = &[
        ("truncated",              payload::brotli_truncated),
        ("invalid_dist_block_sw",  payload::brotli_invalid_distance_block_switch),
        ("valid_then_malformed",   payload::brotli_valid_then_malformed),
        ("decompression_claim",    payload::brotli_decompression_claim),
    ];

    for attempt in 0..attempts {
        let (name, build_payload) = &payloads[(attempt as usize) % payloads.len()];
        let body = build_payload();

        if verbose {
            eprintln!(
                "  [111497] attempt {}/{} payload={} bytes={}",
                attempt + 1,
                attempts,
                name,
                body.len()
            );
        }

        let t0 = Instant::now();
        let result = client
            .post(target)
            .header("Content-Encoding", "br")
            .header("Content-Type", "application/octet-stream")
            .header(
                "User-Agent",
                "shellproof/0.1 (VertexElite Security Research; CVE-2026-111497)",
            )
            .body(body)
            .send()
            .await;

        let elapsed = t0.elapsed().as_millis() as u64;

        let signal = match result {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let content_type = resp
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                let body_bytes = resp.bytes().await.unwrap_or_default();
                let body_preview = String::from_utf8_lossy(&body_bytes[..body_bytes.len().min(200)])
                    .to_string();

                if verbose {
                    eprintln!("    → HTTP {} in {}ms | body: {}", status, elapsed, &body_preview[..body_preview.len().min(80)]);
                }

                match status {
                    502 | 503 => ProbeSignal::GatewayError { status, elapsed_ms: elapsed },
                    _ => ProbeSignal::HttpResponse {
                        status,
                        content_type,
                        body_preview,
                        elapsed_ms: elapsed,
                    },
                }
            }
            Err(e) => {
                if verbose {
                    eprintln!("    → error in {}ms: {}", elapsed, e);
                }
                signal_from_reqwest_err(&e, elapsed)
            }
        };

        signals.push(signal);
    }

    classify(cve, signals)
}

/// Classify collected signals into a final verdict.
fn classify(cve: Vulnerability, signals: Vec<ProbeSignal>) -> ProbeResult {
    let crash_count = signals.iter().filter(|s| is_crash_signal(s)).count();
    let clean_reject_count = signals.iter().filter(|s| is_clean_reject(s)).count();
    let error_count = signals
        .iter()
        .filter(|s| matches!(s, ProbeSignal::NetworkError { .. }))
        .count();

    // If all signals are network errors, we can't determine anything
    if error_count == signals.len() {
        return ProbeResult::Error {
            cve,
            error: "All probe attempts resulted in network errors — target unreachable or proxy blocking".into(),
        };
    }

    let total_useful = signals.len() - error_count;
    let crash_ratio = if total_useful > 0 {
        crash_count as f32 / total_useful as f32
    } else {
        0.0
    };

    let evidence = Evidence {
        signal_summary: build_summary(&signals, crash_count, clean_reject_count),
        signals: signals.clone(),
        confidence: if total_useful >= 3 { Confidence::Medium } else { Confidence::Low },
        attempts: signals.len() as u8,
        probed_at: Utc::now(),
    };

    // Edge: check if CF/nginx blocked at layer 7 before reaching app
    let cf_blocked = signals.iter().any(|s| {
        if let ProbeSignal::HttpResponse { status: 400, body_preview, .. } = s {
            let bp = body_preview.to_lowercase();
            bp.contains("cloudflare") || bp.contains("error 1") || bp.contains("ray id")
        } else {
            false
        }
    });

    if cf_blocked {
        return ProbeResult::NotApplicable {
            cve,
            reason: "Cloudflare (or similar edge) rejected malformed Content-Encoding: br \
                     before reaching the origin — origin not directly testable"
                .into(),
        };
    }

    if crash_ratio >= 0.5 && crash_count >= 1 {
        ProbeResult::Vulnerable {
            cve,
            evidence: Evidence {
                confidence: if crash_ratio >= 0.8 { Confidence::Medium } else { Confidence::Low },
                ..evidence
            },
        }
    } else if clean_reject_count > 0 && crash_count == 0 {
        ProbeResult::Patched { cve, evidence }
    } else {
        ProbeResult::Inconclusive {
            cve,
            reason: format!(
                "Mixed signals — crashes: {}, clean-rejects: {}, errors: {}. \
                 Server may be behind a proxy that absorbs the signal, \
                 or the probe payload did not reach the Brotli decoder.",
                crash_count, clean_reject_count, error_count
            ),
            signals,
        }
    }
}

fn is_crash_signal(s: &ProbeSignal) -> bool {
    matches!(
        s,
        ProbeSignal::ConnectionReset { .. }
            | ProbeSignal::Timeout { .. }
            | ProbeSignal::GatewayError { .. }
    )
}

fn is_clean_reject(s: &ProbeSignal) -> bool {
    matches!(
        s,
        ProbeSignal::HttpResponse { status, .. } if *status == 400 || *status == 415 || *status == 422 || *status == 500
    )
}

fn build_summary(signals: &[ProbeSignal], crashes: usize, clean: usize) -> String {
    let labels: Vec<&str> = signals.iter().map(|s| s.label()).collect();
    format!(
        "crash-signals={} clean-rejects={} total={} | signals: [{}]",
        crashes,
        clean,
        signals.len(),
        labels.join(", ")
    )
}
