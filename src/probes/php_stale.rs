//! CVE-2026-109619 — PHP2Shell Stale Global State
//!
//! Root cause: some PHP internal state belonging to one request can outlive
//! the memory behind it. A later request handled by the same PHP-FPM worker
//! may then use that stale state, producing a use-after-free / corruption
//! write primitive.
//! Fix: proper worker state reset between requests (PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12).
//!
//! Detection approach
//! ──────────────────
//! Use a single keep-alive TCP connection to maximize the probability of
//! hitting the same FPM worker twice. Round 1 "poisons" a specific
//! distinguishable state. Round 2 probes for leakage.
//!
//!   Patched  → Request 2 shows no influence from Request 1 state
//!   Unpatched → Request 2 behavior diverges (timing anomaly, body leak, or crash)
//!
//! Reliability: MEDIUM. Worker affinity with keep-alive is not guaranteed.
//! A INCONCLUSIVE result is expected if the probe doesn't land on the same worker.
//! For high-confidence results, test against a known single-worker FPM config.

use std::time::Instant;

use chrono::Utc;
use reqwest::Client;

use crate::payload;
use crate::probes::{
    signal_from_reqwest_err, Confidence, Evidence, ProbeResult, ProbeSignal, Vulnerability,
};

pub async fn probe(client: &Client, target: &str, verbose: bool, attempts: u8) -> ProbeResult {
    let cve = Vulnerability::Cve109619;
    let mut pair_results: Vec<(ProbeSignal, ProbeSignal)> = Vec::new();

    for attempt in 0..attempts {
        if verbose {
            eprintln!("  [109619] stale-state pair attempt {}/{}", attempt + 1, attempts);
        }

        // ── Request 1: Poison ──────────────────────────────────────────────────
        // POST with the stale-marker body.
        // On unpatched PHP: this request sets global state that persists in the worker.
        let poison_body = payload::php_stale_poison_body();

        let t0 = Instant::now();
        let r1 = client
            .post(target)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Connection", "keep-alive")
            .header("User-Agent", "shellproof/0.1 (VertexElite; CVE-2026-109619/r1)")
            .body(poison_body)
            .send()
            .await;

        let elapsed1 = t0.elapsed().as_millis() as u64;

        let sig1 = match r1 {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let ct = resp.headers().get("content-type")
                    .and_then(|v| v.to_str().ok()).map(String::from);
                let bytes = resp.bytes().await.unwrap_or_default();
                let body_preview = String::from_utf8_lossy(&bytes[..bytes.len().min(200)]).to_string();
                if verbose { eprintln!("    → R1 HTTP {} in {}ms", status, elapsed1); }
                ProbeSignal::HttpResponse { status, content_type: ct, body_preview, elapsed_ms: elapsed1 }
            }
            Err(e) => {
                if verbose { eprintln!("    → R1 error: {}", e); }
                signal_from_reqwest_err(&e, elapsed1)
            }
        };

        // Brief yield to let PHP finish cleanup (but not full worker recycle)
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // ── Request 2: Probe ───────────────────────────────────────────────────
        // GET request on the same keep-alive connection.
        // On unpatched: may observe timing anomaly (stale state causes extra work)
        // or response body differences if the stale state influences output.
        let t1 = Instant::now();
        let r2 = client
            .get(target)
            .header("Connection", "keep-alive")
            .header("User-Agent", "shellproof/0.1 (VertexElite; CVE-2026-109619/r2)")
            .header("X-Shellproof-Probe", "stale-check")
            .send()
            .await;

        let elapsed2 = t1.elapsed().as_millis() as u64;

        let sig2 = match r2 {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let ct = resp.headers().get("content-type")
                    .and_then(|v| v.to_str().ok()).map(String::from);
                let bytes = resp.bytes().await.unwrap_or_default();
                let body_preview = String::from_utf8_lossy(&bytes[..bytes.len().min(200)]).to_string();
                if verbose { eprintln!("    → R2 HTTP {} in {}ms", status, elapsed2); }
                ProbeSignal::HttpResponse { status, content_type: ct, body_preview, elapsed_ms: elapsed2 }
            }
            Err(e) => {
                if verbose { eprintln!("    → R2 error: {}", e); }
                signal_from_reqwest_err(&e, elapsed2)
            }
        };

        pair_results.push((sig1, sig2));
    }

    classify(cve, pair_results)
}

fn classify(cve: Vulnerability, pairs: Vec<(ProbeSignal, ProbeSignal)>) -> ProbeResult {
    let mut anomaly_count = 0usize;
    let mut crash_after_poison = 0usize;
    let mut clean_pairs = 0usize;
    let mut all_signals: Vec<ProbeSignal> = Vec::new();

    for (s1, s2) in &pairs {
        all_signals.push(s1.clone());
        all_signals.push(s2.clone());

        // Crash on R2 after clean R1 is a stale-state indicator
        let r1_ok = matches!(s1, ProbeSignal::HttpResponse { status, .. } if *status < 500);
        let r2_crash = matches!(s2, ProbeSignal::ConnectionReset { .. } | ProbeSignal::GatewayError { .. });

        if r1_ok && r2_crash {
            crash_after_poison += 1;
        }

        // Timing anomaly: R2 significantly slower than baseline suggests stale state processing
        let r1_ms = s1.elapsed_ms();
        let r2_ms = s2.elapsed_ms();
        if r1_ms > 0 && r2_ms > r1_ms * 5 && r2_ms > 500 {
            anomaly_count += 1;
        }

        // Both clean and similar timing → likely patched/independent
        let both_clean = matches!(s1, ProbeSignal::HttpResponse { status, .. } if *status < 500)
            && matches!(s2, ProbeSignal::HttpResponse { status, .. } if *status < 500);
        if both_clean {
            clean_pairs += 1;
        }
    }

    // Can't distinguish our probe from normal traffic easily, so we need
    // to look for stale-marker leakage in R2 body specifically
    let stale_leak = pairs.iter().any(|(_, s2)| {
        if let ProbeSignal::HttpResponse { body_preview, .. } = s2 {
            body_preview.contains("SHELLPROOF_STALE_MARKER")
                || body_preview.contains("VES_PROBE_2026")
        } else {
            false
        }
    });

    let evidence = Evidence {
        signal_summary: format!(
            "pairs={} crash-after-poison={} timing-anomalies={} clean-pairs={} stale-leak={}",
            pairs.len(), crash_after_poison, anomaly_count, clean_pairs, stale_leak
        ),
        signals: all_signals.clone(),
        confidence: Confidence::Low, // keep-alive worker affinity is not guaranteed
        attempts: (pairs.len() * 2) as u8,
        probed_at: Utc::now(),
    };

    if stale_leak {
        // If the R2 body literally echoes R1 state back, that's definitive
        return ProbeResult::Vulnerable {
            cve,
            evidence: Evidence {
                confidence: Confidence::High,
                signal_summary: format!("{} + STALE_LEAK_DETECTED", evidence.signal_summary),
                ..evidence
            },
        };
    }

    if crash_after_poison >= 2 {
        return ProbeResult::Vulnerable { cve, evidence };
    }

    // Clean pairs with no anomalies → suggests patched, but low confidence
    // because worker affinity isn't guaranteed
    if clean_pairs == pairs.len() && anomaly_count == 0 {
        return ProbeResult::Inconclusive {
            cve,
            reason: format!(
                "Both requests returned clean responses with no timing anomalies or state leakage \
                 across {} pair(s). This is consistent with a patched system, but keep-alive \
                 worker affinity is not guaranteed — requests may not have landed on the same worker. \
                 Confidence: LOW. Recommend: verify PHP version \
                 (patched: 8.2.35+ / 8.3.36+ / 8.4.27+ / 8.5.12+) directly.",
                pairs.len()
            ),
            signals: all_signals,
        };
    }

    ProbeResult::Inconclusive {
        cve,
        reason: format!(
            "Ambiguous — crash-after-poison={}, timing-anomalies={}, clean-pairs={}. \
             CVE-2026-109619 requires same FPM worker for both requests and a specific \
             PHP application code path. A generic probe has limited reach against this vector. \
             Recommend version-based verification or targeted testing with known-affected PHP app.",
            crash_after_poison, anomaly_count, clean_pairs
        ),
        signals: all_signals,
    }
}
