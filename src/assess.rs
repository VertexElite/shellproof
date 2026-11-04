//! Assessment orchestrator — ties version-first (safe) analysis to the optional
//! behavioral probes, enforcing safe-by-default behavior.
//!
//! Default (passive): version comparison + feature inference only. No crash
//! payloads are ever sent.
//! --active: additionally run the behavioral probe and reconcile it with the
//! version verdict (version is authoritative when known; a behavioral crash can
//! still escalate an apparently-patched box to VULNERABLE with a note).

use chrono::Utc;
use reqwest::Client;

use crate::cli::ProbeKind;
use crate::fingerprint::Fingerprint;
use crate::probes::{self, Confidence, Evidence, ProbeResult, Vulnerability};
use crate::version;

fn kind_to_cve(kind: &ProbeKind) -> Vulnerability {
    match kind {
        ProbeKind::BrotliOob => Vulnerability::Cve111497,
        ProbeKind::PhpOom => Vulnerability::Cve109618,
        ProbeKind::PhpStale => Vulnerability::Cve109619,
        ProbeKind::PhpSession => Vulnerability::Cve115560,
    }
}

fn inconclusive(cve: Vulnerability, reason: &str) -> ProbeResult {
    ProbeResult::Inconclusive { cve, reason: reason.to_string(), signals: vec![] }
}

fn note(cve: &Vulnerability, affected: bool, summary: String) -> ProbeResult {
    let evidence = Evidence {
        signal_summary: summary,
        signals: vec![],
        confidence: Confidence::High,
        attempts: 0,
        probed_at: Utc::now(),
    };
    if affected {
        ProbeResult::Vulnerable { cve: cve.clone(), evidence }
    } else {
        ProbeResult::Patched { cve: cve.clone(), evidence }
    }
}

/// Run the behavioral probe for a kind (the intrusive path).
async fn behavioral(
    kind: &ProbeKind,
    client: &Client,
    target: &str,
    verbose: bool,
    attempts: u8,
) -> ProbeResult {
    match kind {
        ProbeKind::BrotliOob => probes::brotli_oob::probe(client, target, verbose, attempts).await,
        ProbeKind::PhpOom => probes::php_oom::probe(client, target, verbose, attempts).await,
        ProbeKind::PhpStale => probes::php_stale::probe(client, target, verbose, attempts).await,
        ProbeKind::PhpSession => probes::php_session::probe(client, target, verbose, attempts).await,
    }
}

/// Reconcile a version verdict (authoritative) with a behavioral result.
fn reconcile(cve: &Vulnerability, vv: ProbeResult, beh: ProbeResult) -> ProbeResult {
    let vv_sum = match &vv {
        ProbeResult::Vulnerable { evidence, .. } | ProbeResult::Patched { evidence, .. } => {
            evidence.signal_summary.clone()
        }
        _ => String::new(),
    };
    match (&vv, &beh) {
        // Version says affected → stay VULNERABLE, add behavioral corroboration.
        (ProbeResult::Vulnerable { .. }, _) => note(
            cve,
            true,
            format!("{} | behavioral: {}", vv_sum, beh.verdict_label()),
        ),
        // Version says patched but a crash was still observed → escalate with a loud note.
        (ProbeResult::Patched { .. }, ProbeResult::Vulnerable { evidence, .. }) => note(
            cve,
            true,
            format!(
                "VERSION reports patched ({}) but behavioral probe observed a crash: {} — \
                 investigate (backport mismatch, second vuln, or shared-worker artifact)",
                vv_sum, evidence.signal_summary
            ),
        ),
        // Version patched, behavioral agrees/can't contradict → PATCHED.
        (ProbeResult::Patched { .. }, _) => note(cve, false, format!("{} (behavioral: {})", vv_sum, beh.verdict_label())),
        _ => beh,
    }
}

/// Assess one CVE. `active` gates the behavioral/crash probes.
pub async fn run(
    kind: &ProbeKind,
    client: &Client,
    target: &str,
    fp: &Fingerprint,
    active: bool,
    verbose: bool,
    attempts: u8,
) -> ProbeResult {
    let cve = kind_to_cve(kind);
    let vv = version::version_verdict(&cve, fp);

    if !active {
        // ── SAFE DEFAULT: no crash payloads ──────────────────────────────────
        return match kind {
            // 115560: passive feature inference (no code patch exists).
            ProbeKind::PhpSession => probes::php_session::probe(client, target, verbose, attempts).await,
            // PHP/Node CVEs: pure version comparison.
            _ => vv.unwrap_or_else(|| {
                let what = if matches!(kind, ProbeKind::BrotliOob) { "Node" } else { "PHP" };
                inconclusive(
                    cve.clone(),
                    &format!(
                        "{} version not exposed in headers — cannot assess passively. \
                         Re-run with --active (and --authorized) against a target you own \
                         to use the behavioral crash-diff probe.",
                        what
                    ),
                )
            }),
        };
    }

    // ── ACTIVE: behavioral probe, reconciled with version (if known) ─────────
    let beh = behavioral(kind, client, target, verbose, attempts).await;
    match vv {
        Some(v) => reconcile(&cve, v, beh),
        None => beh,
    }
}
