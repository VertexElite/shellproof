//! Version-first patch assessment.
//!
//! The most reliable, least intrusive signal for these CVEs is the running
//! version compared against the published patch lines. This module turns a
//! fingerprinted version into a verdict with HIGH confidence and sends no
//! payloads at all — it is the core of shellproof's safe-by-default mode.
//!
//! Patch lines:
//!   PHP   (109618/109619): 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12  (Oct 21 2026)
//!   Node  (111497):        22.23.4 / 24.22.1 / 26.12.1
//!   115560 has no code patch — assessed by feature, not version (see php_session).

use chrono::Utc;

use crate::fingerprint::Fingerprint;
use crate::probes::{Confidence, Evidence, ProbeResult, Vulnerability};

/// Parse "8.3.6" / "8.3.6-0ubuntu0.24.04" → (8, 3, 6). Tolerant of trailing junk.
pub fn parse3(v: &str) -> Option<(u32, u32, u32)> {
    let cleaned: String = v
        .trim()
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let mut it = cleaned.split('.');
    let maj = it.next()?.parse().ok()?;
    let min = it.next().unwrap_or("0").parse().unwrap_or(0);
    let pat = it.next().unwrap_or("0").parse().unwrap_or(0);
    Some((maj, min, pat))
}

/// PHP: true = affected (in a vulnerable range), false = at/above the patch.
pub fn php_affected(ver: &str) -> Option<bool> {
    let (maj, min, pat) = parse3(ver)?;
    if maj < 8 {
        return Some(true); // all < 8.x is EOL → affected
    }
    if maj > 8 {
        return Some(false);
    }
    Some(match min {
        0 | 1 => true,   // 8.0 / 8.1 are EOL
        2 => pat < 35,   // 8.2.35
        3 => pat < 36,   // 8.3.36
        4 => pat < 27,   // 8.4.27
        5 => pat < 12,   // 8.5.12
        _ => false,      // 8.6+ (future) assumed patched
    })
}

/// Node.js: true = affected, false = at/above the patch. Best-effort.
pub fn node_affected(ver: &str) -> Option<bool> {
    let (maj, min, pat) = parse3(ver)?;
    Some(match maj {
        0..=21 => true,                       // EOL / odd lines
        22 => (min, pat) < (23, 4),           // 22.23.4
        23 => true,                           // odd, EOL
        24 => (min, pat) < (22, 1),           // 24.22.1
        25 => true,                           // odd, EOL
        26 => (min, pat) < (12, 1),           // 26.12.1
        _ => false,                           // 27+ assumed patched
    })
}

fn verdict(cve: &Vulnerability, affected: bool, detail: String) -> ProbeResult {
    let evidence = Evidence {
        signal_summary: detail,
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

/// Version-based verdict for a CVE, if the relevant version was fingerprinted.
/// Returns None when the version is unknown (caller falls back to passive/active).
pub fn version_verdict(cve: &Vulnerability, fp: &Fingerprint) -> Option<ProbeResult> {
    match cve {
        Vulnerability::Cve111497 => {
            let v = fp.node_version()?;
            let aff = node_affected(&v)?;
            Some(verdict(
                cve,
                aff,
                format!(
                    "Node {} → {} (patch line 22.23.4 / 24.22.1 / 26.12.1)",
                    v,
                    if aff { "AFFECTED" } else { "patched" }
                ),
            ))
        }
        Vulnerability::Cve109618 | Vulnerability::Cve109619 => {
            let v = fp.php_version.clone()?;
            let aff = php_affected(&v)?;
            Some(verdict(
                cve,
                aff,
                format!(
                    "PHP {} → {} (patch line 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12)",
                    v,
                    if aff { "AFFECTED" } else { "patched" }
                ),
            ))
        }
        // 115560 has no code patch — version can't clear it; assessed by feature.
        Vulnerability::Cve115560 => None,
    }
}
