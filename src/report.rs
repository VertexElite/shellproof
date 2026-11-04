//! JSON report structure and terminal summary output.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::fingerprint::Fingerprint;
use crate::probes::ProbeResult;

#[derive(Debug, Serialize, Deserialize)]
pub struct Report {
    pub tool: ToolMeta,
    pub target: String,
    pub scanned_at: DateTime<Utc>,
    pub fingerprint: Fingerprint,
    pub results: Vec<ProbeResult>,
    pub summary: ReportSummary,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ToolMeta {
    pub name: String,
    pub version: String,
    pub author: String,
    pub purpose: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReportSummary {
    pub vulnerable: Vec<String>,   // CVE IDs
    pub patched: Vec<String>,
    pub inconclusive: Vec<String>,
    pub not_applicable: Vec<String>,
    pub errors: Vec<String>,
    pub overall: String,
}

impl Report {
    pub fn new(target: String, fingerprint: Fingerprint, results: Vec<ProbeResult>) -> Self {
        let mut vulnerable = Vec::new();
        let mut patched = Vec::new();
        let mut inconclusive = Vec::new();
        let mut not_applicable = Vec::new();
        let mut errors = Vec::new();

        for r in &results {
            let id = r.cve().cve_id().to_string();
            match r {
                ProbeResult::Vulnerable { .. }    => vulnerable.push(id),
                ProbeResult::Patched { .. }        => patched.push(id),
                ProbeResult::Inconclusive { .. }   => inconclusive.push(id),
                ProbeResult::NotApplicable { .. }  => not_applicable.push(id),
                ProbeResult::Error { .. }          => errors.push(id),
            }
        }

        let overall = if !vulnerable.is_empty() {
            format!("VULNERABLE — {} CVE(s) confirmed exposed", vulnerable.len())
        } else if !patched.is_empty() && inconclusive.is_empty() && errors.is_empty() {
            "PATCHED — all probed CVEs appear patched".to_string()
        } else {
            "INCONCLUSIVE — manual verification recommended".to_string()
        };

        Report {
            tool: ToolMeta {
                name: "shellproof".into(),
                version: env!("CARGO_PKG_VERSION").into(),
                author: "VertexElite Security Research <research@vertexelite.io>".into(),
                purpose: "Behavioral patch-diff scanner — PHP2Shell + Node2Shell".into(),
            },
            target,
            scanned_at: Utc::now(),
            fingerprint,
            results,
            summary: ReportSummary {
                vulnerable,
                patched,
                inconclusive,
                not_applicable,
                errors,
                overall,
            },
        }
    }

    /// Print a clean terminal summary.
    pub fn print_summary(&self) {
        println!();
        println!("\x1b[1m╔══════════════════════════════════════════════════╗\x1b[0m");
        println!("\x1b[1m║              shellproof — scan complete           ║\x1b[0m");
        println!("\x1b[1m╚══════════════════════════════════════════════════╝\x1b[0m");
        println!();
        println!("  Target  : {}", self.target);
        println!("  Scanned : {}", self.scanned_at.format("%Y-%m-%dT%H:%M:%SZ"));
        println!("  Stack   : {}", self.fingerprint.summary());
        println!();

        if !self.summary.vulnerable.is_empty() {
            println!("\x1b[31m  🔴 VULNERABLE\x1b[0m");
            for cve in &self.summary.vulnerable {
                println!("     → {}", cve);
            }
        }
        if !self.summary.patched.is_empty() {
            println!("\x1b[32m  ✅ PATCHED\x1b[0m");
            for cve in &self.summary.patched {
                println!("     → {}", cve);
            }
        }
        if !self.summary.inconclusive.is_empty() {
            println!("\x1b[33m  ⚠️  INCONCLUSIVE\x1b[0m");
            for cve in &self.summary.inconclusive {
                println!("     → {}", cve);
            }
        }
        if !self.summary.not_applicable.is_empty() {
            println!("\x1b[90m  ➖ N/A\x1b[0m");
            for cve in &self.summary.not_applicable {
                println!("     → {}", cve);
            }
        }
        if !self.summary.errors.is_empty() {
            println!("\x1b[35m  ❌ ERROR\x1b[0m");
            for cve in &self.summary.errors {
                println!("     → {}", cve);
            }
        }

        println!();
        let overall_color = if self.summary.vulnerable.is_empty() { "\x1b[32m" } else { "\x1b[31m" };
        println!("  Overall : {}{}\x1b[0m", overall_color, self.summary.overall);
        println!();

        if !self.summary.vulnerable.is_empty() || !self.summary.inconclusive.is_empty() {
            println!("  \x1b[33m⚠ Note: Low/medium confidence probes — confirm with direct version check.\x1b[0m");
            println!("    PHP patches  : 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 (Oct 21 2026)");
            println!("    Node.js fix  : 22.23.4 / 24.22.1 / 26.12.1");
            println!("    Brotli fix   : 1.2.1 | Bun: 1.4.4 | .NET: 8.0.33");
            println!("    CVE-2026-115560: no patch — set session.upload_progress.enabled=0");
            println!();
        }
    }
}
