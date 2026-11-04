pub mod brotli_oob;
pub mod php_oom;
pub mod php_session;
pub mod php_stale;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────
// Vulnerability identifiers
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Vulnerability {
    /// Node2Shell / HTTP2Shell — OOB write in Brotli decoder
    #[serde(rename = "CVE-2026-111497")]
    Cve111497,
    /// PHP2Shell — OOM corruption during request cleanup
    #[serde(rename = "CVE-2026-109618")]
    Cve109618,
    /// PHP2Shell — stale global state in FPM worker reuse
    #[serde(rename = "CVE-2026-109619")]
    Cve109619,
    /// PHP session serializer handler mismatch (no emergency patch)
    #[serde(rename = "CVE-2026-115560")]
    Cve115560,
}

impl Vulnerability {
    pub fn cve_id(&self) -> &'static str {
        match self {
            Vulnerability::Cve111497 => "CVE-2026-111497",
            Vulnerability::Cve109618 => "CVE-2026-109618",
            Vulnerability::Cve109619 => "CVE-2026-109619",
            Vulnerability::Cve115560 => "CVE-2026-115560",
        }
    }

    pub fn alias(&self) -> &'static str {
        match self {
            Vulnerability::Cve111497 => "Node2Shell/HTTP2Shell",
            Vulnerability::Cve109618 => "PHP2Shell-OOM",
            Vulnerability::Cve109619 => "PHP2Shell-Stale",
            Vulnerability::Cve115560 => "PHP2Shell-Session",
        }
    }

    /// Fixed versions for primary affected components
    pub fn fixed_in(&self) -> &'static str {
        match self {
            Vulnerability::Cve111497 => "Node.js 22.23.4 / 24.22.1 / 26.12.1 | Brotli 1.2.1 | Bun 1.4.4 | .NET 8.0.33",
            Vulnerability::Cve109618 => "PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12",
            Vulnerability::Cve109619 => "PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12",
            Vulnerability::Cve115560 => "No patch yet — mitigation: session.upload_progress.enabled=0",
        }
    }
}

// ─────────────────────────────────────────────────────────────
// Probe signals — raw observations from a single attempt
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProbeSignal {
    /// Server returned a clean HTTP status with body
    HttpResponse {
        status: u16,
        content_type: Option<String>,
        body_preview: String,
        elapsed_ms: u64,
    },
    /// TCP connection was reset mid-flight (process crash indicator)
    ConnectionReset { elapsed_ms: u64 },
    /// Server timed out (no response)
    Timeout { after_ms: u64 },
    /// Upstream gateway error (502/503 — origin crashed)
    GatewayError {
        status: u16,
        elapsed_ms: u64,
    },
    /// TLS or network error before HTTP layer
    NetworkError { detail: String },
}

impl ProbeSignal {
    pub fn elapsed_ms(&self) -> u64 {
        match self {
            ProbeSignal::HttpResponse { elapsed_ms, .. } => *elapsed_ms,
            ProbeSignal::ConnectionReset { elapsed_ms } => *elapsed_ms,
            ProbeSignal::Timeout { after_ms } => *after_ms,
            ProbeSignal::GatewayError { elapsed_ms, .. } => *elapsed_ms,
            ProbeSignal::NetworkError { .. } => 0,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            ProbeSignal::HttpResponse { .. } => "http_response",
            ProbeSignal::ConnectionReset { .. } => "connection_reset",
            ProbeSignal::Timeout { .. } => "timeout",
            ProbeSignal::GatewayError { .. } => "gateway_error",
            ProbeSignal::NetworkError { .. } => "network_error",
        }
    }
}

// ─────────────────────────────────────────────────────────────
// Evidence — collected signals + metadata for a probe run
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    /// Human-readable description of what signal was observed
    pub signal_summary: String,
    /// All raw signals collected across attempts
    pub signals: Vec<ProbeSignal>,
    /// Detection confidence: high / medium / low
    pub confidence: Confidence,
    /// Probe attempt count
    pub attempts: u8,
    /// UTC timestamp of probe run
    pub probed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

impl Confidence {
    pub fn label(&self) -> &'static str {
        match self {
            Confidence::High => "HIGH",
            Confidence::Medium => "MEDIUM",
            Confidence::Low => "LOW",
        }
    }
}

// ─────────────────────────────────────────────────────────────
// Final probe verdict
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProbeResult {
    Patched {
        cve: Vulnerability,
        evidence: Evidence,
    },
    Vulnerable {
        cve: Vulnerability,
        evidence: Evidence,
    },
    Inconclusive {
        cve: Vulnerability,
        reason: String,
        signals: Vec<ProbeSignal>,
    },
    NotApplicable {
        cve: Vulnerability,
        reason: String,
    },
    Error {
        cve: Vulnerability,
        error: String,
    },
}

impl ProbeResult {
    pub fn verdict_label(&self) -> &'static str {
        match self {
            ProbeResult::Patched { .. }        => "PATCHED",
            ProbeResult::Vulnerable { .. }     => "VULNERABLE",
            ProbeResult::Inconclusive { .. }   => "INCONCLUSIVE",
            ProbeResult::NotApplicable { .. }  => "N/A",
            ProbeResult::Error { .. }          => "ERROR",
        }
    }

    pub fn verdict_colored(&self) -> String {
        let (color, label) = match self {
            ProbeResult::Patched { .. }       => ("\x1b[32m", "✅ PATCHED"),
            ProbeResult::Vulnerable { .. }    => ("\x1b[31m", "🔴 VULNERABLE"),
            ProbeResult::Inconclusive { .. }  => ("\x1b[33m", "⚠️  INCONCLUSIVE"),
            ProbeResult::NotApplicable { .. } => ("\x1b[90m", "➖ N/A"),
            ProbeResult::Error { .. }         => ("\x1b[35m", "❌ ERROR"),
        };
        format!("{}{}\x1b[0m", color, label)
    }

    pub fn cve(&self) -> &Vulnerability {
        match self {
            ProbeResult::Patched { cve, .. }        => cve,
            ProbeResult::Vulnerable { cve, .. }     => cve,
            ProbeResult::Inconclusive { cve, .. }   => cve,
            ProbeResult::NotApplicable { cve, .. }  => cve,
            ProbeResult::Error { cve, .. }          => cve,
        }
    }

    pub fn is_vulnerable(&self) -> bool {
        matches!(self, ProbeResult::Vulnerable { .. })
    }
}

// ─────────────────────────────────────────────────────────────
// Helper: collect signal from reqwest error
// ─────────────────────────────────────────────────────────────

pub fn signal_from_reqwest_err(err: &reqwest::Error, elapsed_ms: u64) -> ProbeSignal {
    let msg = err.to_string().to_lowercase();
    if err.is_timeout() {
        ProbeSignal::Timeout { after_ms: elapsed_ms }
    } else if msg.contains("connection reset")
        || msg.contains("connection refused")
        || msg.contains("broken pipe")
        || msg.contains("reset by peer")
    {
        ProbeSignal::ConnectionReset { elapsed_ms }
    } else {
        ProbeSignal::NetworkError {
            detail: err.to_string(),
        }
    }
}
