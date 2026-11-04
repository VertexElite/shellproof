use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "shellproof",
    about = "Behavioral patch-diff scanner — PHP2Shell + Node2Shell",
    long_about = "VertexElite Security Research — shellproof v0.1.0\n\
                  \n\
                  Probes CVE-2026-109618, CVE-2026-109619, CVE-2026-115560 (PHP2Shell)\n\
                  and CVE-2026-111497 (Node2Shell/HTTP2Shell) using behavioral patch-diff\n\
                  detection. No exploit delivery — observes response signals to classify\n\
                  patch status as: PATCHED / VULNERABLE / INCONCLUSIVE / N/A.\n\
                  \n\
                  Default (no flags): runs all four probes.",
    version
)]
pub struct Cli {
    /// Target URL — e.g. https://target.example.com or https://target.example.com:3000
    pub target: String,

    /// Probe CVE-2026-111497 (Node2Shell / Brotli OOB write)
    #[arg(long, help = "Node2Shell: malformed Brotli → crash vs clean-reject diff")]
    pub node2shell: bool,

    /// Probe CVE-2026-109618 (PHP2Shell OOM corruption)
    #[arg(long, help = "PHP2Shell OOM: memory-pressure body → worker-crash vs clean-500 diff")]
    pub php_oom: bool,

    /// Probe CVE-2026-109619 (PHP2Shell stale global state, FPM)
    #[arg(long, help = "PHP2Shell Stale: keep-alive two-request state-isolation diff")]
    pub php_stale: bool,

    /// Probe CVE-2026-115560 (PHP session serializer mismatch, no-patch-yet)
    #[arg(long, help = "PHP session: upload_progress + serializer-handler exposure check")]
    pub php_session: bool,

    /// Write structured JSON report to this path
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<String>,

    /// Accept invalid / self-signed TLS certificates
    #[arg(long)]
    pub insecure: bool,

    /// Verbose: print per-attempt signal details
    #[arg(short, long)]
    pub verbose: bool,

    /// Per-request timeout in seconds
    #[arg(long, default_value_t = 10, value_name = "SECS")]
    pub timeout: u64,

    /// Number of probe attempts per CVE (increases confidence)
    #[arg(long, default_value_t = 3, value_name = "N")]
    pub attempts: u8,

    /// Follow redirects (max 5)
    #[arg(long)]
    pub follow_redirects: bool,

    /// Emit the machine-readable JSON report to stdout (suppresses the human banner;
    /// feed this into the OCaml interpreter). Human progress still goes to stderr.
    #[arg(long)]
    pub json: bool,

    /// Enable the behavioral (crash-diff) probes. OFF by default — the default run
    /// is passive (version + feature inference only, no crash payloads). Active
    /// probes can disrupt an unpatched worker, so only use them on hosts you own.
    #[arg(long)]
    pub active: bool,

    /// Confirm you own or are authorized to actively test the target. Required by
    /// --active against any non-local target.
    #[arg(long)]
    pub authorized: bool,
}

impl Cli {
    /// Returns which probes to run. If no specific probe flag is set, run all.
    pub fn active_probes(&self) -> Vec<ProbeKind> {
        let any_specific = self.node2shell || self.php_oom || self.php_stale || self.php_session;
        if !any_specific {
            return vec![
                ProbeKind::BrotliOob,
                ProbeKind::PhpOom,
                ProbeKind::PhpStale,
                ProbeKind::PhpSession,
            ];
        }
        let mut probes = Vec::new();
        if self.node2shell  { probes.push(ProbeKind::BrotliOob); }
        if self.php_oom     { probes.push(ProbeKind::PhpOom); }
        if self.php_stale   { probes.push(ProbeKind::PhpStale); }
        if self.php_session { probes.push(ProbeKind::PhpSession); }
        probes
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ProbeKind {
    BrotliOob,
    PhpOom,
    PhpStale,
    PhpSession,
}
