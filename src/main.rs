//! shellproof — VertexElite Security Research
//!
//! Behavioral patch-diff scanner for:
//!   CVE-2026-111497 — Node2Shell / HTTP2Shell (Brotli OOB write)
//!   CVE-2026-109618 — PHP2Shell OOM corruption
//!   CVE-2026-109619 — PHP2Shell stale FPM global state
//!   CVE-2026-115560 — PHP session serializer mismatch (no patch yet)
//!
//! SAFE BY DEFAULT: a plain run is passive (version + feature inference, no crash
//! payloads). The behavioral crash-diff probes are opt-in via --active and require
//! --authorized against non-local targets.
//!
//! Usage:
//!   shellproof https://your-site.example            # passive, safe
//!   shellproof https://your-site.example --active --authorized
//!   shellproof https://127.0.0.1:8099 --active       # local target, no --authorized needed
//!   shellproof https://your-site.example --json      # JSON to stdout → OCaml interp

use anyhow::Result;
use clap::Parser;
use reqwest::ClientBuilder;
use std::time::Duration;

mod assess;
mod cli;
mod fingerprint;
mod payload;
mod probes;
mod report;
mod version;

use cli::Cli;
use report::Report;

/// A target is "local" if it resolves to loopback / private space or is a bare
/// hostname — these need no --authorized for active probing.
fn is_local_target(target: &str) -> bool {
    let host = match url::Url::parse(target) {
        Ok(u) => u.host_str().map(|h| h.to_string()).unwrap_or_default(),
        Err(_) => target.to_string(),
    };
    let h = host.to_lowercase();
    if h == "localhost" || h.ends_with(".local") || h.ends_with(".localhost") {
        return true;
    }
    if !h.contains('.') && !h.contains(':') {
        return true; // bare hostname (e.g. a container name)
    }
    if let Ok(ip) = h.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
            std::net::IpAddr::V6(v6) => v6.is_loopback(),
        };
    }
    h.starts_with("127.") || h.starts_with("10.") || h.starts_with("192.168.")
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let quiet = cli.json;
    macro_rules! human {
        ($($arg:tt)*) => { if !quiet { println!($($arg)*); } };
    }

    // ── Authorization gate for active probing ────────────────────────────────
    if cli.active && !is_local_target(&cli.target) && !cli.authorized {
        eprintln!(
            "\x1b[31mRefusing --active against a non-local target without --authorized.\x1b[0m\n\
             The behavioral probes send crash-inducing payloads and can disrupt an\n\
             unpatched server. Re-run with --authorized only if you own or are\n\
             explicitly authorized to actively test:\n    {}\n\
             (Passive assessment needs neither flag — just drop --active.)",
            cli.target
        );
        std::process::exit(2);
    }

    let mode = if cli.active { "ACTIVE (behavioral crash-diff)" } else { "PASSIVE (safe: version + feature)" };

    // ── Banner ───────────────────────────────────────────────────────────────
    human!(
        "\n\x1b[1mshellproof\x1b[0m v{} — VertexElite Security Research",
        env!("CARGO_PKG_VERSION")
    );
    human!("Behavioral patch-diff scanner: PHP2Shell + Node2Shell");
    human!("─────────────────────────────────────────────────────");
    human!("Target  : {}", cli.target);
    human!("Mode    : {}", mode);
    human!(
        "Probes  : {}",
        cli.active_probes().iter().map(|p| format!("{:?}", p)).collect::<Vec<_>>().join(", ")
    );
    human!("");
    if cli.active {
        eprintln!("  \x1b[33mActive mode: sending behavioral probe payloads.\x1b[0m");
    }

    // ── HTTP client ──────────────────────────────────────────────────────────
    let mut builder = ClientBuilder::new()
        .timeout(Duration::from_secs(cli.timeout))
        .user_agent("shellproof/0.2 (VertexElite Security Research)");
    if cli.insecure {
        builder = builder.danger_accept_invalid_certs(true);
        eprintln!("  \x1b[33mWarning: TLS verification disabled (--insecure)\x1b[0m");
    }
    builder = if cli.follow_redirects {
        builder.redirect(reqwest::redirect::Policy::limited(5))
    } else {
        builder.redirect(reqwest::redirect::Policy::none())
    };
    let client = builder.build()?;

    // ── Fingerprint ──────────────────────────────────────────────────────────
    if !quiet { print!("Fingerprinting ... "); }
    let fp = fingerprint::fingerprint(&client, &cli.target).await;
    human!("{}", fp.summary());
    human!("");

    if fp.behind_cloudflare() {
        human!("  \x1b[33m⚠ Cloudflare at edge — origin version may be masked; probe the origin directly for a definitive result.\x1b[0m");
        human!("");
    }

    // ── Assess each CVE (version-first; behavioral only under --active) ───────
    let active = cli.active_probes();
    let mut results = Vec::new();

    for kind in &active {
        let (cve_id, alias) = match kind {
            cli::ProbeKind::BrotliOob => ("CVE-2026-111497", "Node2Shell/HTTP2Shell"),
            cli::ProbeKind::PhpOom => ("CVE-2026-109618", "PHP2Shell-OOM"),
            cli::ProbeKind::PhpStale => ("CVE-2026-109619", "PHP2Shell-Stale"),
            cli::ProbeKind::PhpSession => ("CVE-2026-115560", "PHP-Session"),
        };
        if !quiet { print!("[{}] {} ... ", cve_id, alias); } else { eprint!("[{}] {} ... ", cve_id, alias); }

        let result = assess::run(kind, &client, &cli.target, &fp, cli.active, cli.verbose, cli.attempts).await;

        if quiet {
            eprintln!("{}", result.verdict_label());
        } else {
            println!("{}", result.verdict_colored());
            if cli.verbose {
                match &result {
                    probes::ProbeResult::Inconclusive { reason, .. } => println!("    \x1b[33m↳ {}\x1b[0m", reason),
                    probes::ProbeResult::NotApplicable { reason, .. } => println!("    \x1b[90m↳ {}\x1b[0m", reason),
                    probes::ProbeResult::Error { error, .. } => println!("    \x1b[35m↳ {}\x1b[0m", error),
                    probes::ProbeResult::Vulnerable { evidence, .. } => {
                        println!("    \x1b[31m↳ {} (confidence: {})\x1b[0m", evidence.signal_summary, evidence.confidence.label());
                    }
                    probes::ProbeResult::Patched { evidence, .. } => {
                        println!("    \x1b[32m↳ {} (confidence: {})\x1b[0m", evidence.signal_summary, evidence.confidence.label());
                    }
                }
            }
        }
        results.push(result);
    }

    // ── Report ───────────────────────────────────────────────────────────────
    let report = Report::new(cli.target.clone(), fp, results);
    if cli.json {
        println!("{}", serde_json::to_string(&report)?);
    } else {
        report.print_summary();
    }
    if let Some(ref out_path) = cli.output {
        std::fs::write(out_path, serde_json::to_string_pretty(&report)?)?;
        human!("  JSON report → {}", out_path);
        human!("");
    }

    if !report.summary.vulnerable.is_empty() {
        std::process::exit(1);
    }
    Ok(())
}
