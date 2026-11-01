use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

mod analyzer;

#[derive(Debug, Parser)]
#[command(
    name = "archer",
    version,
    about = "ARCHER — AST-based authorization drift detection framework"
)]
struct Cli {
    /// Rust/Actix-Web repository or file to analyze
    path: PathBuf,

    /// Emit the report as JSON for programmatic consumers
    #[arg(long)]
    json: bool,

    /// Emit the Authorization Relationship Graph in Graphviz DOT format
    #[arg(long)]
    graph: bool,

    /// Perform change-aware drift analysis against a Git commit, branch, or HEAD~1
    #[arg(long)]
    diff: Option<Option<String>>,

    /// Deeply explain the authorization contract, peers, and provenance for a specific route
    #[arg(long)]
    explain: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Change-aware drift analysis mode
    if let Some(git_ref_opt) = &cli.diff {
        let diff_report = analyzer::analyze_repository_diff(&cli.path, git_ref_opt.as_deref())?;
        if cli.json {
            println!("{}", serde_json::to_string_pretty(&diff_report)?);
            return Ok(());
        }

        println!("============================================================");
        println!("ARCHER Change-Aware Authorization Drift Analysis");
        println!("============================================================");
        println!("Target Repository : {}", cli.path.display());
        println!("Git Base Ref      : {}", diff_report.base_ref);
        println!("Changed RS Files  : {}", diff_report.changed_files.len());
        for file in &diff_report.changed_files {
            println!("  - {}", file.display());
        }
        println!("Affected Routes   : {}", diff_report.affected_routes.len());
        println!(
            "New Drift Findings: {}",
            diff_report.newly_introduced_drifts.len()
        );
        println!();

        if !diff_report.newly_introduced_drifts.is_empty() {
            println!("⚠️  NEWLY INTRODUCED AUTHORIZATION DRIFTS:");
            for (i, finding) in diff_report.newly_introduced_drifts.iter().enumerate() {
                println!(
                    "[{}] {:?} in {} {} ({}:{})",
                    i + 1,
                    finding.category,
                    finding.suspicious_route.method,
                    finding.suspicious_route.path,
                    finding.suspicious_route.file.display(),
                    finding.suspicious_route.line
                );
                println!("    Inferred Contract : {}", finding.invariant.description);
                println!("    Confidence        : {:?}", finding.confidence);
                println!("    Explanation       : {}", finding.explanation);
                println!("    Remediation       : {}", finding.remediation);
                println!();
            }
        } else {
            println!("✓ No newly introduced authorization drift detected in changed routes.");
        }

        return Ok(());
    }

    let report = analyzer::analyze_repository(&cli.path)?;

    if cli.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    if cli.graph {
        if let Some(graph) = &report.graph {
            println!("{}", graph.to_dot());
        } else {
            eprintln!("No graph available in report.");
        }
        return Ok(());
    }

    if let Some(target_path) = &cli.explain {
        println!("============================================================");
        println!("ARCHER Route Authorization Explainability: {}", target_path);
        println!("============================================================");
        let matching_routes: Vec<_> = report
            .routes
            .iter()
            .filter(|r| r.path == *target_path || r.path.contains(target_path))
            .collect();

        if matching_routes.is_empty() {
            println!("No route matching '{}' was discovered.", target_path);
            return Ok(());
        }

        for route in matching_routes {
            println!("Route              : {} {}", route.method, route.path);
            println!(
                "Scope Prefix       : {}",
                if route.scope_prefix.is_empty() {
                    "/"
                } else {
                    &route.scope_prefix
                }
            );
            println!(
                "Source Location    : {}:{}",
                route.file.display(),
                route.line
            );
            println!(
                "Handler Function   : {}",
                route.handler.as_deref().unwrap_or("<none>")
            );
            println!("Handler Resolution : {:?}", route.handler_resolution);
            println!("Security Status    : {:?}", route.security_status());
            println!("Recognized Evidence: {}", route.evidence_summary());

            let associated_finding = report.finding_details.iter().find(|f| {
                f.suspicious_route.path == route.path && f.suspicious_route.method == route.method
            });
            if let Some(finding) = associated_finding {
                println!("\n  ⚠️  Authorization Drift Detected!");
                println!("  Category   : {:?}", finding.category);
                println!("  Confidence : {:?}", finding.confidence);
                println!("  Contract   : {}", finding.invariant.description);
                println!("  Explanation: {}", finding.explanation);
                println!("  Remediation: {}", finding.remediation);
                println!(
                    "  Supporting Peers ({}):",
                    finding.authorized_peer_routes.len()
                );
                for peer in &finding.authorized_peer_routes {
                    println!(
                        "    - {} {} -> {}",
                        peer.method,
                        peer.path,
                        peer.authorization
                            .iter()
                            .map(|e| format!("{:?}({})", e.kind, e.mechanism))
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                }
            } else if route.is_authorized() {
                println!("\n  ✓ Route satisfies verified authorization requirements.");
            } else {
                println!("\n  ℹ️ Route is either unanalyzed or consistent with its peer context.");
            }
            println!("------------------------------------------------------------");
        }
        return Ok(());
    }

    println!("============================================================");
    println!("ARCHER Authorization Analysis Report");
    println!("============================================================");
    println!("Repository Scanned : {}", cli.path.display());
    println!("Rust Files Scanned : {}", report.files_scanned);
    if !report.parse_errors.is_empty() {
        println!("Rust Files Skipped : {}", report.parse_errors.len());
        for error in &report.parse_errors {
            println!("  - {}", error);
        }
    }
    if let Some(summary) = &report.summary {
        println!(
            "Route Inventory    : {} routes ({} Protected, {} Unprotected, {} Unknown)",
            summary.total_routes,
            summary.protected_routes,
            summary.unprotected_routes,
            summary.unknown_routes
        );
        println!(
            "Analysis Layers    : {} Peer Groups, {} Inferred Invariants",
            summary.peer_groups_count, summary.inferred_invariants_count
        );
    } else {
        println!("Route candidates   : {}", report.routes.len());
    }
    println!("------------------------------------------------------------");

    for route in &report.routes {
        println!("{} {}", route.method, route.path);
        println!("  status: {:?}", route.security_status());
        if route.authorization.is_empty() {
            println!("  authorization:");
            println!("    ✗ No recognized authorization evidence");
        } else {
            println!("  authorization:");
            for evidence in &route.authorization {
                println!("    ✓ {:?}", evidence.kind);
                println!("      mechanism: {}", evidence.mechanism);
                println!(
                    "      symbol: {}",
                    evidence.symbol.as_deref().unwrap_or("<none>")
                );
                println!(
                    "      location: {}:{}",
                    evidence.file.display(),
                    evidence.line
                );
                println!(
                    "      handler: {}",
                    evidence.handler.as_deref().unwrap_or("<none>")
                );
                println!("      strength: {:?}", evidence.strength);
            }
        }
    }

    if !report.finding_details.is_empty() {
        println!("\n============================================================");
        println!(
            "Potential Authorization Drift Findings ({}):",
            report.finding_details.len()
        );
        println!("============================================================");
        for (i, finding) in report.finding_details.iter().enumerate() {
            println!(
                "\n[{}] {:?} (Confidence: {:?})",
                i + 1,
                finding.category,
                finding.confidence
            );
            println!(
                "  Suspicious Route : {} {} ({}:{})",
                finding.suspicious_route.method,
                finding.suspicious_route.path,
                finding.suspicious_route.file.display(),
                finding.suspicious_route.line
            );
            println!("  Inferred Contract: {}", finding.invariant.description);
            println!("  Explanation      : {}", finding.explanation);
            println!("  Remediation      : {}", finding.remediation);
            println!(
                "  Peer Consensus   : {}/{} authorized peers in group '{}'",
                finding.authorized_peer_routes.len(),
                finding.invariant.total_routes,
                finding.peer_group_id
            );
            for peer in &finding.authorized_peer_routes {
                println!(
                    "    - {} {} ({}:{}) -> {}",
                    peer.method,
                    peer.path,
                    peer.file.display(),
                    peer.line,
                    if peer.authorization.is_empty() {
                        "none".to_string()
                    } else {
                        peer.authorization
                            .iter()
                            .map(|e| format!("{:?}({})", e.kind, e.mechanism))
                            .collect::<Vec<_>>()
                            .join(", ")
                    }
                );
            }
        }
    } else {
        println!("\nNo potential authorization drift findings detected.");
    }

    Ok(())
}
