use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

mod analyzer;

#[derive(Debug, Parser)]
#[command(
    name = "archer",
    version,
    about = "ARCHER — Actix-Web authorization drift prototype"
)]
struct Cli {
    /// Rust/Actix-Web repository to analyze
    path: PathBuf,

    /// Emit the report as JSON for programmatic consumers
    #[arg(long)]
    json: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let report = analyzer::analyze_repository(&cli.path)?;

    if cli.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("ARCHER authorization analysis");
    println!("Repository: {}", cli.path.display());
    println!("Rust files scanned: {}", report.files_scanned);
    if !report.parse_errors.is_empty() {
        println!("Rust files skipped: {}", report.parse_errors.len());
        for error in &report.parse_errors {
            println!("  - {}", error);
        }
    }
    println!("Route candidates: {}", report.routes.len());
    println!();

    for route in &report.routes {
        println!("{} {}", route.method, route.path);
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

    if !report.findings.is_empty() {
        println!("\nPotential authorization drift:");
        for finding in &report.findings {
            println!("{}", finding);
        }
    } else {
        println!("\nNo prototype drift findings.");
    }

    Ok(())
}
