use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

mod analyzer;

#[derive(Debug, Parser)]
#[command(name = "archer", version, about = "ARCHER — Actix-Web authorization drift prototype")]
struct Cli {
    /// Rust/Actix-Web repository to analyze
    path: PathBuf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let report = analyzer::analyze_repository(&cli.path)?;

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
        println!(
            "{:<7} {:<28} auth={:<12} line={}",
            route.method,
            route.path,
            route.authorization,
            route.line
        );
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
