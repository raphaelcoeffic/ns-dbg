use std::process;

use anstream::{eprintln, println};
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use owo_colors::OwoColorize;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List installed packages
    List,
    /// Search packages
    Search {
        #[arg(required = true)]
        keywords: Vec<String>,
    },
    /// Install a package
    Install { name: String },
    /// Remove a package
    Remove { name: String },
}

fn init_logging() {
    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Info)
        .parse_env("LOGLEVEL")
        .format_timestamp(None)
        .format_target(false)
        .init();
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    init_logging();

    match &cli.command {
        Commands::List => {
            for pkg in dive::nixpkgs::all_packages_sorted()? {
                println!("{}  ({})", pkg.name.bold(), pkg.version.dimmed());
            }
        }
        Commands::Search { keywords } => {
            let matches = dive::nixpkgs::query(keywords)?;
            if matches.is_empty() {
                println!("{}", "No matches".bold());
            } else {
                for pkg in matches {
                    println!(
                        "* {} ({})",
                        pkg.name.bold(),
                        pkg.version.dimmed()
                    );
                    if let Some(description) = pkg.description {
                        println!("    {}", description);
                    }
                    println!();
                }
            }
        }
        Commands::Install { name } => {
            let pkgs = dive::nixpkgs::all_packages_sorted()?;
            if pkgs.iter().any(|p| &p.name == name) {
                eprintln!("error: '{}' is already installed", name);
                process::exit(1);
            }
            match dive::nixpkgs::find_package(name)? {
                None => {
                    eprintln!("error: '{}' does not exist", name);
                    process::exit(1);
                }
                Some(pkg) => {
                    if let Err(err) = dive::nixpkgs::install_package(pkg)
                        .context("failed to install package")
                    {
                        eprintln!("error: {err}");
                        process::exit(1);
                    }
                }
            }
        }
        Commands::Remove { name } => {
            let pkgs = dive::nixpkgs::all_packages_sorted()?;
            let maybe_pkg = pkgs.iter().find(|p| &p.name == name);
            if maybe_pkg.is_none() {
                eprintln!("error: '{}' is not installed", name);
                process::exit(1);
            }
            let pkg = maybe_pkg.unwrap();
            if pkg.is_builtin() {
                eprintln!(
                    "Error: '{}' is a built-in package and cannot be removed",
                    name
                );
                process::exit(1);
            }
            return dive::nixpkgs::remove_package(name)
                .context("failed to remove package");
        }
    }

    Ok(())
}
