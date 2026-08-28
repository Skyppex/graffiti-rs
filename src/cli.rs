use std::{path::PathBuf, str::FromStr};

use clap::{ArgGroup, Parser, Subcommand};
use tracing::level_filters::LevelFilter;

use crate::path_utils::get_path;

#[derive(Debug, Clone, Parser)]
#[command(group = ArgGroup::new("log").args(["log_file", "log_to_stderr"]).required(false).multiple(false))]
pub struct Cli {
    /// The path to the log file
    #[arg(long)]
    pub log_file: Option<PathBuf>,

    /// Log to stderr
    #[arg(short, long)]
    pub log_to_stderr: bool,

    /// Minimum level for graffiti's own logs: trace, debug, info, warn, error, off.
    /// Imported crates stay at warn unless overridden with --log-filter
    #[arg(long, default_value = "debug", value_parser = parse_level_filter)]
    pub log_level: LevelFilter,

    /// Extra log filter directives in tracing's EnvFilter syntax, applied on
    /// top of the defaults. E.g. "russh=info" or "russh=trace,tokio_tungstenite=debug"
    #[arg(long)]
    pub log_filter: Option<String>,

    #[arg(long)]
    pub graffitiignore: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Commands,
}

fn parse_level_filter(value: &str) -> Result<LevelFilter, String> {
    LevelFilter::from_str(value)
        .map_err(|_| format!("unknown log level '{value}', expected one of: trace, debug, info, warn, error, off"))
}

#[derive(Debug, Clone, Subcommand)]
pub enum Commands {
    /// Start as a host
    Host {
        /// Path to authorized_keys file for public key authentication
        #[arg(long, value_parser = get_path)]
        authorized_keys: PathBuf,
    },
    /// Connect to a host
    Connect {
        sha: String,
        /// Path to client's private key for public key authentication
        #[arg(long, value_parser = get_path)]
        client_key: PathBuf,
    },
}
