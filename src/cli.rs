use std::path::PathBuf;

use clap::{ArgGroup, Parser, Subcommand};

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

    #[arg(long)]
    pub graffitiignore: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Commands,
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
