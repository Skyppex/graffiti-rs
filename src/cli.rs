use clap::{ArgGroup, Parser, Subcommand};

#[derive(Debug, Clone, Parser)]
#[command(group = ArgGroup::new("log").args(["log_file", "log_to_stderr"]).required(false).multiple(false))]
pub struct Cli {
    /// The path to the log file
    #[arg(long)]
    pub log_file: Option<String>,

    /// Log to stderr
    #[arg(short, long)]
    pub log_to_stderr: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Clone, Subcommand)]
pub enum Commands {
    /// Start as a host
    Host,
    /// Connect to a host
    Connect,
}
