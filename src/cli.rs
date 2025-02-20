use clap::{ArgGroup, Parser};

#[derive(Debug, Clone, Parser)]
#[command(group = ArgGroup::new("log").args(["log_file", "log_to_stderr"]).required(false).multiple(false))]
pub struct Cli {
    #[arg(long)]
    pub log_file: Option<String>,
    #[arg(short, long)]
    pub log_to_stderr: bool,
}
