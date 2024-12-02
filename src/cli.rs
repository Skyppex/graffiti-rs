use clap::Parser;

#[derive(Debug, Clone, Parser)]
pub struct Cli {
    pub log_file: Option<String>,
}
