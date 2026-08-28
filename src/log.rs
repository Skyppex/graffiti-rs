use std::io;
use std::path::PathBuf;
use std::sync::Mutex;
use std::{fs::OpenOptions, io::IsTerminal};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

pub fn init(
    log_file: Option<PathBuf>,
    log_to_stderr: bool,
    log_level: LevelFilter,
    log_filter: Option<String>,
) {
    // imported crates stay at warn; our own logs follow --log-level. RUST_LOG,
    // if set, replaces those defaults, and --log-filter directives are applied
    // on top of either — later directives win for the same target.
    let mut directives = std::env::var("RUST_LOG")
        .unwrap_or_else(|_| format!("warn,graffiti_rs={}", log_level));

    if let Some(log_filter) = log_filter {
        directives = format!("{directives},{log_filter}");
    }

    let filter = EnvFilter::try_new(&directives)
        .unwrap_or_else(|e| panic!("invalid log filter '{directives}': {e}"));

    let layer: Box<dyn Layer<_> + Send + Sync> = if let Some(path) = log_file {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .expect("Failed to open log file");
        fmt::layer()
            .with_writer(Mutex::new(file))
            .with_ansi(true)
            .boxed()
    } else if log_to_stderr {
        fmt::layer()
            .with_writer(io::stderr)
            .with_ansi(io::stderr().is_terminal())
            .boxed()
    } else {
        fmt::layer().with_writer(io::sink).boxed()
    };

    tracing_subscriber::registry()
        .with(filter)
        .with(layer)
        .init();
}
