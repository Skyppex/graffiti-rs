use std::io;
use std::path::PathBuf;

use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

pub fn init(log_file: Option<PathBuf>, log_to_stderr: bool) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug"));

    let subscriber = tracing_subscriber::registry().with(filter);

    let make_writer: Box<dyn Fn() -> Box<dyn io::Write + Send + Sync> + Send + Sync> =
        Box::new(move || {
            if let Some(ref path) = log_file {
                let file = std::fs::File::create(path).expect("Failed to create log file");
                Box::new(file)
            } else if log_to_stderr {
                Box::new(std::io::stderr())
            } else {
                Box::new(std::io::sink())
            }
        });

    subscriber
        .with(fmt::layer().with_writer(make_writer).boxed())
        .init();
}
