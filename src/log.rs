use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

pub fn init(log_file: Option<PathBuf>, log_to_stderr: bool) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug"));
    let subscriber = tracing_subscriber::registry().with(filter);

    let layer = if let Some(path) = log_file {
        let file = Arc::new(Mutex::new(
            std::fs::File::create(path).expect("Failed to create log file"),
        ));
        let make_writer = move || Box::new(FileGuard(file.clone())) as Box<dyn Write + Send + Sync>;
        fmt::layer().with_writer(make_writer).boxed()
    } else if log_to_stderr {
        fmt::layer().with_writer(std::io::stderr).boxed()
    } else {
        fmt::layer().with_writer(std::io::sink).boxed()
    };

    subscriber.with(layer).init();
}

struct FileGuard(Arc<Mutex<std::fs::File>>);

impl Write for FileGuard {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.lock().unwrap().flush()
    }
}
