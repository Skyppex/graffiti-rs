use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use tokio::sync::Mutex;

pub struct State {
    cwd: PathBuf,
    pub client_id: String,
    pub fingerprint: Option<String>,
    // pub file: HashMap<PathBuf, u64>,
}

impl State {
    pub fn new(cwd: PathBuf, client_id: String) -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(State {
            cwd,
            client_id,
            fingerprint: None,
            // file: HashMap::new(),
        }))
    }

    pub fn get_cwd(&self) -> &Path {
        &self.cwd
    }

    pub fn set_fingerprint(&mut self, fingerprint: String) {
        self.fingerprint = Some(fingerprint);
    }
}
