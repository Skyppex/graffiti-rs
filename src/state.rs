use std::sync::Arc;

use tokio::sync::Mutex;

pub struct State {
    pub fingerprint: Option<String>,
}

impl State {
    pub fn new() -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(State { fingerprint: None }))
    }

    pub fn set_fingerprint(&mut self, fingerprint: String) {
        self.fingerprint = Some(fingerprint);
    }
}
