use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
};

use tokio::sync::Mutex;

use crate::utility_types::{ClientId, RequestId};

pub type Request = dyn crate::ppp::Req + Send;

pub struct State {
    cwd: PathBuf,
    is_host: bool,
    pub client_id: ClientId,
    pub fingerprint: Option<String>,
    network_requests: HashMap<RequestId, Box<Request>>,
}

impl State {
    pub fn new(cwd: PathBuf, is_host: bool, client_id: ClientId) -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(State {
            cwd,
            is_host,
            client_id,
            fingerprint: None,
            network_requests: HashMap::new(),
        }))
    }

    pub fn is_host(&self) -> bool {
        self.is_host
    }

    pub fn is_client(&self) -> bool {
        !self.is_host
    }

    pub fn get_cwd(&self) -> &Path {
        &self.cwd
    }

    pub fn set_cwd(&mut self, cwd: &Path) {
        self.cwd = cwd.to_path_buf();
    }

    pub fn set_fingerprint(&mut self, fingerprint: String) {
        self.fingerprint = Some(fingerprint);
    }

    pub fn get_net_req(&mut self, req_id: &RequestId) -> Option<&Request> {
        self.network_requests.get(req_id).map(|r| r.as_ref())
    }

    pub fn add_net_req(&mut self, req: Box<Request>) -> Option<Box<Request>> {
        self.network_requests.insert(req.id(), req)
    }

    pub fn remove_net_req(&mut self, req_id: &RequestId) -> Option<Box<Request>> {
        self.network_requests.remove(req_id)
    }
}
