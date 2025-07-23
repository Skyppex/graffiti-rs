use std::{
    collections::HashMap,
    hash::{Hash, Hasher},
    path::{Path, PathBuf},
    sync::Arc,
};

use tokio::sync::Mutex;
use twox_hash::XxHash64;

use crate::{csp, ppp};

pub type Request = dyn crate::ppp::Req + Send;

pub struct State {
    cwd: PathBuf,
    custom_ignore_file: Option<PathBuf>,
    remote_projects_path: Option<PathBuf>,
    is_host: bool,
    pub client_id: String,
    pub fingerprint: Option<String>,
    network_requests: HashMap<String, Box<Request>>,
    client_locations: HashMap<String, DocumentLocation>,
    file_hashes: HashMap<PathBuf, u64>,
}

impl State {
    pub fn new(
        cwd: PathBuf,
        custom_ignore_file: Option<PathBuf>,
        is_host: bool,
        client_id: String,
    ) -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(State {
            cwd,
            custom_ignore_file,
            remote_projects_path: None,
            is_host,
            client_id,
            fingerprint: None,
            network_requests: HashMap::new(),
            client_locations: HashMap::new(),
            file_hashes: HashMap::new(),
        }))
    }

    pub fn _is_host(&self) -> bool {
        self.is_host
    }

    pub fn is_client(&self) -> bool {
        !self.is_host
    }

    pub fn get_cwd(&self) -> PathBuf {
        self.cwd.clone()
    }

    pub fn set_cwd(&mut self, cwd: &Path) {
        self.cwd = cwd.to_path_buf();
    }

    pub fn _set_remote_projects_path(&mut self, remote_projects_path: PathBuf) {
        self.remote_projects_path = Some(remote_projects_path);
    }

    pub fn set_cwd_from_remote_projects_path(&mut self, project_dir_name: &Path) {
        self.cwd = self
            .remote_projects_path
            .clone()
            .unwrap_or_else(|| dirs::data_local_dir().expect("failed to get data local dir"))
            .join("graffiti")
            .join(project_dir_name)
    }

    pub fn get_ignore_file(&self) -> Option<PathBuf> {
        self.custom_ignore_file.clone()
    }

    pub fn set_fingerprint(&mut self, fingerprint: String) {
        self.fingerprint = Some(fingerprint);
    }

    pub fn _get_net_req(&mut self, req_id: &str) -> Option<&Request> {
        self.network_requests.get(req_id).map(|r| r.as_ref())
    }

    pub fn add_net_req(&mut self, req: Box<Request>) -> Option<Box<Request>> {
        self.network_requests.insert(req.id(), req)
    }

    pub fn remove_net_req(&mut self, req_id: &str) -> Option<Box<Request>> {
        self.network_requests.remove(req_id)
    }

    pub fn get_client_location(&self, client_id: &str) -> Option<&DocumentLocation> {
        self.client_locations.get(client_id)
    }

    pub fn get_my_location(&self) -> Option<&DocumentLocation> {
        self.client_locations.get(&self.client_id)
    }

    pub fn set_client_location(&mut self, client_id: String, location: DocumentLocation) {
        self.client_locations.insert(client_id, location);
    }

    pub fn set_my_location<T: Into<DocumentLocation>>(&mut self, location: T) {
        self.client_locations
            .insert(self.client_id.clone(), location.into());
    }

    pub fn set_file(&mut self, path: PathBuf, content: &str) {
        let hash = self.hash_file(content);
        self.file_hashes.insert(path, hash);
    }

    pub fn file_equals(&self, path: impl AsRef<Path>, content: &str) -> Option<bool> {
        if let Some(hash) = self.file_hashes.get(path.as_ref()) {
            let new_hash = self.hash_file(content);
            return Some(*hash == new_hash);
        }

        None
    }

    fn hash_file(&self, content: &str) -> u64 {
        let mut hasher = XxHash64::with_seed(0);
        content.hash(&mut hasher);
        hasher.finish()
    }
}

#[derive(Debug, Clone)]
pub struct DocumentLocation {
    pub uri: PathBuf,
    pub pos: DocumentPosition,
}

#[derive(Debug, Clone)]
pub struct DocumentPosition {
    pub line: u32,
    pub column: u32,
}

impl From<csp::DocumentLocation> for DocumentLocation {
    fn from(location: csp::DocumentLocation) -> Self {
        Self {
            uri: location.uri,
            pos: location.pos.into(),
        }
    }
}

impl From<ppp::DocumentLocation> for DocumentLocation {
    fn from(location: ppp::DocumentLocation) -> Self {
        Self {
            uri: location.uri,
            pos: location.pos.into(),
        }
    }
}

impl From<csp::DocumentPosition> for DocumentPosition {
    fn from(location: csp::DocumentPosition) -> Self {
        Self {
            line: location.line,
            column: location.column,
        }
    }
}

impl From<ppp::DocumentPosition> for DocumentPosition {
    fn from(location: ppp::DocumentPosition) -> Self {
        Self {
            line: location.line,
            column: location.column,
        }
    }
}
