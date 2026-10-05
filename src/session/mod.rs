pub mod editor;
pub mod identity;
pub mod peer;

use std::{collections::HashMap, path::PathBuf, sync::Arc};

use ignore::WalkBuilder;
use tokio::{
    io::AsyncWriteExt,
    sync::{mpsc, Mutex},
};

use tracing::{debug, info};

use crate::{
    csp::{self, MoveCursorNotification},
    id::{next_client_id, next_request_id},
    net::{self, bootstrap::Protocol},
    ppp,
    session::{
        editor::{CspResponse, EditorInbound, EditorOutbound},
        peer::{Peer, PeerId, PeerMessage, PppNotification, PppRequest, PppResponse},
    },
    state::{self, State},
    DynResult,
};

#[derive(Debug)]
pub enum Role {
    Host,   // The peer which is hosting the session and "owns" the repo
    Client, // The peer which is connecting and downloading the repo from the host
}

/// The hub of the server: a single loop over one inbox, fed by the endpoint
/// tasks (the editor over stdio, one task per network link). Owns the peer
/// map and all protocol logic; knows nothing about transports or wire
/// formats — only typed messages cross its boundary, in either direction.
pub struct Session {
    /// Who this session is on the wire. The host knows from the start; a
    /// client only learns its id from the host's initialize response, so
    /// until then this holds a provisional value.
    me: PeerId,
    state: Arc<Mutex<State>>,
    peers: HashMap<PeerId, Peer>,
    open_links: usize,
    editor_sender: mpsc::Sender<EditorOutbound>,
    inbox: mpsc::Receiver<SessionEvent>,
    pending_shutdown: Option<String>,
    shutting_down: bool,
    token: String,
    configuration: Option<Configuration>,
    handle: SessionHandle,
    network_task: Option<tokio::task::JoinHandle<DynResult<()>>>,
}

#[derive(Clone)]
pub struct Configuration {
    pub authorized_keys: PathBuf,
    pub client_key: PathBuf,
    pub protocol_preference: Vec<Protocol>,
}

impl From<csp::ConfigurationResponse> for Configuration {
    fn from(value: csp::ConfigurationResponse) -> Self {
        Configuration {
            authorized_keys: value.authorized_keys,
            client_key: value.client_key,
            protocol_preference: value.protocol_preference,
        }
    }
}

#[derive(Clone)]
pub struct SessionHandle {
    /// sends events into the session's inbox
    inbox_sender: mpsc::Sender<SessionEvent>,

    /// the host's identity, when this is a host session
    identity: Option<identity::Identity>,
}

impl SessionHandle {
    pub async fn send(&self, event: SessionEvent) -> DynResult<()> {
        self.inbox_sender
            .send(event)
            .await
            .map_err(|_| "session inbox closed".into())
    }

    /// The host's identity key, if this is a host session. Transports pull it
    /// from here rather than receiving one as a parameter: the session owns it.
    pub fn identity(&self) -> Option<&identity::Identity> {
        self.identity.as_ref()
    }
}

pub enum SessionEvent {
    FromEditor(EditorInbound),
    FromPeer(PeerId, PeerMessage),
    PeerConnected(PeerId, mpsc::Sender<PeerMessage>),
    PeerDisconnected(PeerId),
    EditorClosed,
}

impl Session {
    // all peers
    pub async fn new(
        role: Role,
        state: Arc<Mutex<State>>,
        editor_sender: mpsc::Sender<EditorOutbound>,
        known_token: Option<String>,
    ) -> DynResult<(Self, SessionHandle)> {
        let (inbox_sender, inbox) = mpsc::channel(32);

        // A session exists only with a token in hand: the host generates one
        // from its fresh identity before anything listens, the client brought
        // one out of band. From here on state.token always holds it.
        let host_identity = match &role {
            Role::Host => Some(identity::Identity::generate()?),
            Role::Client => None,
        };

        let session_token = match &host_identity {
            Some(host_identity) => {
                let token = host_identity.token(&identity::bootstrap_addr().await)?;
                info!("Token: {}", token);
                Some(token)
            }
            None => known_token,
        };

        let Some(session_token) = session_token else {
            panic!("failed to generate session token");
        };

        let my_peer_id = match role {
            Role::Host => PeerId::Host,
            Role::Client => PeerId::Client(1),
        };

        let handle = SessionHandle {
            inbox_sender,
            identity: host_identity,
        };

        Ok((
            Session {
                me: my_peer_id,
                state,
                peers: HashMap::new(),
                open_links: 0,
                editor_sender,
                inbox,
                pending_shutdown: None,
                shutting_down: false,
                token: session_token,
                configuration: None,
                handle: handle.clone(),
                network_task: None,
            },
            handle,
        ))
    }

    pub fn set_configuration(&mut self, configuration: Configuration) {
        self.configuration = Some(configuration);
    }

    // all peers
    fn is_host(&self) -> bool {
        matches!(self.me, PeerId::Host)
    }

    async fn start_net(&mut self) -> DynResult<()> {
        if self.network_task.is_some() {
            return Err("network task already started".into());
        }

        let network_task = match self.me {
            PeerId::Host => {
                let Some(configuration) = &self.configuration else {
                    return Err("started network without a configuration".into());
                };

                info!("Starting host mode");

                let my_client_id = next_client_id();
                info!("my client id is {}", my_client_id);
                self.state.lock().await.set_client_id(my_client_id);

                tokio::spawn(net::run_host(self.handle.clone(), configuration.clone()))
            }
            PeerId::Client(_) => {
                let Some(configuration) = &self.configuration else {
                    return Err("started network without a configuration".into());
                };

                tokio::spawn(net::run_client(
                    self.token.clone(),
                    self.handle.clone(),
                    configuration.clone(),
                ))
            }
        };

        self.network_task = Some(network_task);

        Ok(())
    }

    // all peers
    /// Runs the session to completion. Returns true when it ended through the
    /// shutdown flow rather than by surprise.
    pub async fn run(mut self) -> bool {
        info!("Entering session loop");

        while let Some(event) = self.inbox.recv().await {
            match self.handle_event(event).await {
                Ok(true) => break,
                Ok(false) => {}
                Err(e) => info!("Error handling session event: {}", e),
            }
        }

        info!("Session loop exited");
        self.shutting_down
    }

    // all peers
    async fn handle_event(&mut self, event: SessionEvent) -> DynResult<bool> {
        match event {
            SessionEvent::FromEditor(message) => self.handle_editor_message(message).await,
            SessionEvent::FromPeer(from, message) => {
                info!(
                    "{} received from peer {:?}: {}",
                    self.me,
                    from,
                    message.method()
                );
                self.handle_peer_message(from, message).await?;
                Ok(false)
            }
            SessionEvent::PeerConnected(id, link_sender) => {
                self.handle_peer_connected(id, link_sender).await?;
                Ok(false)
            }
            SessionEvent::PeerDisconnected(id) => self.handle_peer_disconnected(id).await,
            SessionEvent::EditorClosed => Ok(true),
        }
    }

    // ─── lifecycle ───────────────────────────────────────────────────────

    // all peers
    async fn handle_peer_connected(
        &mut self,
        id: PeerId,
        link_sender: mpsc::Sender<PeerMessage>,
    ) -> DynResult<()> {
        info!("Peer connected: {:?}", id);

        self.peers.insert(
            id,
            Peer {
                link_sender,
                initialized: false,
            },
        );
        self.open_links += 1;

        // the client starts the handshake as soon as its link to the host is up
        if !self.is_host() {
            let request = PeerMessage::Request {
                req_id: next_request_id(),
                request: PppRequest::Initialize(ppp::InitializeRequest {
                    process_id: None,
                    client_info: Some(ppp::ClientInfo {
                        name: "ppp".to_string(),
                        version: Some("0.1.0".to_string()),
                    }),
                    root_path: None,
                }),
            };

            self.send_to(&id, request).await?;
        }

        Ok(())
    }

    async fn handle_peer_disconnected(&mut self, id: PeerId) -> DynResult<bool> {
        info!("Peer disconnected: {:?}", id);

        self.peers.remove(&id);
        self.open_links = self.open_links.saturating_sub(1);

        if let PeerId::Client(client_id) = &id {
            self.broadcast(
                PppNotification::PeerDisconnected(ppp::PeerDisconnectedNotification {
                    client_id: *client_id,
                }),
                Some(&id),
            )
            .await?;
        };

        if self.open_links > 0 {
            let PeerId::Client(client_id) = id else {
                unreachable!("received client notification from non-client peer");
            };

            self.to_editor(EditorOutbound::PeerDisconnected(
                csp::PeerDisconnectedNotification { client_id },
            ))
            .await?;

            return Ok(false);
        }

        if self.pending_shutdown.is_some() {
            self.finish_shutdown().await?;
        } else {
            // the other side went away on its own: ask the editor to shut us down
            self.to_editor(EditorOutbound::ShutdownRequest).await?;
            self.shutting_down = true;
        }

        Ok(true)
    }

    async fn finish_shutdown(&mut self) -> DynResult<()> {
        let req_id = self
            .pending_shutdown
            .take()
            .ok_or("no pending shutdown to finish")?;

        info!("Sending shutdown response to editor");
        self.to_editor(EditorOutbound::Response {
            req_id,
            response: CspResponse::Shutdown,
        })
        .await?;

        self.shutting_down = true;
        Ok(())
    }

    // ─── editor messages ─────────────────────────────────────────────────

    async fn handle_editor_message(&mut self, message: EditorInbound) -> DynResult<bool> {
        match message {
            EditorInbound::Initialize { req_id, params } => {
                info!("Received initialize message from editor");

                let (client_id, token) = {
                    let mut state = self.state.lock().await;

                    if let Some(csp::InitializeOptions {
                        client_projects_root: Some(client_projects_root),
                    }) = params.initialize_options
                    {
                        if !self.is_host() {
                            state.set_cwd(client_projects_root);
                        }
                    }

                    (state.client_id, self.token.clone())
                };

                self.to_editor(EditorOutbound::Response {
                    req_id,
                    response: CspResponse::Initialize {
                        client_id,
                        token: if self.is_host() { Some(token) } else { None },
                    },
                })
                .await?;
            }
            EditorInbound::Initialized => {
                info!("Received initialized message from editor");

                self.to_editor(EditorOutbound::LocationRequest).await?;
                self.to_editor(EditorOutbound::Configuration).await?;
            }
            EditorInbound::MoveCursor(MoveCursorNotification { location }) => {
                info!("Received move_cursor message from editor");

                if !location.exists() {
                    return Ok(false);
                }

                let client_id = {
                    let mut state = self.state.lock().await;
                    state.set_my_location(location.clone());
                    state.client_id
                };

                self.broadcast(
                    PppNotification::CursorMoved(ppp::CursorMovedNotification {
                        client_id,
                        location: location.into(),
                    }),
                    None,
                )
                .await?;
            }
            EditorInbound::Configuration(configuration) => {
                info!("Received configuration message from editor");
                self.set_configuration(configuration);
                self.start_net().await?;
            }
            EditorInbound::DocumentEditFull { uri, content } => {
                info!("Received document/edit message from editor");

                let mut state = self.state.lock().await;

                if let Ok(true) = tokio::fs::try_exists(state.get_cwd().join(&uri)).await {
                    if let Some(true) = state.file_equals(&uri, &content) {
                        return Ok(false);
                    }

                    state.set_file(uri.clone(), &content);
                    let client_id = state.client_id;
                    drop(state);

                    self.broadcast(
                        PppNotification::DocumentEditFull(ppp::DocumentEditFullNotification {
                            client_id,
                            mode: ppp::DocumentEditMode::Full,
                            uri,
                            content,
                        }),
                        None,
                    )
                    .await?;
                } else {
                    info!("File doesn't exist: {:?}", uri);
                }
            }
            EditorInbound::DocumentLocation(location) => {
                info!("Received document/location message from editor");
                self.state.lock().await.set_my_location(location);
            }
            EditorInbound::CwdChanged => {
                info!("Received cwd_changed message from editor");
            }
            EditorInbound::RequestSessionToken { req_id } => {
                info!("Received session token request from editor");

                let token = self.token.clone();

                self.to_editor(EditorOutbound::Response {
                    req_id,
                    response: CspResponse::SessionToken { token },
                })
                .await?;
            }
            EditorInbound::Shutdown { req_id } => {
                info!("Received shutdown message from editor");

                self.pending_shutdown = Some(req_id);

                // dropping the senders tells every link task to close gracefully;
                // their PeerDisconnected events complete the shutdown
                self.peers.clear();

                if self.open_links == 0 {
                    self.finish_shutdown().await?;
                    return Ok(true);
                }
            }
            EditorInbound::Exit => {
                info!("Received exit message from editor");
                return Ok(true);
            }
            EditorInbound::Unknown { method } => {
                info!("Received unknown message from editor: {}", method);
                self.to_editor(EditorOutbound::UnknownMethod).await?;
            }
        }

        Ok(false)
    }

    // ─── peer messages ───────────────────────────────────────────────────

    async fn handle_peer_message(&mut self, from: PeerId, message: PeerMessage) -> DynResult<()> {
        match message {
            PeerMessage::Request {
                req_id,
                request: PppRequest::Initialize(_params),
            } => {
                info!("Received initialize request from client");

                let client_id = match &from {
                    PeerId::Client(id) => *id,
                    PeerId::Host => return Err("initialize request from the host".into()),
                };

                let project_dir_name = PathBuf::from(
                    self.state
                        .lock()
                        .await
                        .get_cwd()
                        .file_name()
                        .ok_or("unable to get project directory name")?,
                );

                let response = PeerMessage::Response {
                    req_id,
                    response: PppResponse::Initialize(ppp::InitializeResponse {
                        host_info: Some(ppp::HostInfo {
                            name: "graffiti-rs".to_string(),
                            version: Some("0.1.0".to_string()),
                        }),
                        client_id,
                        project_dir_name,
                    }),
                };

                self.send_to(&from, response).await?;
            }
            PeerMessage::Response {
                req_id: _,
                response: PppResponse::Initialize(result),
            } => {
                info!("Received initialize response from host");

                let mut state = self.state.lock().await;
                let new_cwd = state.get_cwd_from_remote_projects_path(&result.project_dir_name);

                info!("moving to directory: {}", new_cwd.to_string_lossy());

                tokio::fs::create_dir_all(&new_cwd).await?;
                state.set_cwd(new_cwd.clone());
                state.set_client_id(result.client_id);
                drop(state);

                // the host has now told us who we are
                self.me = PeerId::Client(result.client_id);

                self.to_editor(EditorOutbound::ChangeCwd(csp::ChangeCwdRequest {
                    cwd: new_cwd,
                }))
                .await?;

                info!("my client id is {}", result.client_id);

                if let Some(peer) = self.peers.get_mut(&from) {
                    peer.initialized = true;
                }

                self.to_editor(EditorOutbound::PeerConnected(
                    csp::PeerConnectedNotification { client_id: 1 },
                ))
                .await?;

                self.to_editor(EditorOutbound::ClientIdChanged(
                    csp::ClientIdChangedNotification {
                        client_id: result.client_id,
                    },
                ))
                .await?;

                self.send_to(
                    &from,
                    PeerMessage::Notification(PppNotification::Initialized(
                        ppp::InitializedNotification {
                            client_id: result.client_id,
                        },
                    )),
                )
                .await?;
            }
            PeerMessage::Notification(notification) => {
                self.handle_peer_notification(from, notification).await?;
            }
        }

        Ok(())
    }

    async fn handle_peer_notification(
        &mut self,
        from: PeerId,
        notification: PppNotification,
    ) -> DynResult<()> {
        match notification {
            PppNotification::Initialized(params) => {
                info!(
                    "{} received initialized notification from {}",
                    self.me, from
                );

                if let Some(peer) = self.peers.get_mut(&from) {
                    peer.initialized = true;
                }

                let PeerId::Client(client_id) = from else {
                    unreachable!("received client notification from non-client peer");
                };

                self.to_editor(EditorOutbound::PeerConnected(
                    csp::PeerConnectedNotification { client_id },
                ))
                .await?;

                self.broadcast(
                    PppNotification::PeerConnected(ppp::PeerConnectedNotification { client_id }),
                    Some(&from),
                )
                .await?;

                for id in self.peers.keys() {
                    if id == &from {
                        continue;
                    }

                    let PeerId::Client(peer_client_id) = *id else {
                        continue;
                    };

                    debug!("notifying {} that {} exists", from, id);

                    self.send_to(
                        &from,
                        PeerMessage::Notification(PppNotification::PeerExists(
                            ppp::PeerExistsNotification {
                                client_id: peer_client_id,
                                location: self
                                    .state
                                    .lock()
                                    .await
                                    .get_client_location(&peer_client_id)
                                    .cloned()
                                    .map(|l| l.into()),
                            },
                        )),
                    )
                    .await?;
                }

                self.upload_project(&from, params.client_id).await?;

                let location = self.state.lock().await.get_my_location().cloned();

                if let Some(state::DocumentLocation { uri, pos }) = location {
                    info!("Sending initial file URI: {:?}", uri);

                    self.send_to(
                        &from,
                        PeerMessage::Notification(PppNotification::InitialFileUri(
                            ppp::InitialFileNotification { uri: uri.clone() },
                        )),
                    )
                    .await?;

                    self.send_to(
                        &from,
                        PeerMessage::Notification(PppNotification::CursorMoved(
                            ppp::CursorMovedNotification {
                                client_id: self.state.lock().await.client_id,
                                location: ppp::DocumentLocation {
                                    uri,
                                    pos: pos.into(),
                                },
                            },
                        )),
                    )
                    .await?;
                } else {
                    info!("No initial file URI found");
                }
            }
            PppNotification::PeerConnected(params) => {
                info!("Received peer_connected notification");

                self.to_editor(EditorOutbound::PeerConnected(
                    csp::PeerConnectedNotification {
                        client_id: params.client_id,
                    },
                ))
                .await?;
            }
            PppNotification::PeerExists(params) => {
                info!("Received peer_exists notification");

                self.to_editor(EditorOutbound::PeerExists(ppp::PeerExistsNotification {
                    client_id: params.client_id,
                    location: params.location,
                }))
                .await?;
            }
            PppNotification::PeerDisconnected(params) => {
                info!("Received peer_disconnected notification");

                self.to_editor(EditorOutbound::PeerDisconnected(
                    csp::PeerDisconnectedNotification {
                        client_id: params.client_id,
                    },
                ))
                .await?;
            }
            PppNotification::DirectoriesUpload(params) => {
                info!("Received directories/upload notification");

                let cwd = self.state.lock().await.get_cwd();

                for dir in params.directories {
                    let full_uri = cwd.join(&dir.uri);

                    match dir.type_ {
                        ppp::DirectoryType::Directory => {
                            if !full_uri.exists() {
                                tokio::fs::create_dir_all(&full_uri).await?;
                            }
                        }
                        ppp::DirectoryType::File => {
                            if !full_uri.exists() {
                                tokio::fs::create_dir_all(
                                    full_uri.parent().ok_or("file has no parent directory")?,
                                )
                                .await?;
                            }

                            let mut file = tokio::fs::File::create(&full_uri).await?;
                            file.write_all(&dir.content).await?;
                        }
                    }
                }
            }
            PppNotification::InitialFileUri(params) => {
                info!("Received initial_file_uri notification");

                self.to_editor(EditorOutbound::InitialFileUri(csp::InitialFileUriRequest {
                    initial_file_uri: params.uri,
                }))
                .await?;
            }
            PppNotification::CursorMoved(params) => {
                info!("Received cursor_moved notification");

                self.state
                    .lock()
                    .await
                    .set_client_location(params.client_id, params.location.clone().into());

                self.to_editor(EditorOutbound::CursorMoved(csp::CursorMovedNotification {
                    client_id: params.client_id,
                    location: params.location.clone().into(),
                }))
                .await?;

                self.broadcast(PppNotification::CursorMoved(params), Some(&from))
                    .await?;
            }
            PppNotification::DocumentEditFull(params) => {
                info!("Received document/edit notification");

                let mut state = self.state.lock().await;

                if let Some(true) = state.file_equals(&params.uri, &params.content) {
                    return Ok(());
                }

                state.set_file(params.uri.clone(), &params.content);
                let full_uri = state.get_cwd().join(&params.uri);
                drop(state);

                self.to_editor(EditorOutbound::DocumentEditedFull(
                    csp::DocumentEditedFull {
                        client_id: params.client_id,
                        mode: csp::DocumentEditMode::Full,
                        uri: full_uri,
                        content: params.content.clone(),
                    },
                ))
                .await?;

                self.broadcast(PppNotification::DocumentEditFull(params), Some(&from))
                    .await?;
            }
        }

        Ok(())
    }

    // ─── outbound helpers ────────────────────────────────────────────────

    async fn to_editor(&self, message: EditorOutbound) -> DynResult<()> {
        self.editor_sender
            .send(message)
            .await
            .map_err(|_| "editor writer closed".into())
    }

    async fn send_to(&self, id: &PeerId, message: PeerMessage) -> DynResult<()> {
        let peer = self.peers.get(id).ok_or("unknown peer")?;
        peer.link_sender
            .send(message)
            .await
            .map_err(|_| "peer link closed".into())
    }

    /// Sends a notification to every initialized peer except `exclude`. This
    /// is both "tell everyone what my editor did" (no exclusion) and the
    /// host's relay (excluding the originating link, so a message never
    /// returns to where it came from).
    /// On the client, this only sends to the host.
    async fn broadcast(
        &self,
        notification: PppNotification,
        exclude: Option<&PeerId>,
    ) -> DynResult<()> {
        for (id, peer) in &self.peers {
            debug!(
                "{} is broadcasting {} to {:?}",
                self.me,
                notification.method(),
                id
            );

            if Some(id) == exclude || !peer.initialized {
                continue;
            }

            if !self.is_host() && id != &PeerId::Host {
                continue;
            }

            peer.link_sender
                .send(PeerMessage::Notification(notification.clone()))
                .await
                .map_err(|_| "peer link closed")?;
        }

        Ok(())
    }

    /// Walks the project directory and uploads it to one peer in pages.
    async fn upload_project(&self, to: &PeerId, client_id: usize) -> DynResult<()> {
        let (cwd, custom_ignore) = {
            let state = self.state.lock().await;
            (state.get_cwd(), state.get_ignore_file())
        };

        let home = dirs::home_dir().ok_or("home dir not found")?;

        let path_to_option = |path: PathBuf| -> Option<PathBuf> { path.exists().then_some(path) };

        let cwd_ignore = path_to_option(cwd.join(".graffitiignore"));
        let home_ignore = path_to_option(home.join(".graffitiignore"));
        let first_ignore = custom_ignore.or(cwd_ignore).or(home_ignore);

        let mut walker = &mut WalkBuilder::new(&cwd);

        if let Some(ignore) = first_ignore {
            walker = walker.add_custom_ignore_filename(ignore);
        }

        let dirs = walker
            .standard_filters(false)
            .skip_stdout(true)
            .build()
            .filter_map(Result::ok)
            .filter(|entry| entry.path() != cwd)
            .filter_map(|entry| {
                entry
                    .into_path()
                    .strip_prefix(&cwd)
                    .ok()
                    .map(|p| p.to_path_buf())
            })
            .collect::<Vec<_>>();

        const PAGE_SIZE: usize = 16;

        for (page, batch) in dirs.chunks(PAGE_SIZE).enumerate() {
            info!("sending batch: {}", page);

            let mut directories = Vec::new();

            for path in batch {
                let (type_, content) = match tokio::fs::canonicalize(path).await {
                    Ok(p) if p.is_dir() => (ppp::DirectoryType::Directory, vec![]),
                    Ok(p) if p.is_file() => {
                        (ppp::DirectoryType::File, tokio::fs::read(path).await?)
                    }
                    Ok(p) if p.is_symlink() => {
                        unreachable!("path is canonicalized so the path should never be a symlink at this stage")
                    }
                    Err(_) => continue,
                    Ok(p) => panic!("unexpected path value {:?}", p),
                };

                directories.push(ppp::Directory {
                    uri: path.to_path_buf(),
                    type_,
                    content,
                });
            }

            self.send_to(
                to,
                PeerMessage::Notification(PppNotification::DirectoriesUpload(
                    ppp::DirectoriesUploadNotification {
                        client_id,
                        directories,
                    },
                )),
            )
            .await?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[tokio::test]
    async fn editor_initialize_gets_a_response() {
        // arrange
        let (editor_sender, mut editor_receiver) = mpsc::channel(8);
        let state = State::new(PathBuf::new(), None);
        let (session, handle) = Session::new(Role::Host, state, editor_sender, None)
            .await
            .unwrap();
        tokio::spawn(session.run());

        // act
        handle
            .send(SessionEvent::FromEditor(EditorInbound::Initialize {
                req_id: "1".into(),
                params: csp::InitializeRequest {
                    process_id: Some(123),
                    editor_info: Some(csp::EditorInfo {
                        name: "test-client".to_string(),
                        version: Some("0.1.0".to_string()),
                    }),
                    root_path: Some(".".to_string()),
                    initialize_options: None,
                },
            }))
            .await
            .unwrap();

        // assert
        let response = editor_receiver.recv().await.unwrap();
        match response {
            EditorOutbound::Response {
                req_id,
                response: CspResponse::Initialize { client_id, token },
            } => {
                assert_eq!(req_id, "1");
                assert_eq!(client_id, 1);

                // the initialize response is where the editor learns the token:
                // it must round-trip back into a token and an address
                let (_, addr) = identity::parse_token(&token.unwrap())
                    .expect("initialize response carried a malformed token");
                assert!(addr.ends_with(":32700"));
            }
            other => panic!("expected an initialize response, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn host_relays_to_other_peers_but_not_the_origin() {
        // arrange
        let (editor_sender, _editor_receiver) = mpsc::channel(8);
        let state = State::new(PathBuf::new(), None);
        let (session, handle) = Session::new(Role::Host, state, editor_sender, None)
            .await
            .unwrap();
        tokio::spawn(session.run());

        let (a_link_sender, mut a_link_receiver) = mpsc::channel(8);
        let (b_link_sender, mut b_link_receiver) = mpsc::channel(8);
        let a = PeerId::Client(2);
        let b = PeerId::Client(3);

        handle
            .send(SessionEvent::PeerConnected(a, a_link_sender))
            .await
            .unwrap();

        handle
            .send(SessionEvent::PeerConnected(b, b_link_sender))
            .await
            .unwrap();

        // both peers finish their handshake
        for id in [2, 3] {
            handle
                .send(SessionEvent::FromPeer(
                    PeerId::Client(id),
                    PeerMessage::Notification(PppNotification::Initialized(
                        ppp::InitializedNotification { client_id: id },
                    )),
                ))
                .await
                .unwrap();
        }

        // act: a cursor move arrives from peer A
        handle
            .send(SessionEvent::FromPeer(
                a,
                PeerMessage::Notification(PppNotification::CursorMoved(
                    ppp::CursorMovedNotification {
                        client_id: 2,
                        location: ppp::DocumentLocation {
                            uri: PathBuf::from("file.txt"),
                            pos: ppp::DocumentPosition { line: 1, column: 2 },
                        },
                    },
                )),
            ))
            .await
            .unwrap();

        // assert: B receives the relayed move, attributed to A. The handshake
        // also queued some peer-discovery notifications on B's link, so skip
        // past those instead of assuming the move arrives first.
        let relayed = loop {
            match b_link_receiver.recv().await.expect("B's link closed") {
                PeerMessage::Notification(PppNotification::CursorMoved(params)) => break params,
                PeerMessage::Notification(
                    PppNotification::PeerConnected(_) | PppNotification::PeerExists(_),
                ) => continue,
                other => panic!("expected a relayed cursor move, got {:?}", other),
            }
        };
        assert_eq!(relayed.client_id, 2);

        // and the move never came back to A. The session handles events in
        // order, so everything A is ever going to get is queued by now.
        while let Ok(msg) = a_link_receiver.try_recv() {
            assert!(
                !matches!(
                    msg,
                    PeerMessage::Notification(PppNotification::CursorMoved(_))
                ),
                "the origin was sent its own cursor move back"
            );
        }
    }
}
