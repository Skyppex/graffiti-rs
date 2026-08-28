pub mod editor;
pub mod identity;
pub mod peer;

use std::{collections::HashMap, path::PathBuf, sync::Arc};

use ignore::WalkBuilder;
use tokio::{
    io::AsyncWriteExt,
    sync::{mpsc, Mutex},
};

use tracing::info;

use crate::{
    csp,
    id::next_request_id,
    ppp,
    session::{
        editor::{CspNotification, CspRequest, CspResponse, EditorInbound, EditorOutbound},
        peer::{Peer, PeerId, PeerMessage, PppNotification, PppRequest, PppResponse},
    },
    state::{self, State},
    DynResult,
};

pub enum Role {
    Host,   // The peer which is hosting the session and "owns" the repo
    Client, // The peer which is connecting and downloading the repo from the host
}

/// The hub of the server: a single loop over one inbox, fed by the endpoint
/// tasks (the editor over stdio, one task per network link). Owns the peer
/// map and all protocol logic; knows nothing about transports or wire
/// formats — only typed messages cross its boundary, in either direction.
pub struct Session {
    role: Role,
    state: Arc<Mutex<State>>,
    peers: HashMap<PeerId, Peer>,
    open_links: usize,
    editor_sender: mpsc::Sender<EditorOutbound>,
    inbox: mpsc::Receiver<SessionEvent>,
    pending_shutdown: Option<String>,
    shutting_down: bool,
    token: String,
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

        Ok((
            Session {
                role,
                state,
                peers: HashMap::new(),
                open_links: 0,
                editor_sender,
                inbox,
                pending_shutdown: None,
                shutting_down: false,
                token: session_token,
            },
            SessionHandle {
                inbox_sender,
                identity: host_identity,
            },
        ))
    }

    fn is_host(&self) -> bool {
        matches!(self.role, Role::Host)
    }

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

    async fn handle_event(&mut self, event: SessionEvent) -> DynResult<bool> {
        match event {
            SessionEvent::FromEditor(message) => self.handle_editor_message(message).await,
            SessionEvent::FromPeer(from, message) => {
                info!("Received from peer {:?}: {}", from, message.method());
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

    async fn handle_peer_connected(
        &mut self,
        id: PeerId,
        link_sender: mpsc::Sender<PeerMessage>,
    ) -> DynResult<()> {
        info!("Peer connected: {:?}", id);

        self.peers.insert(
            id.clone(),
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

        if self.open_links > 0 {
            return Ok(false);
        }

        if self.pending_shutdown.is_some() {
            self.finish_shutdown().await?;
        } else {
            // the other side went away on its own: ask the editor to shut us down
            self.to_editor(EditorOutbound::Request(CspRequest::Shutdown))
                .await?;
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

                    (state.client_id.clone(), self.token.clone())
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

                self.to_editor(EditorOutbound::Request(CspRequest::Location))
                    .await?;
            }
            EditorInbound::MoveCursor { location } => {
                info!("Received move_cursor message from editor");

                if !location.exists() {
                    return Ok(false);
                }

                let client_id = {
                    let mut state = self.state.lock().await;
                    state.set_my_location(location.clone());
                    state.client_id.clone()
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
            EditorInbound::DocumentEditFull { uri, content } => {
                info!("Received document/edit message from editor");

                let mut state = self.state.lock().await;

                if let Ok(true) = tokio::fs::try_exists(state.get_cwd().join(&uri)).await {
                    if let Some(true) = state.file_equals(&uri, &content) {
                        return Ok(false);
                    }

                    state.set_file(uri.clone(), &content);
                    let client_id = state.client_id.clone();
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
                    info!("File doesn't exist");
                }
            }
            EditorInbound::DocumentLocation { location } => {
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
                    PeerId::Client(id) => id.clone(),
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
                state.set_client_id(result.client_id.clone());
                drop(state);

                self.to_editor(EditorOutbound::Request(CspRequest::ChangeCwd {
                    cwd: new_cwd,
                }))
                .await?;

                info!("my client id is {}", result.client_id);

                if let Some(peer) = self.peers.get_mut(&from) {
                    peer.initialized = true;
                }

                self.to_editor(EditorOutbound::Notification(
                    CspNotification::ClientIdChanged {
                        client_id: result.client_id.clone(),
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
                info!("Received initialized notification from client");

                if let Some(peer) = self.peers.get_mut(&from) {
                    peer.initialized = true;
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
                                client_id: self.state.lock().await.client_id.clone(),
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

                self.to_editor(EditorOutbound::Request(CspRequest::InitialFileUri {
                    initial_file_uri: params.uri,
                }))
                .await?;
            }
            PppNotification::CursorMoved(params) => {
                self.state
                    .lock()
                    .await
                    .set_client_location(params.client_id.clone(), params.location.clone().into());

                self.to_editor(EditorOutbound::Notification(CspNotification::CursorMoved {
                    client_id: params.client_id.clone(),
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

                self.to_editor(EditorOutbound::Notification(
                    CspNotification::DocumentEdited {
                        client_id: params.client_id.clone(),
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
    async fn broadcast(
        &self,
        notification: PppNotification,
        exclude: Option<&PeerId>,
    ) -> DynResult<()> {
        for (id, peer) in &self.peers {
            if Some(id) == exclude || !peer.initialized {
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
    async fn upload_project(&self, to: &PeerId, client_id: String) -> DynResult<()> {
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
                        client_id: client_id.clone(),
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
                assert_eq!(client_id, "0");

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
        let a = PeerId::Client("1".into());
        let b = PeerId::Client("2".into());

        handle
            .send(SessionEvent::PeerConnected(a.clone(), a_link_sender))
            .await
            .unwrap();
        handle
            .send(SessionEvent::PeerConnected(b.clone(), b_link_sender))
            .await
            .unwrap();

        // both peers finish their handshake
        for id in ["1", "2"] {
            handle
                .send(SessionEvent::FromPeer(
                    PeerId::Client(id.into()),
                    PeerMessage::Notification(PppNotification::Initialized(
                        ppp::InitializedNotification {
                            client_id: id.into(),
                        },
                    )),
                ))
                .await
                .unwrap();
        }

        // act: a cursor move arrives from peer A
        handle
            .send(SessionEvent::FromPeer(
                a.clone(),
                PeerMessage::Notification(PppNotification::CursorMoved(
                    ppp::CursorMovedNotification {
                        client_id: "1".into(),
                        location: ppp::DocumentLocation {
                            uri: PathBuf::from("file.txt"),
                            pos: ppp::DocumentPosition { line: 1, column: 2 },
                        },
                    },
                )),
            ))
            .await
            .unwrap();

        // assert: B receives the relayed move, attributed to A
        let relayed = b_link_receiver.recv().await.unwrap();
        match relayed {
            PeerMessage::Notification(PppNotification::CursorMoved(params)) => {
                assert_eq!(params.client_id, "1");
            }
            other => panic!("expected a relayed cursor move, got {:?}", other),
        }

        // and A got nothing back
        assert!(a_link_receiver.try_recv().is_err());
    }
}
