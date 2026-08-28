pub mod bootstrap;
pub mod connection;
pub mod identity;

use tokio::{
    net::{TcpListener, TcpStream},
    sync::mpsc,
};
use tracing::info;

use crate::{
    id::next_client_id,
    net::{
        bootstrap::Protocol,
        connection::{Connection, Message},
        identity::Identity,
    },
    ppp,
    session::{
        peer::{PeerId, PeerMessage},
        SessionEvent, SessionHandle,
    },
    DynResult,
};

/// The one port a host listens on. Every connection starts with the plaintext
/// bootstrap prelude here and upgrades in place to the negotiated protocol.
pub const BOOTSTRAP_PORT: u16 = 32700;

pub async fn run_host(
    session: SessionHandle,
    identity: Identity,
    authorized_keys_path: std::path::PathBuf,
) -> DynResult<()> {
    let authorized_keys = connection::load_authorized_keys(&authorized_keys_path)?;

    // the token exists before anything listens: identity is an input to the
    // transport, and the fingerprint is an ordinary startup event
    let bootstrap_addr = format!("{}:{}", connection::resolve_public_ip().await, BOOTSTRAP_PORT);
    let token = identity.token(&bootstrap_addr)?;

    info!("Fingerprint: {}", token);
    session.send(SessionEvent::Fingerprint(token)).await?;

    let listener = TcpListener::bind(("0.0.0.0", BOOTSTRAP_PORT)).await?;
    info!("Listening on 0.0.0.0:{}", BOOTSTRAP_PORT);

    let (mut socket, peer_addr) = listener.accept().await?;
    info!("bootstrap connection from {}", peer_addr);

    let protocol = bootstrap::negotiate_host(&mut socket).await?;
    info!("negotiated protocol: {:?}", protocol);

    let connection = match protocol {
        Protocol::Ssh => Connection::ssh_host(socket, identity, authorized_keys).await?,
        // negotiate_host refuses unimplemented protocols before picking them
        Protocol::Wss => unreachable!("wss has no upgrade path yet"),
    };

    info!("connection established");

    // the host allocates the client_id at accept time, so the link and the
    // author it carries share one identity from the first frame
    run_link(PeerId::Client(next_client_id()), connection, &session).await
}

pub async fn run_client(
    token: String,
    session: SessionHandle,
    client_key_path: std::path::PathBuf,
) -> DynResult<()> {
    let (expected_fingerprint, bootstrap_addr) = identity::parse_token(&token)?;

    // A host advertising our own public address is on this side of the NAT;
    // dial loopback since hairpinning rarely works. The host key check still
    // runs against the token's fingerprint.
    let (host, port) = bootstrap_addr
        .rsplit_once(':')
        .ok_or("token address is missing a port")?;
    let bootstrap_addr = if host == connection::resolve_public_ip().await {
        format!("127.0.0.1:{}", port)
    } else {
        bootstrap_addr
    };

    info!("connecting to bootstrap endpoint {}", bootstrap_addr);
    let mut socket = TcpStream::connect(&bootstrap_addr).await?;

    let protocol = bootstrap::negotiate_client(&mut socket).await?;
    info!("negotiated protocol: {:?}", protocol);

    let connection = match protocol {
        Protocol::Ssh => {
            Connection::ssh_client(socket, expected_fingerprint, client_key_path).await?
        }
        Protocol::Wss => return Err("wss transport not implemented yet".into()),
    };

    info!("connection established");

    run_link(PeerId::Host, connection, &session).await
}

/// Owns one connection for its whole life: decodes every inbound frame into
/// the session's inbox, drains the session's outbound channel onto the wire.
/// The session closing that channel (dropping the peer) is the close signal.
async fn run_link(id: PeerId, connection: Connection, session: &SessionHandle) -> DynResult<()> {
    let (mut peer_writer, mut peer_reader) = connection.split();
    let (link_sender, mut session_receiver) = mpsc::channel::<PeerMessage>(8);

    session
        .send(SessionEvent::PeerConnected(id.clone(), link_sender))
        .await?;

    loop {
        tokio::select! {
            inbound = peer_reader.next() => {
                match inbound {
                    Some(Ok(Message::Data(data))) => match ppp::decode(&data).await {
                        Ok(message) => {
                            session
                                .send(SessionEvent::FromPeer(id.clone(), message))
                                .await?
                        }
                        Err(e) => info!("failed to decode peer message: {}", e),
                    },
                    Some(Ok(Message::Close)) => {
                        info!("peer closed the connection");
                        break;
                    }
                    Some(Err(e)) => {
                        info!("connection error: {}", e);
                        break;
                    }
                    None => break,
                }
            }
            outbound = session_receiver.recv() => {
                match outbound {
                    Some(message) => {
                        peer_writer.send(Message::Data(ppp::encode(&message)?)).await?
                    }
                    // the session dropped our sender: close the link gracefully
                    None => {
                        peer_writer.send(Message::Close).await?;
                        break;
                    }
                }
            }
        }
    }

    peer_writer.close().await?;
    info!("link closed");

    session.send(SessionEvent::PeerDisconnected(id)).await?;

    Ok(())
}
