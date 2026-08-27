pub mod connection;

use tokio::sync::mpsc;
use tracing::info;

use crate::{
    id::next_client_id,
    net::connection::{Connection, ConnectionMode, Message},
    ppp,
    session::{
        peer::{PeerId, PeerMessage},
        SessionEvent, SessionHandle,
    },
    DynResult,
};

pub async fn run_host(
    session: SessionHandle,
    authorized_keys_path: std::path::PathBuf,
) -> DynResult<()> {
    info!("connecting...");
    let connection = Connection::host(
        ConnectionMode::Ssh,
        async |fingerprint| {
            info!("Fingerprint: {}", &fingerprint);
            session.send(SessionEvent::Fingerprint(fingerprint)).await
        },
        authorized_keys_path,
    )
    .await?;

    info!("connection established");

    // the host allocates the client_id at accept time, so the link and the
    // author it carries share one identity from the first frame
    run_link(PeerId::Client(next_client_id()), connection, &session).await
}

pub async fn run_client(
    fingerprint: String,
    session: SessionHandle,
    client_key_path: std::path::PathBuf,
) -> DynResult<()> {
    let connection = Connection::connect(fingerprint, client_key_path).await?;

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
