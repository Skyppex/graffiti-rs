pub mod connection;
pub mod receive;
pub mod send;

use std::sync::Arc;

use tokio::sync::{
    mpsc::{Receiver, Sender},
    Mutex,
};
use tracing::info;

use crate::{
    net::connection::{Connection, ConnectionMode, Message},
    ppp,
    state::State,
    DynResult,
};

pub async fn run_host(
    state: Arc<Mutex<State>>,
    sender: Sender<send::Message>,
    mut receiver: Receiver<receive::Message>,
    authorized_keys_path: Option<std::path::PathBuf>,
) -> DynResult<()> {
    info!("connecting...");
    let stream = Connection::host(
        ConnectionMode::Ssh,
        async |fingerprint| {
            info!("Fingerprint: {}", &fingerprint);

            sender.send(send::Message::Fingerprint(fingerprint)).await?;
            Ok(())
        },
        authorized_keys_path,
    )
    .await?;

    info!("connection established");

    let (mut writer, mut reader) = stream.split();

    let mut shutdown_id = None;

    loop {
        tokio::select! {
            // Handle websocket messages
            Some(msg) = reader.next() => {
                info!("Received from client: {:?}", msg);

                if msg.is_err() {
                    break;
                }

                let msg = msg?;

                if let Message::Close = msg {
                    info!("Client disconnected");
                    break;
                }

                ppp::receive::handle_message(msg, state.clone(), &mut writer, &sender).await?;
            }
            // Handle channel messages
            Some(msg) = receiver.recv() => {
                info!("Received from main: {}", msg);

                if let receive::Message::Shutdown(id) = msg {
                    info!("Shutting down");
                    writer.send(Message::Close).await?;
                    shutdown_id = Some(id);
                } else {
                    receive::handle_message(msg, state.clone(), &mut writer).await?;
                }
            }
        }
    }

    info!("Websocket connection closed");
    writer.close().await?;
    info!("closed websocket sink");
    sender.send(send::Message::Shutdown(shutdown_id)).await?;
    info!("shutdown sent to main");

    Ok(())
}

pub async fn run_client(
    fingerprint: String,
    state: Arc<Mutex<State>>,
    sender: Sender<send::Message>,
    mut receiver: Receiver<receive::Message>,
    client_key_path: Option<std::path::PathBuf>,
) -> DynResult<()> {
    let stream = Connection::connect(fingerprint, client_key_path).await?;

    let (mut writer, mut reader) = stream.split();

    ppp::send::initialize(state.clone(), &mut writer).await?;

    let mut shutdown_id = None;

    loop {
        tokio::select! {
            // Handle incoming messages
            Some(msg) = reader.next() => {
                info!("Received from host");

                if msg.is_err() {
                    break;
                }

                let msg = msg?;

                if let Message::Close = msg {
                    info!("Disconnected by server");
                    break;
                }

                ppp::receive::handle_message(msg, state.clone(), &mut writer, &sender).await?;
            }
            // Handle channel messages
            Some(msg) = receiver.recv() => {
                info!("Received from main: {}", msg);

                if let receive::Message::Shutdown(id) = msg {
                    info!("Shutting down");
                    writer.send(Message::Close).await?;
                    shutdown_id = Some(id);
                } else {
                    receive::handle_message(msg, state.clone(), &mut writer).await?;
                }
            }
        }
    }

    info!("Websocket connection closed");
    writer.close().await?;
    info!("closed websocket sink");
    sender.send(send::Message::Shutdown(shutdown_id)).await?;
    info!("shutdown sent to main");

    Ok(())
}
