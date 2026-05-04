pub mod connection;
pub mod receive;
pub mod send;

use std::sync::Arc;

use tokio::sync::{
    mpsc::{Receiver, Sender},
    Mutex,
};

use crate::{
    net::connection::{Connection, ConnectionMode, Message},
    ppp,
    state::State,
    DynResult, Log, Logger,
};

pub async fn run_host(
    state: Arc<Mutex<State>>,
    sender: Sender<send::Message>,
    mut receiver: Receiver<receive::Message>,
    mut logger: Arc<Mutex<Logger>>,
) -> DynResult<()> {
    let stream = Connection::host(
        ConnectionMode::Ssh,
        async |fingerprint| {
            logger
                .clone()
                .log(&format!("Fingerprint: {}", &fingerprint))
                .await?;

            sender.send(send::Message::Fingerprint(fingerprint)).await?;
            Ok(())
        },
        logger.clone(),
    )
    .await?;

    logger.log("connection established").await?;

    let (mut writer, mut reader) = stream.split();

    let mut shutdown_id = None;

    loop {
        tokio::select! {
            // Handle websocket messages
            Some(msg) = reader.next() => {
                logger.log(&format!("Received from client: {:?}", msg)).await?;

                if msg.is_err() {
                    break;
                }

                let msg = msg?;

                if let Message::Close = msg {
                    logger.log("Client disconnected").await?;
                    break;
                }

                ppp::receive::handle_message(msg, state.clone(), &mut writer, &sender, logger.clone()).await?;
            }
            // Handle channel messages
            Some(msg) = receiver.recv() => {
                logger.log(&format!("Received from main: {}", msg)).await?;

                if let receive::Message::Shutdown(id) = msg {
                    logger.log("Shutting down").await?;
                    writer.send(Message::Close).await?;
                    shutdown_id = Some(id);
                } else {
                    receive::handle_message(msg, state.clone(), &mut writer, logger.clone()).await?;
                }
            }
        }
    }

    logger.log("Websocket connection closed").await?;
    writer.close().await?;
    logger.log("closed websocket sink").await?;
    sender.send(send::Message::Shutdown(shutdown_id)).await?;
    logger.log("shutdown sent to main").await?;

    Ok(())
}

pub async fn run_client(
    fingerprint: String,
    state: Arc<Mutex<State>>,
    sender: Sender<send::Message>,
    mut receiver: Receiver<receive::Message>,
    mut logger: Arc<Mutex<Logger>>,
) -> DynResult<()> {
    let stream = Connection::connect(fingerprint, logger.clone()).await?;

    let (mut writer, mut reader) = stream.split();

    ppp::send::initialize(state.clone(), &mut writer, logger.clone()).await?;

    let mut shutdown_id = None;

    loop {
        tokio::select! {
            // Handle incoming messages
            Some(msg) = reader.next() => {
                logger.log("Received from host").await?;

                if msg.is_err() {
                    break;
                }

                let msg = msg?;

                if let Message::Close = msg {
                    logger.log("Disconnected by server").await?;
                    break;
                }

                ppp::receive::handle_message(msg, state.clone(), &mut writer, &sender, logger.clone()).await?;
            }
            // Handle channel messages
            Some(msg) = receiver.recv() => {
                logger.log(&format!("Received from main: {}", msg)).await?;

                if let receive::Message::Shutdown(id) = msg {
                    logger.log("Shutting down").await?;
                    writer.send(Message::Close).await?;
                    shutdown_id = Some(id);
                } else {
                    receive::handle_message(msg, state.clone(), &mut writer, logger.clone()).await?;
                }
            }
        }
    }

    logger.log("Websocket connection closed").await?;
    writer.close().await?;
    logger.log("closed websocket sink").await?;
    sender.send(send::Message::Shutdown(shutdown_id)).await?;
    logger.log("shutdown sent to main").await?;

    Ok(())
}
