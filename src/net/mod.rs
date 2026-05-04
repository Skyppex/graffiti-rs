pub mod connection;
pub mod receive;
pub mod send;

use std::{net::IpAddr, str::FromStr, sync::Arc};

use futures_util::{stream::SplitSink, SinkExt, StreamExt};

use rcgen::CertifiedKey;
use rustls::{
    client::danger::{ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    ClientConfig, ServerConfig, SignatureScheme,
};
use sha2::{Digest, Sha256};
use tokio::{
    net::TcpListener,
    sync::{
        mpsc::{Receiver, Sender},
        Mutex,
    },
};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::{
    accept_async_with_config, connect_async_tls_with_config,
    tungstenite::{http::Uri, Message},
    Connector, WebSocketStream,
};

use crate::{
    id::next_client_id,
    net::connection::{Connection, ConnectionMode},
    ppp,
    state::State,
    DynResult, Log, Logger,
};

pub type WsWriter<S> = SplitSink<WebSocketStream<S>, Message>;

struct CertData {
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

fn compute_fingerprint(cert: &CertificateDer<'static>, public_ip: &IpAddr) -> String {
    let mut hasher = Sha256::new();
    hasher.update(cert.as_ref());
    let result = hasher.finalize();

    let octets = match public_ip {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    };

    let result = result.into_iter().chain(octets).collect::<Vec<u8>>();

    hex::encode(result)
}

fn generate_cert(public_ip: &IpAddr) -> CertData {
    let CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec![public_ip.to_string()]).unwrap();
    let cert_der = cert.der();
    let priv_key_der = key_pair.serialize_der();

    CertData {
        certs: vec![cert_der.clone()],
        key: PrivateKeyDer::from(PrivatePkcs8KeyDer::from(priv_key_der)),
    }
}

async fn get_ip() -> DynResult<String> {
    Ok(reqwest::get("https://api.ipify.org").await?.text().await?)
}

pub async fn run_host(
    state: Arc<Mutex<State>>,
    sender: Sender<send::Message>,
    mut receiver: Receiver<receive::Message>,
    mut logger: Arc<Mutex<Logger>>,
) -> DynResult<()> {
    let stream = Connection::host(ConnectionMode::Direct, async |fingerprint| {
        logger
            .log(&format!("Fingerprint: {}", &fingerprint))
            .await?;

        sender.send(send::Message::Fingerprint(fingerprint)).await?;
        Ok(())
    })
    .await?;

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

                if let Message::Close(_) = msg {
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
                    writer.send(Message::Close(None)).await?;
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
    let stream = Connection::connect(fingerprint).await?;

    let (mut writer, mut reader) = stream.split();

    ppp::send::initialize(state.clone(), &mut writer, logger.clone()).await?;

    let mut shutdown_id = None;

    loop {
        tokio::select! {
            // Handle incoming messages
            Some(msg) = reader.next() => {
                logger.log(&format!("Received from host")).await?;

                if msg.is_err() {
                    break;
                }

                let msg = msg?;

                if let Message::Close(_) = msg {
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
                    writer.send(Message::Close(None)).await?;
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
