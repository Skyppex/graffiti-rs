use std::sync::{Arc, Mutex};

use futures_util::{SinkExt, StreamExt};

use tokio::net::TcpListener;
use tokio_tungstenite::{
    accept_async_with_config, connect_async,
    tungstenite::{http::Uri, Message},
};

use crate::{DynResult, Log, Logger};

// struct CertData {
//     certs: Vec<CertificateDer<'static>>,
//     key: PrivateKeyDer<'static>,
// }
//
// fn compute_fingerprint(cert: &CertificateDer<'static>) -> String {
//     let mut hasher = Sha256::new();
//     hasher.update(cert.as_ref());
//     let result = hasher.finalize();
//     hex::encode(result)
// }
//
// fn generate_cert() -> CertData {
//     let CertifiedKey { cert, key_pair } =
//         rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
//     let cert_der = cert.der();
//     let priv_key_der = key_pair.serialize_der();
//
//     CertData {
//         certs: vec![cert_der.clone()],
//         key: PrivateKeyDer::from(PrivatePkcs8KeyDer::from(priv_key_der)),
//     }
// }

pub async fn run_host(mut logger: Arc<Mutex<Logger>>) -> DynResult<()> {
    let listener = TcpListener::bind("0.0.0.0:8080").await?; // Bind to all interfaces
    logger.log("Listening on 0.0.0.0:8080")?;

    let (socket, addr) = listener.accept().await?;
    logger.log(&format!("Client connected from: {}", addr))?;

    let ws_stream = accept_async_with_config(socket, None).await?;
    logger.log("WebSocket connection established")?;

    let (mut write, mut read) = ws_stream.split();

    // Send a test message
    write.send(Message::Text("Hello from host!".into())).await?;

    // Handle incoming messages
    while let Some(msg) = read.next().await {
        match msg? {
            Message::Text(text) => {
                logger.log(&format!("Received message: {}", text))?;
            }
            Message::Close(_) => {
                logger.log("Client disconnected")?;
                break;
            }
            _ => {}
        }
    }

    Ok(())
}

pub async fn run_client(mut logger: Arc<Mutex<Logger>>) -> DynResult<()> {
    let url = "ws://127.0.0.1:8080".parse::<Uri>()?;

    let (ws_stream, _) = connect_async(url).await?;
    logger.log("Reconnected with pinned certificate")?;

    let (mut write, mut read) = ws_stream.split();
    // Send a test message
    write
        .send(Message::Text("Hello from client!".into()))
        .await?;

    // Handle incoming messages
    while let Some(msg) = read.next().await {
        match msg? {
            Message::Text(text) => {
                logger.log(&format!("Received message: {}", text))?;
            }
            Message::Close(_) => {
                logger.log("Server disconnected")?;
                break;
            }
            _ => {}
        }
    }

    Ok(())
}
