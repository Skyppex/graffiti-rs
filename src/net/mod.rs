pub mod receive;
pub mod send;

use std::sync::Arc;

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

use crate::{ppp, state::State, DynResult, Log, Logger};

pub type WsWriter<S> = SplitSink<WebSocketStream<S>, Message>;

struct CertData {
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

fn compute_fingerprint(cert: &CertificateDer<'static>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(cert.as_ref());
    let result = hasher.finalize();
    hex::encode(result)
}

fn generate_cert() -> CertData {
    let CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = cert.der();
    let priv_key_der = key_pair.serialize_der();

    CertData {
        certs: vec![cert_der.clone()],
        key: PrivateKeyDer::from(PrivatePkcs8KeyDer::from(priv_key_der)),
    }
}

pub async fn run_host(
    state: Arc<Mutex<State>>,
    sender: Sender<send::Message>,
    mut receiver: Receiver<receive::Message>,
    mut logger: Arc<Mutex<Logger>>,
) -> DynResult<()> {
    let cert_data = generate_cert();
    let fingerprint = compute_fingerprint(&cert_data.certs[0]);
    logger.log(&format!("Fingerprint: {}", fingerprint)).await?;

    sender.send(send::Message::Fingerprint(fingerprint)).await?;

    let tls_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_data.certs, cert_data.key)?;

    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

    let listener = TcpListener::bind("0.0.0.0:8080").await?;
    logger.log("Listening on 0.0.0.0:8080").await?;

    let (socket, addr) = listener.accept().await?;
    logger
        .log(&format!("Client connected from: {}", addr))
        .await?;

    let tls_stream = match tls_acceptor.accept(socket).await {
        Ok(s) => s,
        Err(e) => {
            logger.log(&format!("TLS error: {:?}", e)).await?;
            return Ok(());
        }
    };

    logger.log("TLS connection established").await?;

    let ws_stream = accept_async_with_config(tls_stream, None).await?;
    logger.log("WebSocket connection established").await?;

    let (mut writer, mut reader) = ws_stream.split();

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
                    receive::handle_message(msg, &mut writer, logger.clone()).await?;
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
    let url = "wss://127.0.0.1:8080".parse::<Uri>()?;
    logger.log(&format!("Connecting to {}", url)).await?;

    let verifier = FingerprintVerifier::new(hex::decode(fingerprint)?);

    let tls_config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();

    let tls_connector = Connector::Rustls(Arc::new(tls_config));

    let (ws_stream, _) =
        connect_async_tls_with_config(url, None, false, Some(tls_connector)).await?;

    logger.log("Connected with pinned certificate").await?;

    let (mut writer, mut reader) = ws_stream.split();

    ppp::send::initialize(&mut writer).await?;

    let mut shutdown_id = None;

    loop {
        tokio::select! {
            // Handle incoming messages
            Some(msg) = reader.next() => {
                logger.log(&format!("Received from host: {:?}", msg)).await?;

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
                    receive::handle_message(msg, &mut writer, logger.clone()).await?;
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

#[derive(Debug)]
struct FingerprintVerifier {
    fingerprint: Vec<u8>,
}

impl FingerprintVerifier {
    pub fn new(fingerprint: Vec<u8>) -> Self {
        Self { fingerprint }
    }
}

impl ServerCertVerifier for FingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        eprintln!("Verifying certificate");
        let mut hasher = Sha256::new();
        hasher.update(end_entity.as_ref());
        let fingerprint = hasher.finalize();

        if fingerprint.as_slice() == self.fingerprint.as_slice() {
            eprintln!("Verified certificate");
            Ok(ServerCertVerified::assertion())
        } else {
            eprintln!("Fingerprint mismatch");
            Err(rustls::Error::General("Fingerprint mismatch".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // For development, we can accept all signatures
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())

        // // Use webpki to verify the signature
        // let cert_content = cert.as_ref();
        // let alg = match dss.scheme {
        //     rustls::SignatureScheme::RSA_PKCS1_SHA256 => &webpki::RSA_PKCS1_2048_8192_SHA256,
        //     rustls::SignatureScheme::ECDSA_NISTP256_SHA256 => &webpki::ECDSA_P256_SHA256,
        //     // Add other schemes you want to support
        //     _ => return Err(rustls::Error::General("Unsupported signature scheme".into())),
        // };
        //
        // match alg.verify(
        //     untrusted::Input::from(cert_content),
        //     untrusted::Input::from(message),
        //     untrusted::Input::from(&dss.signature),
        // ) {
        //     Ok(()) => Ok(rustls::client::danger::HandshakeSignatureValid::assertion()),
        //     Err(_) => Err(rustls::Error::General("Invalid signature".into())),
        // }
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // For development, we can accept all signatures
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())

        // // TLS 1.3 uses different signature verification
        // // Similar to TLS 1.2 but with TLS 1.3 specific algorithms
        // let cert_content = cert.as_ref();
        // let alg = match dss.scheme {
        //     rustls::SignatureScheme::RSA_PSS_SHA256 => &webpki::RSA_PSS_2048_8192_SHA256,
        //     rustls::SignatureScheme::ECDSA_NISTP384_SHA384 => &webpki::ECDSA_P384_SHA384,
        //     // Add other TLS 1.3 schemes
        //     _ => return Err(rustls::Error::General("Unsupported signature scheme".into())),
        // };
        //
        // match alg.verify(
        //     untrusted::Input::from(cert_content),
        //     untrusted::Input::from(message),
        //     untrusted::Input::from(&dss.signature),
        // ) {
        //     Ok(()) => Ok(rustls::client::danger::HandshakeSignatureValid::assertion()),
        //     Err(_) => Err(rustls::Error::General("Invalid signature".into())),
        // }
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
        ]
    }
}
