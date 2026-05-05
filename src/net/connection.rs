use std::{future::Future, net::IpAddr, str::FromStr, sync::Arc};

use futures_util::{
    stream::{SplitSink, SplitStream},
    SinkExt, StreamExt,
};

use rcgen::CertifiedKey;
use russh::{
    client,
    keys::{ssh_key, Algorithm, PrivateKey, PrivateKeyWithHashAlg},
    server, Channel, ChannelMsg, ChannelStream,
};
use rustls::{
    client::danger::{ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    ClientConfig, ServerConfig, SignatureScheme,
};
use sha2::{Digest, Sha256};
use tokio::{
    io::{ReadHalf, WriteHalf},
    net::{TcpListener, TcpStream},
    sync::{oneshot, Mutex},
};
use tokio_rustls::{server::TlsStream, TlsAcceptor};
use tokio_tungstenite::{
    accept_async_with_config, connect_async_tls_with_config,
    tungstenite::{self, http::Uri, Utf8Bytes},
    Connector, MaybeTlsStream, WebSocketStream,
};
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};

use crate::{DynError, DynResult, Log, Logger};

#[derive(Debug, Clone)]
pub enum Message {
    Data(Vec<u8>),
    Close,
}

impl From<tungstenite::Message> for Message {
    fn from(value: tungstenite::Message) -> Self {
        match value {
            tungstenite::Message::Text(data) => Message::Data(data.bytes().collect::<Vec<_>>()),
            tungstenite::Message::Close(_) => Message::Close,
            _ => todo!("unhandled message type (wss)"),
        }
    }
}

impl TryInto<tungstenite::Message> for Message {
    type Error = DynError;

    fn try_into(self) -> Result<tungstenite::Message, Self::Error> {
        match self {
            Message::Data(data) => Ok(tungstenite::Message::Text(Utf8Bytes::try_from(data)?)),
            Message::Close => Ok(tungstenite::Message::Close(None)),
        }
    }
}

impl From<Message> for Vec<u8> {
    fn from(val: Message) -> Self {
        match val {
            Message::Data(data) => [[0].to_vec(), data].concat(),
            Message::Close => vec![1],
        }
    }
}

impl TryFrom<Vec<u8>> for Message {
    type Error = DynError;

    fn try_from(mut value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.is_empty() {
            return Err("failed to deserialize bytes into message".into());
        }

        value.push(0);
        let end = value.len() - 1;
        value.swap(0, end);

        let message_type = value.remove(end);

        match message_type {
            // data
            0 => {
                let slice = &value[1..];
                Ok(Message::Data(slice.to_vec()))
            }
            // close
            1 => Ok(Message::Close),
            _ => unreachable!("unknown message type"),
        }
    }
}

impl TryFrom<ChannelMsg> for Message {
    type Error = DynError;

    fn try_from(value: ChannelMsg) -> Result<Self, Self::Error> {
        match value {
            ChannelMsg::Data { data } => Ok(data.to_vec().try_into()?),
            ChannelMsg::Close => Ok(Message::Close),
            _ => todo!("unhandled message type (ssh)"),
        }
    }
}

pub enum ConnectionMode {
    Direct,
    Ssh,
}

pub enum Connection {
    DirectHost(WebSocketStream<TlsStream<TcpStream>>),
    DirectClient(WebSocketStream<MaybeTlsStream<TcpStream>>),
    SshHost(ChannelStream<server::Msg>),
    SshClient(ChannelStream<client::Msg>),
}

pub enum ConnectionWriter {
    DirectHost(SplitSink<WebSocketStream<TlsStream<TcpStream>>, tungstenite::Message>),
    DirectClient(SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, tungstenite::Message>),
    SshHost(FramedWrite<WriteHalf<ChannelStream<server::Msg>>, LengthDelimitedCodec>),
    SshClient(FramedWrite<WriteHalf<ChannelStream<client::Msg>>, LengthDelimitedCodec>),
}

pub enum ConnectionReader {
    DirectHost(SplitStream<WebSocketStream<TlsStream<TcpStream>>>),
    DirectClient(SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>),
    SshHost(FramedRead<ReadHalf<ChannelStream<server::Msg>>, LengthDelimitedCodec>),
    SshClient(FramedRead<ReadHalf<ChannelStream<client::Msg>>, LengthDelimitedCodec>),
}

struct CertData {
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

async fn get_ip() -> DynResult<String> {
    Ok(reqwest::get("https://api.ipify.org").await?.text().await?)
}

fn generate_cert(public_ip: String) -> CertData {
    let CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec![public_ip]).unwrap();
    let cert_der = cert.der();
    let priv_key_der = key_pair.serialize_der();

    CertData {
        certs: vec![cert_der.clone()],
        key: PrivateKeyDer::from(PrivatePkcs8KeyDer::from(priv_key_der)),
    }
}

fn compute_fingerprint(data: &[u8], connection_string: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();

    let result = result
        .into_iter()
        .chain(connection_string.iter().copied())
        .collect::<Vec<u8>>();

    hex::encode(result)
}

fn compute_fingerprint_raw(data: &[u8], connection_string: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.update(connection_string);
    hex::encode(hasher.finalize())
}

fn compute_fingerprint_simple(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

fn load_authorized_keys(path: &std::path::Path) -> DynResult<Vec<Vec<u8>>> {
    let content = std::fs::read_to_string(path)?;
    let mut fingerprints = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let fingerprint = if line.starts_with("ssh-") {
            let key = ssh_key::PublicKey::from_openssh(line)
                .map_err(|e| format!("failed to parse public key: {}", e))?;
            compute_fingerprint_simple(key.to_bytes()?.as_ref())
        } else if line.len() == 64 && line.chars().all(|c| c.is_ascii_hexdigit()) {
            hex::decode(line)?
        } else {
            continue;
        };

        fingerprints.push(fingerprint);
    }

    Ok(fingerprints)
}

impl Connection {
    pub async fn host<F, Fut>(
        mode: ConnectionMode,
        fingerprint_generated: F,
        mut logger: Arc<Mutex<Logger>>,
        authorized_keys_path: Option<std::path::PathBuf>,
    ) -> DynResult<Self>
    where
        F: FnOnce(String) -> Fut,
        Fut: Future<Output = DynResult<()>>,
    {
        let authorized_keys = if let Some(path) = authorized_keys_path {
            load_authorized_keys(&path).unwrap_or_default()
        } else {
            Vec::new()
        };
        match mode {
            ConnectionMode::Direct => {
                let ip = get_ip().await.unwrap_or_else(|_| "127.0.0.1".to_string());
                let cert_data = generate_cert(ip.clone());
                let ip = IpAddr::from_str(&ip)?;

                let octets = match ip {
                    IpAddr::V4(v4) => v4.octets().to_vec(),
                    IpAddr::V6(v6) => v6.octets().to_vec(),
                };

                let connection_string = [b"ws://".to_vec(), octets].concat();
                let fingerprint = compute_fingerprint(&cert_data.certs[0], &connection_string);

                fingerprint_generated(fingerprint.clone()).await?;

                let tls_config = ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(cert_data.certs, cert_data.key)?;

                let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

                let uri = "0.0.0.0:32700";
                let listener = TcpListener::bind(uri).await?;
                logger.log(&format!("Listening on {}", uri)).await?;

                let (socket, _) = listener.accept().await?;

                let tls_stream = match tls_acceptor.accept(socket).await {
                    Ok(s) => s,
                    Err(e) => return Err(Box::new(e)),
                };

                let ws_stream = accept_async_with_config(tls_stream, None).await?;

                Ok(Connection::DirectHost(ws_stream))
            }
            ConnectionMode::Ssh => {
                let host = "127.0.0.1".to_string();

                let host_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)?;

                let connection_string = [b"ssh://".to_vec(), host.as_bytes().to_vec()].concat();

                let fingerprint = compute_fingerprint_raw(
                    host_key.public_key().to_bytes()?.as_ref(),
                    &connection_string,
                );

                fingerprint_generated(fingerprint.to_string()).await?;

                let uri = "0.0.0.0:32700";
                let listener = TcpListener::bind(uri).await?;
                logger.log(&format!("Listening on {}", uri)).await?;

                let (socket, _) = listener.accept().await?;

                let mut ssh_config = server::Config::default();

                ssh_config.keys.push(host_key);

                let (channel_tx, channel_rx) = oneshot::channel();

                let ssh_handler = ServerFlow {
                    channel_tx: Some(channel_tx),
                    logger: logger.clone(),
                    authorized_keys,
                };

                logger
                    .log(&format!("creating ssh session on {}", uri))
                    .await?;

                let session = server::run_stream(Arc::new(ssh_config), socket, ssh_handler).await?;

                tokio::spawn(async move {
                    let _ = session.await;
                });

                logger
                    .log(&format!("ssh session created on {}", uri))
                    .await?;

                let channel = channel_rx.await?;

                logger.log("MMM accepted session creation").await?;

                Ok(Connection::SshHost(channel.into_stream()))
            }
        }
    }

    pub async fn connect(
        fingerprint_from_out_of_band: String,
        mut logger: Arc<Mutex<Logger>>,
        client_key_path: Option<std::path::PathBuf>,
    ) -> DynResult<Self> {
        let client_key = if let Some(path) = client_key_path {
            let content = tokio::fs::read_to_string(&path).await?;
            Some(PrivateKey::from_openssh(&content)?)
        } else {
            None
        };

        let ip = get_ip().await.unwrap_or_else(|_| "127.0.0.1".to_string());

        let (fingerprint, connection_string, connection_mode) = {
            let decoded = hex::decode(fingerprint_from_out_of_band.clone())?;

            let (fingerprint, connection_string) = decoded.split_at(32);

            let conn_str = String::from_utf8_lossy(connection_string);
            logger.log(&format!("aaa {}", conn_str)).await?;

            let conn_uri = Uri::from_str(&conn_str)?;

            logger.log(&format!("uri {:?}", conn_uri)).await?;
            logger
                .log(&format!("scheme {:?}", conn_uri.scheme_str()))
                .await?;

            if conn_uri.scheme_str().is_some_and(|s| s == "ssh") {
                (
                    fingerprint.to_vec(),
                    connection_string.to_vec(),
                    ConnectionMode::Ssh,
                )
            } else if conn_uri.scheme_str().is_some_and(|s| s == "wss") {
                (
                    fingerprint.to_vec(),
                    connection_string.to_vec(),
                    ConnectionMode::Direct,
                )
            } else {
                return Err(format!("unsupported protocol: {:?}", conn_uri.scheme_str()).into());
            }
        };

        let connection_string = if connection_string == ip.as_bytes().to_vec() {
            b"127.0.0.1".to_vec()
        } else {
            connection_string
        };

        let uri =
            format!("{}:32700", String::from_utf8_lossy(&connection_string)).parse::<Uri>()?;

        logger.log(&format!("Connecting to {}", uri)).await?;

        match connection_mode {
            ConnectionMode::Direct => {
                let verifier = FingerprintVerifier::new(fingerprint);

                let tls_config = ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(verifier))
                    .with_no_client_auth();

                let tls_connector = Connector::Rustls(Arc::new(tls_config));

                let (ws_stream, _) =
                    connect_async_tls_with_config(uri, None, false, Some(tls_connector)).await?;

                // logger.log("Connected with pinned certificate").await?;

                Ok(Connection::DirectClient(ws_stream))
            }
            ConnectionMode::Ssh => {
                let ssh_config = client::Config::default();
                let ssh_handler = ClientFlow {
                    connection_string,
                    expected_fingerprint_hex: fingerprint_from_out_of_band,
                };

                let host = uri.host().ok_or("missing host")?;
                let address = format!("{}:32700", host);

                logger
                    .log(&format!("creating ssh session on {}", &address))
                    .await?;

                let mut session =
                    client::connect(Arc::new(ssh_config), &address, ssh_handler).await?;

                logger
                    .log(&format!("ssh session created on {}", address))
                    .await?;

                let auth_result = if let Some(ref key) = client_key {
                    let key_with_hash = PrivateKeyWithHashAlg::new(Arc::new(key.clone()), None);
                    session.authenticate_publickey("peer", key_with_hash).await?
                } else {
                    session.authenticate_none("peer").await?
                };

                if !auth_result.success() {
                    return Err("failed to authenticate over ssh".into());
                }

                let channel = session.channel_open_session().await?;

                logger
                    .log(&format!("ssh session created on {}", address))
                    .await?;

                Ok(Connection::SshClient(channel.into_stream()))
            }
        }
    }

    pub fn split(self) -> (ConnectionWriter, ConnectionReader) {
        match self {
            Connection::DirectHost(stream) => {
                let (writer, reader) = stream.split();

                let conn_writer = ConnectionWriter::DirectHost(writer);
                let conn_reader = ConnectionReader::DirectHost(reader);

                (conn_writer, conn_reader)
            }
            Connection::DirectClient(stream) => {
                let (writer, reader) = stream.split();

                let conn_writer = ConnectionWriter::DirectClient(writer);
                let conn_reader = ConnectionReader::DirectClient(reader);

                (conn_writer, conn_reader)
            }
            Connection::SshHost(stream) => {
                let (reader, writer) = tokio::io::split(stream);

                let conn_writer = ConnectionWriter::SshHost(FramedWrite::new(
                    writer,
                    LengthDelimitedCodec::new(),
                ));

                let conn_reader =
                    ConnectionReader::SshHost(FramedRead::new(reader, LengthDelimitedCodec::new()));

                (conn_writer, conn_reader)
            }
            Connection::SshClient(stream) => {
                let (reader, writer) = tokio::io::split(stream);

                let conn_writer = ConnectionWriter::SshClient(FramedWrite::new(
                    writer,
                    LengthDelimitedCodec::new(),
                ));

                let conn_reader = ConnectionReader::SshClient(FramedRead::new(
                    reader,
                    LengthDelimitedCodec::new(),
                ));

                (conn_writer, conn_reader)
            }
        }
    }
}

impl ConnectionWriter {
    pub async fn send(&mut self, msg: Message) -> DynResult<()> {
        match self {
            ConnectionWriter::DirectHost(stream) => stream.send(msg.try_into()?).await?,
            ConnectionWriter::DirectClient(stream) => stream.send(msg.try_into()?).await?,
            ConnectionWriter::SshHost(stream) => {
                stream.send(Into::<Vec<u8>>::into(msg).into()).await?
            }
            ConnectionWriter::SshClient(stream) => {
                stream.send(Into::<Vec<u8>>::into(msg).into()).await?
            }
        }

        Ok(())
    }

    pub async fn close(&mut self) -> DynResult<()> {
        match self {
            ConnectionWriter::DirectHost(stream) => stream.close().await?,
            ConnectionWriter::DirectClient(stream) => stream.close().await?,
            ConnectionWriter::SshHost(stream) => stream.close().await?,
            ConnectionWriter::SshClient(stream) => stream.close().await?,
        }

        Ok(())
    }
}

impl ConnectionReader {
    pub async fn next(&mut self) -> Option<DynResult<Message>> {
        match self {
            ConnectionReader::DirectHost(stream) => stream
                .next()
                .await
                .map(|v| v.map(|v| v.into()).map_err(|e| e.into())),
            ConnectionReader::DirectClient(stream) => stream
                .next()
                .await
                .map(|v| v.map(|v| v.into()).map_err(|e| e.into())),
            ConnectionReader::SshHost(channel) => channel.next().await.map(|v| {
                v.map(|v| TryInto::<Message>::try_into(v.to_vec()))
                    .map_err(|e| e.into())
                    .flatten()
            }),
            ConnectionReader::SshClient(channel) => channel.next().await.map(|v| {
                v.map(|v| v.to_vec().try_into())
                    .map_err(|e| e.into())
                    .flatten()
            }),
        }
    }
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
        let mut hasher = Sha256::new();
        hasher.update(end_entity.as_ref());
        let fingerprint = hasher.finalize();

        if fingerprint.as_slice() == self.fingerprint.as_slice() {
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

struct ServerFlow {
    channel_tx: Option<oneshot::Sender<Channel<server::Msg>>>,
    logger: Arc<Mutex<Logger>>,
    authorized_keys: Vec<Vec<u8>>,
}

struct ClientFlow {
    connection_string: Vec<u8>,
    expected_fingerprint_hex: String,
}

impl server::Handler for ServerFlow {
    type Error = DynError;

    async fn auth_none(&mut self, _user: &str) -> Result<russh::server::Auth, Self::Error> {
        Ok(russh::server::Auth::Accept)
    }

    async fn auth_password(
        &mut self,
        _user: &str,
        _password: &str,
    ) -> Result<server::Auth, Self::Error> {
        Ok(russh::server::Auth::reject())
    }

    async fn auth_publickey(
        &mut self,
        _user: &str,
        public_key: &russh::keys::PublicKey,
    ) -> Result<russh::server::Auth, Self::Error> {
        if self.authorized_keys.is_empty() {
            return Ok(russh::server::Auth::Accept);
        }

        let key_bytes = public_key.to_bytes().map_err(|e| e.to_string())?;
        let key_fingerprint = compute_fingerprint_simple(key_bytes.as_ref());

        if self.authorized_keys.iter().any(|f| f == &key_fingerprint) {
            Ok(russh::server::Auth::Accept)
        } else {
            Ok(russh::server::Auth::reject())
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<server::Msg>,
        _session: &mut server::Session,
    ) -> Result<bool, Self::Error> {
        self.logger.log("MMM accepting session creation").await?;

        if let Some(tx) = self.channel_tx.take() {
            let _ = tx.send(channel);
        }

        Ok(true)
    }
}

impl client::Handler for ClientFlow {
    type Error = DynError;

    async fn check_server_key(
        &mut self,
        server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        let computed = compute_fingerprint_raw(
            server_public_key.to_bytes()?.as_ref(),
            &self.connection_string,
        );
        Ok(computed == self.expected_fingerprint_hex)
    }
}
