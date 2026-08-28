use std::{
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
};

use futures_util::{SinkExt, StreamExt};
use russh::{
    client,
    keys::{ssh_key, PrivateKey, PrivateKeyWithHashAlg},
    server, Channel, ChannelStream, MethodKind, MethodSet,
};
use tokio::{
    io::{ReadHalf, WriteHalf},
    net::TcpStream,
    sync::oneshot,
};
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};
use tracing::{info, warn};

use crate::{
    net::identity::{key_fingerprint, Identity},
    DynError, DynResult,
};

#[derive(Debug, Clone)]
pub enum Message {
    Data(Vec<u8>),
    Close,
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

pub enum Connection {
    SshHost(ChannelStream<server::Msg>),
    SshClient(ChannelStream<client::Msg>),
}

pub enum ConnectionWriter {
    SshHost(FramedWrite<WriteHalf<ChannelStream<server::Msg>>, LengthDelimitedCodec>),
    SshClient(FramedWrite<WriteHalf<ChannelStream<client::Msg>>, LengthDelimitedCodec>),
}

pub enum ConnectionReader {
    SshHost(FramedRead<ReadHalf<ChannelStream<server::Msg>>, LengthDelimitedCodec>),
    SshClient(FramedRead<ReadHalf<ChannelStream<client::Msg>>, LengthDelimitedCodec>),
}

async fn get_ip() -> DynResult<String> {
    Ok(reqwest::get("https://api.ipify.org").await?.text().await?)
}

/// The address the default route sends our packets from. On a machine with a
/// public IP bound directly to an interface (e.g. a VPS) this IS the public IP.
/// No packets are sent: connecting a UDP socket only selects the route.
fn local_outbound_ip() -> Option<IpAddr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:53").ok()?;
    socket.local_addr().ok().map(|addr| addr.ip())
}

fn is_global_v4(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    // 100.64.0.0/10 is carrier-grade NAT space
    let is_cgnat = octets[0] == 100 && (64..128).contains(&octets[1]);

    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_documentation()
        || is_cgnat)
}

/// The address peers can reach us on: a globally routable address on one of our
/// own interfaces when we have one, otherwise whatever the outside world sees us
/// as, otherwise loopback (offline/local-only).
pub async fn resolve_public_ip() -> String {
    if let Some(IpAddr::V4(ip)) = local_outbound_ip() {
        if is_global_v4(&ip) {
            return ip.to_string();
        }
    }

    get_ip().await.unwrap_or_else(|_| "127.0.0.1".to_string())
}

pub fn load_authorized_keys(path: &std::path::Path) -> DynResult<Vec<[u8; 32]>> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        format!(
            "failed to read authorized keys file {}: {}",
            path.display(),
            e
        )
    })?;
    let mut fingerprints = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        match ssh_key::PublicKey::from_openssh(line) {
            Ok(key) => fingerprints.push(key_fingerprint(key.to_bytes()?.as_ref())),
            Err(e) => warn!("skipping unparseable authorized keys line: {}", e),
        }
    }

    if fingerprints.is_empty() {
        return Err(format!("no valid public keys in {}", path.display()).into());
    }

    Ok(fingerprints)
}

impl Connection {
    /// Takes over a socket whose bootstrap prelude chose ssh, host side: the
    /// identity key becomes the SSH host key the client will verify against
    /// the token.
    pub async fn ssh_host(
        socket: TcpStream,
        identity: Identity,
        authorized_keys: Vec<[u8; 32]>,
    ) -> DynResult<Self> {
        let mut ssh_config = server::Config::default();
        ssh_config.keys.push(identity.key);

        let (channel_sender, channel_receiver) = oneshot::channel();

        let ssh_handler = ServerFlow {
            channel_sender: Some(channel_sender),
            authorized_keys,
        };

        info!("starting ssh on the bootstrapped socket");

        let session = server::run_stream(Arc::new(ssh_config), socket, ssh_handler).await?;

        tokio::spawn(async move {
            let _ = session.await;
        });

        let channel = channel_receiver.await?;

        info!("accepted session creation");

        Ok(Connection::SshHost(channel.into_stream()))
    }

    /// Takes over a socket whose bootstrap prelude chose ssh, client side:
    /// the server's host key must hash to the fingerprint from the token.
    pub async fn ssh_client(
        socket: TcpStream,
        expected_fingerprint: [u8; 32],
        client_key_path: std::path::PathBuf,
    ) -> DynResult<Self> {
        let content = tokio::fs::read_to_string(&client_key_path)
            .await
            .map_err(|e| {
                format!(
                    "failed to read client key file {}: {}",
                    client_key_path.display(),
                    e
                )
            })?;
        let client_key = PrivateKey::from_openssh(&content)?;

        let ssh_config = client::Config::default();
        let ssh_handler = ClientFlow {
            expected_fingerprint,
        };

        info!("starting ssh on the bootstrapped socket");

        let mut session =
            client::connect_stream(Arc::new(ssh_config), socket, ssh_handler).await?;

        let key_with_hash = PrivateKeyWithHashAlg::new(Arc::new(client_key), None);
        let auth_result = session.authenticate_publickey("peer", key_with_hash).await?;

        if !auth_result.success() {
            return Err("failed to authenticate over ssh".into());
        }

        let channel = session.channel_open_session().await?;

        info!("ssh session established");

        Ok(Connection::SshClient(channel.into_stream()))
    }

    pub fn split(self) -> (ConnectionWriter, ConnectionReader) {
        match self {
            Connection::SshHost(stream) => {
                let (read_half, write_half) = tokio::io::split(stream);

                let conn_writer = ConnectionWriter::SshHost(FramedWrite::new(
                    write_half,
                    LengthDelimitedCodec::new(),
                ));

                let conn_reader = ConnectionReader::SshHost(FramedRead::new(
                    read_half,
                    LengthDelimitedCodec::new(),
                ));

                (conn_writer, conn_reader)
            }
            Connection::SshClient(stream) => {
                let (read_half, write_half) = tokio::io::split(stream);

                let conn_writer = ConnectionWriter::SshClient(FramedWrite::new(
                    write_half,
                    LengthDelimitedCodec::new(),
                ));

                let conn_reader = ConnectionReader::SshClient(FramedRead::new(
                    read_half,
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
            ConnectionWriter::SshHost(stream) => stream.close().await?,
            ConnectionWriter::SshClient(stream) => stream.close().await?,
        }

        Ok(())
    }
}

impl ConnectionReader {
    pub async fn next(&mut self) -> Option<DynResult<Message>> {
        match self {
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

struct ServerFlow {
    channel_sender: Option<oneshot::Sender<Channel<server::Msg>>>,
    authorized_keys: Vec<[u8; 32]>,
}

struct ClientFlow {
    expected_fingerprint: [u8; 32],
}

impl server::Handler for ServerFlow {
    type Error = DynError;

    async fn auth_none(&mut self, _user: &str) -> Result<russh::server::Auth, Self::Error> {
        Ok(russh::server::Auth::Reject {
            proceed_with_methods: Some(MethodSet::from(&[MethodKind::PublicKey][..])),
            partial_success: false,
        })
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
        let key_bytes = public_key.to_bytes().map_err(|e| e.to_string())?;
        let fingerprint = key_fingerprint(key_bytes.as_ref());

        if self.authorized_keys.contains(&fingerprint) {
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
        info!("accepting session creation");

        if let Some(channel_sender) = self.channel_sender.take() {
            let _ = channel_sender.send(channel);
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
        let fingerprint = key_fingerprint(server_public_key.to_bytes()?.as_ref());
        Ok(fingerprint == self.expected_fingerprint)
    }
}
