//! The plaintext prelude spoken on a fresh TCP connection, before the socket
//! upgrades in place to the negotiated protocol. It carries hints, never
//! secrets: nothing here is trusted until the chosen protocol has proven the
//! host's identity key against the out-of-band token.

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::info;

use crate::DynResult;

pub const PROTOCOL_VERSION: u32 = 1;

/// The host picks the first of these the client also supports. Hardcoded
/// until the CSP grows a configure method.
const HOST_PREFERENCE: [Protocol; 2] = [Protocol::Ssh, Protocol::Wss];

/// What this build's client offers in its hello. Same story as above.
const CLIENT_SUPPORTED: [Protocol; 2] = [Protocol::Ssh, Protocol::Wss];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Ssh,
    Wss,
}

impl Protocol {
    fn wire_name(&self) -> &'static str {
        match self {
            Protocol::Ssh => "ssh",
            Protocol::Wss => "wss",
        }
    }

    fn from_wire_name(name: &str) -> Option<Protocol> {
        match name {
            "ssh" => Some(Protocol::Ssh),
            "wss" => Some(Protocol::Wss),
            _ => None,
        }
    }

    /// A protocol can be negotiated before its upgrade path exists; the host
    /// refuses rather than switching to one it can't actually speak.
    fn implemented(&self) -> bool {
        matches!(self, Protocol::Ssh)
    }
}

/// client → host: opening frame of every connection
#[derive(Debug, Serialize, Deserialize)]
struct Hello {
    version: u32,
    protocols: Vec<String>,
}

/// host → client: the pick; the next byte on the wire belongs to this protocol
#[derive(Debug, Serialize, Deserialize)]
struct Switch {
    protocol: String,
}

/// host → client: no deal; the connection ends here
#[derive(Debug, Serialize, Deserialize)]
struct Refusal {
    error: String,
}

/// The two frames a client can get back. Untagged works because the field
/// sets are disjoint.
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum HostReply {
    Switch(Switch),
    Refusal(Refusal),
}

/// Host side of the prelude. On success the socket's very next bytes belong
/// to the returned protocol.
pub async fn negotiate_host<S>(stream: &mut S) -> DynResult<Protocol>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let hello: Hello = serde_json::from_slice(&read_frame(stream).await?)?;

    info!("bootstrap hello: {:?}", hello);

    if hello.version != PROTOCOL_VERSION {
        return refuse(
            stream,
            format!(
                "protocol version mismatch: host speaks {}, client speaks {}",
                PROTOCOL_VERSION, hello.version
            ),
        )
        .await;
    }

    let client_protocols: Vec<Protocol> = hello
        .protocols
        .iter()
        .filter_map(|name| Protocol::from_wire_name(name))
        .collect();

    let Some(protocol) = HOST_PREFERENCE
        .into_iter()
        .find(|preferred| client_protocols.contains(preferred))
    else {
        return refuse(
            stream,
            format!("no common protocol: client offered {:?}", hello.protocols),
        )
        .await;
    };

    if !protocol.implemented() {
        return refuse(
            stream,
            format!("{} transport not implemented yet", protocol.wire_name()),
        )
        .await;
    }

    write_frame(
        stream,
        &Switch {
            protocol: protocol.wire_name().to_string(),
        },
    )
    .await?;

    Ok(protocol)
}

/// Client side of the prelude. On success the socket's very next bytes belong
/// to the returned protocol.
pub async fn negotiate_client<S>(stream: &mut S) -> DynResult<Protocol>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    write_frame(
        stream,
        &Hello {
            version: PROTOCOL_VERSION,
            protocols: CLIENT_SUPPORTED
                .iter()
                .map(|protocol| protocol.wire_name().to_string())
                .collect(),
        },
    )
    .await?;

    match serde_json::from_slice(&read_frame(stream).await?)? {
        HostReply::Switch(switch) => {
            info!("bootstrap switch: {:?}", switch);

            Protocol::from_wire_name(&switch.protocol)
                .filter(|protocol| CLIENT_SUPPORTED.contains(protocol))
                .ok_or_else(|| {
                    format!("host switched to unsupported protocol: {}", switch.protocol).into()
                })
        }
        HostReply::Refusal(refusal) => Err(format!("host refused: {}", refusal.error).into()),
    }
}

async fn refuse<S>(stream: &mut S, error: String) -> DynResult<Protocol>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    write_frame(
        stream,
        &Refusal {
            error: error.clone(),
        },
    )
    .await?;

    Err(error.into())
}

// ─── byte-exact framing ──────────────────────────────────────────────────
// Same "content-length: N\r\n\r\n{json}" shape as the rpc module, but read
// and written byte-exact: no buffered reader (it would slurp the first bytes
// of the protocol that follows the prelude and they'd never reach it), and
// no trailing newline after the content (rpc::encode appends one that its
// length header doesn't count — harmless inside a framed transport, fatal
// on a socket about to be handed to SSH).

const MAX_HEADER_BYTES: usize = 1024;
const MAX_CONTENT_BYTES: usize = 64 * 1024;

async fn read_frame<S>(stream: &mut S) -> DynResult<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut headers = Vec::new();
    let mut byte = [0u8; 1];

    while !headers.ends_with(b"\r\n\r\n") {
        if headers.len() >= MAX_HEADER_BYTES {
            return Err("bootstrap frame headers too long".into());
        }

        stream.read_exact(&mut byte).await?;
        headers.push(byte[0]);
    }

    let headers = String::from_utf8(headers)?;

    let content_length = headers
        .lines()
        .find_map(|line| {
            line.to_lowercase()
                .strip_prefix("content-length:")
                .map(|value| value.trim().parse::<usize>())
        })
        .ok_or("bootstrap frame has no content-length header")??;

    if content_length > MAX_CONTENT_BYTES {
        return Err("bootstrap frame too large".into());
    }

    let mut content = vec![0; content_length];
    stream.read_exact(&mut content).await?;

    Ok(content)
}

async fn write_frame<S, T>(stream: &mut S, value: &T) -> DynResult<()>
where
    S: AsyncWrite + Unpin,
    T: Serialize,
{
    let content = serde_json::to_vec(value)?;
    let frame = [
        format!("content-length: {}\r\n\r\n", content.len()).into_bytes(),
        content,
    ]
    .concat();

    stream.write_all(&frame).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn both_sides_agree_on_ssh() {
        let (mut host_end, mut client_end) = tokio::io::duplex(4096);

        let host = tokio::spawn(async move { negotiate_host(&mut host_end).await });
        let picked = negotiate_client(&mut client_end).await.unwrap();

        assert_eq!(picked, Protocol::Ssh);
        assert_eq!(host.await.unwrap().unwrap(), Protocol::Ssh);
    }

    #[tokio::test]
    async fn the_prelude_consumes_exactly_its_own_bytes() {
        let (mut host_end, mut client_end) = tokio::io::duplex(4096);

        let host = tokio::spawn(async move {
            let protocol = negotiate_host(&mut host_end).await.unwrap();
            // the first post-prelude bytes the real protocol would send
            host_end.write_all(b"SSH-2.0-banner").await.unwrap();
            protocol
        });

        negotiate_client(&mut client_end).await.unwrap();

        // if the prelude over-read, part of this banner is gone
        let mut banner = [0u8; 14];
        client_end.read_exact(&mut banner).await.unwrap();
        assert_eq!(&banner, b"SSH-2.0-banner");

        host.await.unwrap();
    }

    #[tokio::test]
    async fn unknown_protocols_get_refused() {
        let (mut host_end, mut client_end) = tokio::io::duplex(4096);

        let host = tokio::spawn(async move { negotiate_host(&mut host_end).await });

        write_frame(
            &mut client_end,
            &Hello {
                version: PROTOCOL_VERSION,
                protocols: vec!["carrier-pigeon".to_string()],
            },
        )
        .await
        .unwrap();

        let reply: HostReply = serde_json::from_slice(&read_frame(&mut client_end).await.unwrap())
            .expect("host should answer with a frame");

        assert!(matches!(reply, HostReply::Refusal(_)));
        assert!(host.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn version_mismatch_gets_refused() {
        let (mut host_end, mut client_end) = tokio::io::duplex(4096);

        let host = tokio::spawn(async move { negotiate_host(&mut host_end).await });

        write_frame(
            &mut client_end,
            &Hello {
                version: PROTOCOL_VERSION + 1,
                protocols: vec!["ssh".to_string()],
            },
        )
        .await
        .unwrap();

        let reply: HostReply = serde_json::from_slice(&read_frame(&mut client_end).await.unwrap())
            .expect("host should answer with a frame");

        assert!(matches!(reply, HostReply::Refusal(_)));
        assert!(host.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn refusals_reach_the_client_as_errors() {
        let (mut host_end, mut client_end) = tokio::io::duplex(4096);

        let host = tokio::spawn(async move {
            // consume the hello, then refuse
            read_frame(&mut host_end).await.unwrap();
            write_frame(
                &mut host_end,
                &Refusal {
                    error: "not today".to_string(),
                },
            )
            .await
            .unwrap();
        });

        let result = negotiate_client(&mut client_end).await;

        assert!(result.unwrap_err().to_string().contains("not today"));
        host.await.unwrap();
    }
}
