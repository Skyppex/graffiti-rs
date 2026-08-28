//! The host's identity: one Ed25519 key generated at startup. Only a host
//! session generates one; the out-of-band token pins it, and every transport
//! must prove possession of it. Identity is an input to transports, never a
//! side effect of them.

use std::net::{IpAddr, Ipv4Addr};

use base64::Engine;
use russh::keys::{Algorithm, PrivateKey};
use sha2::{Digest, Sha256};

use crate::DynResult;

/// The one port a host listens on. Every connection starts with the plaintext
/// bootstrap prelude here and upgrades in place to the negotiated protocol.
pub const BOOTSTRAP_PORT: u16 = 32700;

#[derive(Clone)]
pub struct Identity {
    pub key: PrivateKey,
}

impl Identity {
    pub fn generate() -> DynResult<Self> {
        Ok(Identity {
            key: PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)?,
        })
    }

    pub fn fingerprint(&self) -> DynResult<[u8; 32]> {
        Ok(key_fingerprint(self.key.public_key().to_bytes()?.as_ref()))
    }

    /// The token the host user hands out of band:
    /// base64( fingerprint ++ "ip:port" ), where ip:port is the bootstrap
    /// endpoint. No scheme — the protocol is negotiated there, not encoded here.
    pub fn token(&self, bootstrap_addr: &str) -> DynResult<String> {
        let bytes = [self.fingerprint()?.as_slice(), bootstrap_addr.as_bytes()].concat();
        Ok(base64::prelude::BASE64_STANDARD.encode(bytes))
    }
}

/// The address peers can reach a host on, from the host's point of view.
pub async fn bootstrap_addr() -> String {
    format!("{}:{}", resolve_public_ip().await, BOOTSTRAP_PORT)
}

/// The other half of Identity::token: what the client recovers from what the
/// host user handed over.
pub fn parse_token(token: &str) -> DynResult<([u8; 32], String)> {
    let decoded = base64::prelude::BASE64_STANDARD.decode(token.trim())?;

    if decoded.len() <= 32 {
        return Err("token too short to hold a fingerprint and an address".into());
    }

    let (fingerprint, addr) = decoded.split_at(32);

    Ok((
        fingerprint.try_into().expect("split_at(32) yields 32 bytes"),
        String::from_utf8(addr.to_vec())?,
    ))
}

/// sha256 of a public key's bytes: the one fingerprint definition used for
/// the token, authorized_keys matching, and host key verification.
pub fn key_fingerprint(key_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(key_bytes);
    hasher.finalize().into()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_roundtrips() {
        let identity = Identity::generate().unwrap();

        let token = identity.token("203.0.113.7:32700").unwrap();
        let (fingerprint, addr) = parse_token(&token).unwrap();

        assert_eq!(fingerprint, identity.fingerprint().unwrap());
        assert_eq!(addr, "203.0.113.7:32700");
    }

    #[test]
    fn garbage_tokens_are_rejected() {
        assert!(parse_token("not base64!!!").is_err());
        assert!(parse_token("c2hvcnQ=").is_err()); // valid base64, too short
    }
}