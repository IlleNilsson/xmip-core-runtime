//! One connection from a surface to a node's operate listener: TCP to the
//! node's operate address with Xmip's mutual TLS agreeing `h2`, or the
//! node's local endpoint on this machine (`plane::local`) — and HTTP/2
//! carrying one call after another, read through `net::watched` so the
//! surface ending reaches a read within [`WATCH`], or, on a pipe, by the
//! read cancelled ([`Cancel`]).

use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use net::http2::Client;
use net::watched::Watched;
use serde_json::Value;

use crate::plane::call;
use crate::plane::listener::WATCH;
use crate::plane::local::{self, Cancel, Stream};

/// Whether the surface a line belongs to is ending.
pub(crate) type Ending = Box<dyn Fn() -> bool + Send>;

/// How a surface reaches its node.
pub(crate) enum Reach {
    /// `host:port`, inside mutual TLS by this configuration.
    Network {
        address: String,
        config: Arc<tls::ClientConfig>,
    },
    /// The node's local endpoint at this path.
    Local(PathBuf),
}

/// The connection under a line.
pub(crate) enum Link {
    Tls(Box<tls::Guarded>),
    Local(Stream),
}

impl Read for Link {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Tls(guarded) => guarded.read(buffer),
            Self::Local(stream) => stream.read(buffer),
        }
    }
}

impl Write for Link {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Tls(guarded) => guarded.write(bytes),
            Self::Local(stream) => stream.write(bytes),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Tls(guarded) => guarded.flush(),
            Self::Local(stream) => stream.flush(),
        }
    }
}

/// A connection.
pub(crate) struct Line {
    client: Client<Watched<Link, Ending>>,
    authority: String,
}

impl Line {
    /// Connect as `reach` says within `patience` — on the network checking
    /// the node's certificate names its host and reaches the anchors the
    /// configuration holds, and presenting this side's; an answer is
    /// waited for at most `silence` where the connection keeps time, and
    /// not once `ending` says so. What ends a read in flight, where a
    /// connection has no timeout to look between, comes with it.
    ///
    /// # Errors
    ///
    /// The connection, the handshake or the protocol it agreed, in words.
    pub(crate) fn open(
        reach: &Reach,
        patience: Duration,
        silence: Duration,
        ending: Ending,
    ) -> Result<(Self, Option<Cancel>), String> {
        let (link, authority, scheme, cancel) = match reach {
            Reach::Network { address, config } => (
                secured(address, config, patience)?,
                address.clone(),
                "https",
                None,
            ),
            Reach::Local(path) => {
                let stream = local::connect(path, patience)?;
                stream.watch(WATCH).map_err(|error| error.to_string())?;
                let cancel = stream.cancel();
                (
                    Link::Local(stream),
                    "localhost".to_string(),
                    "http",
                    Some(cancel),
                )
            }
        };
        let mut watched = Watched::new(link, ending);
        watched.silence = Some(silence);
        let client = Client::handshake(watched, scheme).map_err(|failed| failed.message)?;
        Ok((Self { client, authority }, cancel))
    }

    /// Call `method` with `message` and read what it answered.
    ///
    /// # Errors
    ///
    /// The connection broke, or the node refused the call, in words.
    pub(crate) fn call(&mut self, method: &str, message: &Value) -> Result<Value, String> {
        let request = call::request(&self.authority, method, message)?;
        // Silence is counted from the call, not from the last answer.
        self.client.io_mut().heard = std::time::Instant::now();
        let response = self
            .client
            .send(&request)
            .map_err(|failed| failed.message)?;
        call::answered(&response)
    }
}

/// TCP to `address` and Xmip's mutual TLS agreeing `h2`.
fn secured(
    address: &str,
    config: &Arc<tls::ClientConfig>,
    patience: Duration,
) -> Result<Link, String> {
    let host = host_of(address)?;
    let tcp = net::connect(address, Some(patience)).map_err(|failed| failed.message)?;
    tcp.set_nodelay(true)
        .and_then(|()| tcp.set_read_timeout(Some(patience)))
        .and_then(|()| tcp.set_write_timeout(Some(patience)))
        .map_err(|error| error.to_string())?;
    let mut guarded =
        tls::client_with(host, tcp, Arc::clone(config)).map_err(|failed| failed.message)?;
    let agreed = tls::alpn::agreed(&mut guarded).map_err(|failed| failed.message)?;
    if agreed.as_deref() != Some(b"h2") {
        return Err(format!("{address} did not agree h2: no operate listener"));
    }
    guarded
        .sock
        .set_read_timeout(Some(WATCH))
        .map_err(|error| error.to_string())?;
    Ok(Link::Tls(Box::new(guarded)))
}

/// The host of an operate address, `host:port` or `[v6]:port`.
///
/// # Errors
///
/// An address with no port.
pub fn host_of(address: &str) -> Result<&str, String> {
    let (host, port) = address
        .rsplit_once(':')
        .ok_or_else(|| format!("{address} is no operate address; it is host:port"))?;
    if host.is_empty() || host.contains('/') || port.parse::<u16>().is_err() {
        return Err(format!("{address} is no operate address; it is host:port"));
    }
    Ok(host.trim_start_matches('[').trim_end_matches(']'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_operate_address_is_a_host_and_a_port() {
        assert_eq!(host_of("node1:7401"), Ok("node1"));
        assert_eq!(host_of("[::1]:7401"), Ok("::1"));
        assert!(host_of("node1").is_err());
        assert!(host_of("https://node1").is_err());
        assert!(host_of("http://node1:5087").is_err());
        assert!(host_of(":7401").is_err());
    }
}
