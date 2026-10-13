//! One connection from a surface to a node's operate listener: TCP to the
//! node's operate address, Xmip's mutual TLS agreeing `h2`, and HTTP/2
//! carrying one call after another, read through `net::watched` so the
//! surface ending reaches a read within [`WATCH`].

use std::sync::Arc;
use std::time::Duration;

use net::http2::Client;
use net::watched::Watched;
use serde_json::Value;

use crate::plane::call;
use crate::plane::listener::WATCH;

/// Whether the surface a line belongs to is ending.
pub(crate) type Ending = Box<dyn Fn() -> bool + Send>;

/// A connection.
pub(crate) struct Line {
    client: Client<Watched<tls::Guarded, Ending>>,
    authority: String,
}

impl Line {
    /// Connect to `address` — `host:port` — within `patience`, checking the
    /// node's certificate names `host` and reaches the anchors `config`
    /// holds, and presenting this side's; an answer is waited for at most
    /// `silence`, and not once `ending` says so.
    ///
    /// # Errors
    ///
    /// The connection, the handshake or the protocol it agreed, in words.
    pub(crate) fn open(
        address: &str,
        config: &Arc<tls::ClientConfig>,
        patience: Duration,
        silence: Duration,
        ending: Ending,
    ) -> Result<Self, String> {
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
        let mut watched = Watched::new(guarded, ending);
        watched.silence = Some(silence);
        let client = Client::handshake(watched, "https").map_err(|failed| failed.message)?;
        Ok(Self {
            client,
            authority: address.to_string(),
        })
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
