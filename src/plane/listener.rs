//! A node's operate listener (ADR-0067): the plane an operator surface on
//! another machine reaches the node through, over gRPC on TCP inside
//! Xmip's mutual TLS (ADR-0014, amendment 2026-10-12; ADR-0052, amendment
//! 2026-10-05; ADR-0063).
//!
//! Every connection presents a certificate reaching the anchors the
//! listener was given, and agrees `h2` by ALPN; the certificate's subject
//! is who acts, never a name the caller says. A connection is one thread,
//! no async runtime: requests are answered in turn, so a surface following
//! the node holds a connection of its own for its wait. A stop wakes every
//! wait, and every connection reading sees it within [`WATCH`]
//! (`net::watched`).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;

use xaudit::program_audit::ProgramAudit;

use crate::plane::board::Published;
use crate::plane::role::Role;
use crate::plane::served::answer;

/// How long a stop waits on its own wake-up connection.
const WAKE: Duration = Duration::from_secs(1);

/// How often a connection waiting on its surface looks whether the
/// listener stops. An arriving byte wakes it at once; this bounds only how
/// long a stop waits for an idle connection.
pub(crate) const WATCH: Duration = Duration::from_millis(50);

/// What every connection shares.
pub(crate) struct Serve {
    pub(crate) published: Arc<dyn Published>,
    pub(crate) config: Arc<tls::ServerConfig>,
    /// The role the node's configuration states for every proven caller.
    pub(crate) stated: Option<Role>,
    pub(crate) audit: ProgramAudit,
    pub(crate) stopping: AtomicBool,
}

impl Serve {
    pub(crate) fn stopped(&self) -> bool {
        self.stopping.load(Ordering::SeqCst)
    }
}

/// An operate listener, serving until it is stopped or dropped.
pub struct Listener {
    address: SocketAddr,
    serve: Arc<Serve>,
    accepting: Option<JoinHandle<()>>,
    served: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl Listener {
    /// Serve what `published` holds, and the acts on it, to every surface
    /// connecting to `listener` with a certificate reaching `identity`'s
    /// anchors, each caller holding the role `stated` grants a proven
    /// caller (Observer where it states none); every act, taken or
    /// refused, recorded in `audit`.
    ///
    /// # Errors
    ///
    /// Where the identity does not make a server, or the listener has no
    /// address or thread.
    pub fn start(
        listener: TcpListener,
        identity: &tls::Identity,
        published: Arc<dyn Published>,
        stated: Option<Role>,
        audit: &ProgramAudit,
    ) -> Result<Self, String> {
        let server = identity.server().map_err(|failed| failed.message)?;
        let config = tls::alpn::selecting(server, &[b"h2"]);
        let address = listener.local_addr().map_err(|error| error.to_string())?;
        let serve = Arc::new(Serve {
            published,
            config: Arc::new(config),
            stated,
            audit: audit.clone(),
            stopping: AtomicBool::new(false),
        });
        let served: Arc<Mutex<Vec<JoinHandle<()>>>> = Arc::default();
        let accepting = {
            let (serve, served) = (Arc::clone(&serve), Arc::clone(&served));
            std::thread::Builder::new()
                .name("xmip-operate-accept".to_string())
                .spawn(move || accept(&listener, &serve, &served))
                .map_err(|error| error.to_string())?
        };
        Ok(Self {
            address,
            serve,
            accepting: Some(accepting),
            served,
        })
    }

    /// Where it listens.
    #[must_use]
    pub const fn address(&self) -> SocketAddr {
        self.address
    }

    /// Stop: nothing accepted after, every wait woken, every connection
    /// ended and every thread finished.
    pub fn stop(&mut self) {
        if self.serve.stopping.swap(true, Ordering::SeqCst) {
            return;
        }
        self.serve.published.wake();
        let _ = net::connect(wakeable(self.address), Some(WAKE));
        if let Some(accepting) = self.accepting.take() {
            let _ = accepting.join();
        }
        let served =
            std::mem::take(&mut *self.served.lock().unwrap_or_else(PoisonError::into_inner));
        for thread in served {
            let _ = thread.join();
        }
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.stop();
    }
}

/// An address a connection reaches the listener at: loopback where it
/// listens on every address.
fn wakeable(address: SocketAddr) -> SocketAddr {
    match address.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => (Ipv4Addr::LOCALHOST, address.port()).into(),
        IpAddr::V6(ip) if ip.is_unspecified() => (Ipv6Addr::LOCALHOST, address.port()).into(),
        _ => address,
    }
}

fn accept(listener: &TcpListener, serve: &Arc<Serve>, served: &Arc<Mutex<Vec<JoinHandle<()>>>>) {
    loop {
        // bounded: a listener waits as long as its node runs; a stop wakes it
        let accepted = listener.accept();
        if serve.stopped() {
            return;
        }
        let Ok((connection, peer)) = accepted else {
            continue;
        };
        let serve = Arc::clone(serve);
        let Ok(thread) = std::thread::Builder::new()
            .name("xmip-operate-connection".to_string())
            .spawn(move || answer(connection, peer, &serve))
        else {
            continue;
        };
        let mut served = served.lock().unwrap_or_else(PoisonError::into_inner);
        served.retain(|thread| !thread.is_finished());
        served.push(thread);
    }
}
