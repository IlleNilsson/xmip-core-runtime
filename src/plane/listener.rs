//! A node's operate listener (ADR-0067): the plane an operator surface
//! reaches the node through — over gRPC on TCP inside Xmip's mutual TLS
//! from another machine (ADR-0014, amendment 2026-10-12; ADR-0063), and
//! over gRPC on the node's local endpoint from its own (ADR-0014,
//! amendment 2026-10-13; ADR-0052, amendment 2026-10-05: *gRPC over net
//! pipe* between processes on one machine).
//!
//! On TCP every connection presents a certificate reaching the anchors the
//! listener was given, and agrees `h2` by ALPN; the certificate's subject
//! is who acts. On the local endpoint the operating system admits only the
//! node's account and the machine's administrators and proves who
//! connected ([`local`](crate::plane::local)). Either way who acts is what
//! the connection proved, never a name the caller says. A connection is
//! one thread, no async runtime: requests are answered in turn, so a
//! surface following the node holds a connection of its own for its wait.
//! A stop wakes every wait, and ends every connection reading.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use xaudit::program_audit::ProgramAudit;
use xcore::{ExecutionPhase, Severity};

use crate::plane::board::Published;
use crate::plane::local::{self, Acceptor, Cancel};
use crate::plane::role::Role;
use crate::plane::served::{answer, answer_local};

/// How long a stop waits on its own wake-up connection, and on a
/// connection to end.
const WAKE: Duration = Duration::from_secs(1);

/// How often a connection waiting on its surface looks whether the
/// listener stops. An arriving byte wakes it at once; this bounds only how
/// long a stop waits for an idle connection.
pub(crate) const WATCH: Duration = Duration::from_millis(50);

/// What every connection shares.
pub(crate) struct Serve {
    pub(crate) published: Arc<dyn Published>,
    /// The TLS a network connection is answered inside; none on the local
    /// endpoint.
    pub(crate) config: Option<Arc<tls::ServerConfig>>,
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

/// Where a listener listens.
enum Place {
    Network(SocketAddr),
    Local(PathBuf),
}

/// A connection being answered, and what ends a read it waits in.
struct Connection {
    thread: JoinHandle<()>,
    cancel: Option<Cancel>,
}

type Connections = Arc<Mutex<Vec<Connection>>>;

/// An operate listener, serving until it is stopped or dropped.
pub struct Listener {
    place: Place,
    serve: Arc<Serve>,
    accepting: Option<JoinHandle<()>>,
    served: Connections,
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
        let config = Arc::new(tls::alpn::selecting(server, &[b"h2"]));
        let address = listener.local_addr().map_err(|error| error.to_string())?;
        let serve = serving(Some(config), published, stated, audit);
        Self::begin(Place::Network(address), serve, move |serve, served| {
            accept(&listener, serve, served);
        })
    }

    /// Serve the same on the node's local endpoint called `endpoint` — a
    /// named pipe on Windows, a Unix domain socket elsewhere — to every
    /// surface on this machine the operating system lets open it, each
    /// caller the user its process runs as. Plain HTTP/2 inside the
    /// machine, said in `audit` where it is made (ADR-0063 clause 1).
    ///
    /// # Errors
    ///
    /// A name that would leave the endpoints' folder
    /// ([`local::place`]), an endpoint that cannot be made, or no thread.
    pub fn local(
        endpoint: &str,
        published: Arc<dyn Published>,
        stated: Option<Role>,
        audit: &ProgramAudit,
    ) -> Result<Self, String> {
        let path = local::place(endpoint)?;
        let acceptor = Acceptor::bind(&path)?;
        let where_ = path.display().to_string();
        let _ = audit.record(
            "operate.local",
            ExecutionPhase::Begin,
            Severity::Information,
            Some("the local operate endpoint carries gRPC without TLS; the system proves who"),
            BTreeMap::from([("endpoint".to_string(), where_)]),
        );
        let serve = serving(None, published, stated, audit);
        Self::begin(Place::Local(path), serve, move |serve, served| {
            accept_local(&acceptor, serve, served);
        })
    }

    fn begin(
        place: Place,
        serve: Arc<Serve>,
        accepting: impl FnOnce(&Arc<Serve>, &Connections) + Send + 'static,
    ) -> Result<Self, String> {
        let served: Connections = Arc::default();
        let thread = {
            let (serve, served) = (Arc::clone(&serve), Arc::clone(&served));
            std::thread::Builder::new()
                .name("xmip-operate-accept".to_string())
                .spawn(move || accepting(&serve, &served))
                .map_err(|error| error.to_string())?
        };
        Ok(Self {
            place,
            serve,
            accepting: Some(thread),
            served,
        })
    }

    /// Where it listens: `host:port`, or the local endpoint's path.
    #[must_use]
    pub fn address(&self) -> String {
        match &self.place {
            Place::Network(address) => address.to_string(),
            Place::Local(path) => path.display().to_string(),
        }
    }

    /// Stop: nothing accepted after, every wait woken, every connection
    /// ended and every thread finished.
    pub fn stop(&mut self) {
        if self.serve.stopping.swap(true, Ordering::SeqCst) {
            return;
        }
        self.serve.published.wake();
        match &self.place {
            Place::Network(address) => drop(net::connect(wakeable(*address), Some(WAKE))),
            Place::Local(path) => local::wake(path),
        }
        if let Some(accepting) = self.accepting.take() {
            let _ = accepting.join();
        }
        let served =
            std::mem::take(&mut *self.served.lock().unwrap_or_else(PoisonError::into_inner));
        for connection in served {
            ended(connection);
        }
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.stop();
    }
}

fn serving(
    config: Option<Arc<tls::ServerConfig>>,
    published: Arc<dyn Published>,
    stated: Option<Role>,
    audit: &ProgramAudit,
) -> Arc<Serve> {
    Arc::new(Serve {
        published,
        config,
        stated,
        audit: audit.clone(),
        stopping: AtomicBool::new(false),
    })
}

/// A connection ended: a read it waits in cancelled until its thread
/// finishes — a pipe has no timeout to look between — and the thread
/// joined. One that does not finish within [`WAKE`] is left to end alone.
fn ended(connection: Connection) {
    if let Some(cancel) = &connection.cancel {
        let until = Instant::now() + WAKE;
        while !connection.thread.is_finished() && Instant::now() < until {
            cancel.cancel();
            std::thread::sleep(Duration::from_micros(200));
        }
    }
    if connection.thread.is_finished() || connection.cancel.is_none() {
        let _ = connection.thread.join();
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

fn accept(listener: &TcpListener, serve: &Arc<Serve>, served: &Connections) {
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
        spawned(served, None, move || answer(connection, peer, &serve));
    }
}

fn accept_local(acceptor: &Acceptor, serve: &Arc<Serve>, served: &Connections) {
    loop {
        let accepted = acceptor.accept();
        if serve.stopped() {
            return;
        }
        let Ok(stream) = accepted else {
            continue;
        };
        let cancel = stream.cancel();
        let serve = Arc::clone(serve);
        spawned(served, Some(cancel), move || answer_local(stream, &serve));
    }
}

fn spawned(served: &Connections, cancel: Option<Cancel>, work: impl FnOnce() + Send + 'static) {
    let Ok(thread) = std::thread::Builder::new()
        .name("xmip-operate-connection".to_string())
        .spawn(work)
    else {
        return;
    };
    let mut served = served.lock().unwrap_or_else(PoisonError::into_inner);
    served.retain(|connection| !connection.thread.is_finished());
    served.push(Connection { thread, cancel });
}
