//! A node's operate listener (ADR-0067): the plane an operator surface
//! reaches the node through — over gRPC on TCP inside Xmip's mutual TLS
//! from another machine (ADR-0014, amendment 2026-10-12; ADR-0063), and
//! over gRPC on the node's local endpoint from its own (ADR-0014,
//! amendment 2026-10-13; ADR-0052, amendment 2026-10-05: *gRPC over net
//! pipe* between processes on one machine).
//!
//! On TCP every connection presents a certificate reaching the anchors the
//! listener was given, and agrees `h2` by ALPN; the certificate's subject
//! is who acts, and a connection over loopback is no exception. On the
//! local endpoint the operating system admits only the node's account, the
//! machine's administrators and whom `[operate] admit` names, and proves
//! who connected ([`local`](crate::plane::local)). Either way who acts is what
//! the connection proved, never a name the caller says. A connection is
//! one thread, no async runtime: requests are answered in turn, so a
//! surface following the node holds a connection of its own for its wait;
//! a thread that answered one is kept for the next (`plane::workers`).
//! How many it answers at once, how many may be in their handshake and how
//! long a handshake may take are its [`Limits`] (`plane::limits`).
//! A stop wakes every wait, and ends every connection reading.

use std::collections::BTreeMap;
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use xcore::lock::Locked;

use xaudit::program_audit::ProgramAudit;
use xcore::{ExecutionPhase, Severity};

use crate::plane::board::Published;
use crate::plane::grant::Grants;
use crate::plane::limits::{Backoff, Handshaking, Limits};
use crate::plane::local::{self, Acceptor, Cancel};
use crate::plane::served::{answer, answer_local, noted};
use crate::plane::vouched::Relaying;
use crate::plane::workers::Workers;

/// How long a stop waits on its own wake-up connection, and on a
/// connection to end.
const WAKE: Duration = Duration::from_secs(1);

/// What every connection shares.
pub(crate) struct Serve {
    pub(crate) published: Arc<dyn Published>,
    /// The TLS a network connection is answered inside; none on the local
    /// endpoint.
    pub(crate) config: Option<Arc<tls::ServerConfig>>,
    /// Which role each proven caller holds (`plane::grant`).
    pub(crate) grants: Grants,
    /// Who may relay for a caller and what its certificate must reach
    /// (`[operate] relay`, `plane::vouched`); none until set, so a call
    /// before is relayed for no one.
    pub(crate) relaying: OnceLock<Arc<Relaying>>,
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

/// A connection being answered, whether it has ended, and what ends a read
/// it waits in.
struct Connection {
    done: Arc<AtomicBool>,
    cancel: Option<Cancel>,
}

/// The connections being answered, the threads answering them, what bounds
/// them, the handshakes in progress, and whether a connection past a bound
/// was told to the audit since one was last taken.
#[derive(Default)]
struct Served {
    connections: Mutex<Vec<Connection>>,
    workers: Arc<Workers>,
    limits: Mutex<Limits>,
    handshaking: Arc<AtomicUsize>,
    refusing: AtomicBool,
}

impl Served {
    /// Whether `most` connections are being answered already.
    fn full(&self, most: usize) -> bool {
        let mut connections = self.connections.locked();
        connections.retain(|connection| !connection.done.load(Ordering::SeqCst));
        connections.len() >= most
    }

    /// A connection from `peer` closed for going past `most` of `bound`,
    /// told to the audit where it is the first since one was taken.
    fn refused(&self, serve: &Serve, peer: &str, (most, bound): (usize, &str)) {
        if !self.refusing.swap(true, Ordering::SeqCst) {
            let said = format!(
                "refused: the listener takes {most} {bound} at once ([tuning] operate_{bound}); \
                 every connection past them is closed until one ends"
            );
            noted(serve, peer, &said);
        }
    }
}

type Connections = Arc<Served>;

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
    /// anchors, each caller holding the role `grants` lists it with and
    /// none where it lists it not; every act, taken or refused, recorded
    /// in `audit`. Bounded by the default [`Limits`] until
    /// [`Listener::limit`] sets others.
    ///
    /// # Errors
    ///
    /// Where the identity does not make a server, or the listener has no
    /// address or thread.
    pub fn start(
        listener: TcpListener,
        identity: &tls::Identity,
        published: Arc<dyn Published>,
        grants: Grants,
        audit: &ProgramAudit,
    ) -> Result<Self, String> {
        let server = identity.server().map_err(|failed| failed.message)?;
        let config = Arc::new(tls::alpn::selecting(server, &[b"h2"]));
        let address = listener.local_addr().map_err(|error| error.to_string())?;
        let serve = serving(Some(config), published, grants, audit);
        Self::begin(Place::Network(address), serve, move |serve, served| {
            accept(&listener, serve, served);
        })
    }

    /// Serve the same on the node's local endpoint called `endpoint` — a
    /// named pipe on Windows, a Unix domain socket elsewhere — to every
    /// surface on this machine the operating system lets open it: the
    /// node's account, the machine's administrators and whom `admitting`
    /// names (`[operate] admit`, and on Unix the socket's `[operate]
    /// group`), each caller the account its process runs as, holding the
    /// role `grants` lists that account with. Plain HTTP/2 inside the
    /// machine, said in `audit` where it is made (ADR-0063 clause 1).
    ///
    /// # Errors
    ///
    /// A name that would leave the endpoints' folder
    /// ([`local::place`]), an admitted name or a group the system does not
    /// know, an endpoint that cannot be made, or no thread.
    pub fn local(
        endpoint: &str,
        admitting: local::Admitting<'_>,
        published: Arc<dyn Published>,
        grants: Grants,
        audit: &ProgramAudit,
    ) -> Result<Self, String> {
        let path = local::place(endpoint)?;
        let acceptor = Acceptor::bind(&path, admitting)?;
        let where_ = path.display().to_string();
        let _ = audit.record(
            "operate.local",
            ExecutionPhase::Begin,
            Severity::Information,
            Some("the local operate endpoint carries gRPC without TLS; the system proves who"),
            BTreeMap::from([("endpoint".to_string(), where_)]),
        );
        let serve = serving(None, published, grants, audit);
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

    /// Relay for a caller `relaying` says (`[operate] relay`): its accounts
    /// may vouch for a caller's certificate and act for that caller, by the
    /// caller's own role (`plane::vouched`). Set once, as the node starts;
    /// until then no one is relayed.
    pub fn relay(&self, relaying: Arc<Relaying>) {
        let _ = self.serve.relaying.set(relaying);
    }

    /// Bound it by `limits` from the next connection on (`[tuning]
    /// operate_connections`, `operate_handshakes`, `operate_handshake`).
    pub fn limit(&self, limits: Limits) {
        *self.served.limits.locked() = limits;
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
        // Knocked until it has heard (`net::accepting`).
        if let Some(accepting) = self.accepting.take() {
            let _ = net::accepting::woken(accepting, WAKE, || match &self.place {
                Place::Network(address) => net::accepting::knock(*address, WAKE),
                Place::Local(path) => local::wake(path),
            });
        }
        let connections = std::mem::take(&mut *self.served.connections.locked());
        for connection in &connections {
            ended(connection);
        }
        self.served.workers.stop(WAKE);
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
    grants: Grants,
    audit: &ProgramAudit,
) -> Arc<Serve> {
    Arc::new(Serve {
        published,
        config,
        grants,
        audit: audit.clone(),
        relaying: OnceLock::new(),
        stopping: AtomicBool::new(false),
    })
}

/// A connection ended: a read it waits in cancelled until it has ended — a
/// pipe has no timeout to look between — waiting at most [`WAKE`]; one
/// that has not by then is left to end alone.
fn ended(connection: &Connection) {
    let until = Instant::now() + WAKE;
    while !connection.done.load(Ordering::SeqCst) && Instant::now() < until {
        if let Some(cancel) = &connection.cancel {
            cancel.cancel();
        }
        std::thread::sleep(Duration::from_micros(200));
    }
}

/// Each connection accepted answered, within the listener's [`Limits`]: one
/// past them closed as it is accepted, the handshake of one taken bounded in
/// all.
fn accept(listener: &TcpListener, serve: &Arc<Serve>, served: &Connections) {
    let mut backoff = Backoff::default();
    loop {
        // bounded: a listener waits as long as its node runs; a stop wakes it
        let accepted = listener.accept();
        if serve.stopped() {
            return;
        }
        let Ok((connection, peer)) = accepted else {
            backoff.failed();
            continue;
        };
        backoff.succeeded();
        let limits = *served.limits.locked();
        if served.full(limits.connections) {
            served.refused(
                serve,
                &peer.to_string(),
                (limits.connections, "connections"),
            );
            continue;
        }
        let Some(handshaking) = Handshaking::begun(&served.handshaking, limits.handshakes) else {
            served.refused(serve, &peer.to_string(), (limits.handshakes, "handshakes"));
            continue;
        };
        let bound = (limits.handshake_within, handshaking);
        let serve = Arc::clone(serve);
        answered(served, None, move || {
            answer(connection, peer, &serve, bound)
        });
    }
}

fn accept_local(acceptor: &Acceptor, serve: &Arc<Serve>, served: &Connections) {
    let mut backoff = Backoff::default();
    loop {
        let accepted = acceptor.accept();
        if serve.stopped() {
            return;
        }
        let Ok(stream) = accepted else {
            backoff.failed();
            continue;
        };
        backoff.succeeded();
        let most = served.limits.locked().connections;
        if served.full(most) {
            served.refused(serve, "the local endpoint", (most, "connections"));
            continue;
        }
        let cancel = stream.cancel();
        let serve = Arc::clone(serve);
        answered(served, Some(cancel), move || answer_local(stream, &serve));
    }
}

/// `work` answered on one of the listener's threads (`plane::workers`),
/// and kept among its connections until it has ended.
fn answered(served: &Connections, cancel: Option<Cancel>, work: impl FnOnce() + Send + 'static) {
    let done = Arc::new(AtomicBool::new(false));
    let ending = Arc::clone(&done);
    let mut connections = served.connections.locked();
    connections.retain(|connection| !connection.done.load(Ordering::SeqCst));
    let running = served.workers.run(Box::new(move || {
        work();
        ending.store(true, Ordering::SeqCst);
    }));
    if running {
        connections.push(Connection { done, cancel });
        served.refusing.store(false, Ordering::SeqCst);
    }
}
