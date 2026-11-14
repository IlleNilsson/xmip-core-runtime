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

mod accepting;

use std::collections::BTreeMap;
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread::JoinHandle;
use std::time::Duration;
use xcore::lock::Locked;

use xaudit::program_audit::ProgramAudit;
use xcore::{ExecutionPhase, Severity};

use crate::act_watch::Door;
use crate::plane::board::Published;
use crate::plane::grant::Grants;
use crate::plane::limits::Limits;
use crate::plane::local::{self, Acceptor};
use crate::plane::vouched::Relaying;
use accepting::{Connections, accept, accept_local, ended};

/// How long a stop waits on its own wake-up connection, and on a
/// connection to end.
const WAKE: Duration = Duration::from_secs(1);

/// What every connection shares.
pub(crate) struct Serve {
    pub(crate) published: Arc<dyn Published>,
    /// The cluster's publication a monitoring node gathers, `Cluster` and
    /// `ClusterWait` answered from (`plane::served::read`); none for a node
    /// that gathers none, which refuses both naming the role.
    pub(crate) gathered: OnceLock<Arc<dyn Published>>,
    /// The TLS a network connection is answered inside; none on the local
    /// endpoint.
    pub(crate) config: Option<Arc<tls::ServerConfig>>,
    /// Which role each proven caller holds (`plane::grant`).
    pub(crate) grants: Grants,
    /// Who may relay for a caller and what its certificate must reach
    /// (`[operate] relay`, `plane::vouched`); none until set, so a call
    /// before is relayed for no one.
    pub(crate) relaying: OnceLock<Arc<Relaying>>,
    /// The node's door its acts are asked through (`act_watch::Door`); none
    /// until set, the door of no node.
    pub(crate) door: OnceLock<Arc<Door>>,
    pub(crate) audit: ProgramAudit,
    pub(crate) stopping: AtomicBool,
}

impl Serve {
    pub(crate) fn stopped(&self) -> bool {
        self.stopping.load(Ordering::SeqCst)
    }

    /// The door its acts are asked through: the node's, else the door of
    /// no node.
    pub(crate) fn door(&self) -> &Door {
        static NO_DOOR: Door = Door::none();
        self.door.get().map_or(&NO_DOOR, AsRef::as_ref)
    }
}

/// Where a listener listens.
enum Place {
    Network(SocketAddr),
    Local(PathBuf),
}

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

    /// Answer `Cluster` and `ClusterWait` from `gathered`, the cluster's
    /// publication this node gathers: handed a node whose roles include
    /// monitoring (`node::Capability::gathers`), and a program hosting a
    /// listener through the C ABI as it posts the first it gathered
    /// (`xmip_operate_post_cluster_v1`). Set once; until then both are
    /// refused in words naming the role (ADR-0027 decision 8, amendment
    /// 2026-11-13).
    pub fn gathers(&self, gathered: Arc<dyn Published>) {
        let _ = self.serve.gathered.set(gathered);
    }

    /// Ask every act it admits through `door`, the node's (`act_watch`).
    /// Set once, as the node starts; until then an act is asked through the
    /// door of no node.
    pub fn door(&self, door: Arc<Door>) {
        let _ = self.serve.door.set(door);
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
        if let Some(gathered) = self.serve.gathered.get() {
            gathered.wake();
        }
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
        gathered: OnceLock::new(),
        config,
        grants,
        audit: audit.clone(),
        relaying: OnceLock::new(),
        door: OnceLock::new(),
        stopping: AtomicBool::new(false),
    })
}
