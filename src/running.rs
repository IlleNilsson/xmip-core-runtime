//! A node running: ADR-0018's nine startup phases over its configuration and
//! the technologies its program linked, the message path on every Receive
//! Location it starts, and a stop that drains.
//!
//! ```text
//! 1 read-configuration     the node's document and the Applications it binds
//! 2 build-execution-tree   what this node starts, bound
//! 3 validate-startup       every Location held to its technology's declaration;
//!                          every technology, accepted mechanism and filter name
//!                          one this node was built with — refused here, not at
//!                          the first Message
//! 4 plan-host-services     the Host Services the started Modules need
//! 5 start-host-services    this process is the in-process one
//! 6 load-modules           each technology used loaded once, its declaration
//!                          carried into the catalogue; each library opened once
//! 7 register-capabilities  each capability once, by the Module serving it
//! 8 verify-extensions      the execution tree's, verified and not loaded
//! 9 accept-work            each Location's transport built once; Xmip Storage
//!                          reached; the Runtime built once; every Receive
//!                          Location serving; the send step dispatching, its
//!                          queues read first for what the Ledger left
//! ```
//!
//! Phase 3 also holds how the node reaches Xmip Storage to what its program
//! linked, and phase 9 reaches it (`crate::storage`): every Stream a
//! Receive Location takes in is written to the Ledger through it.

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread::JoinHandle;

use configure::{ConfiguredLocation, Declarations};
use xaudit::origin::Origin;
use xaudit::program_audit::ProgramAudit;

use crate::budget::NodeBudget;
use crate::capability_registry::CapabilityRegistry;
use crate::configured_subscription::ConfiguredSubscription;
use crate::execution_tree::build_execution_tree;
use crate::host::{self, HostService};
use crate::linked::Linked;
use crate::outcome::{Outcomes, Tally};
use crate::pickup::Pickup;
use crate::recognized::Recognized;
use crate::send_step::SendStep;
use crate::service::StartupPhase;
use crate::start::read;
use crate::startup::{Checked, check, load, open, start_host_services};
use crate::stopping::Stopping;
use crate::storage::Reached;
use crate::work_step::WorkStep;

#[cfg(test)]
mod accepted;
mod certificate_standing;
mod operate;
pub mod publication;
mod serving;

use serving::{Served, serve};

/// Why a node did not start: the phase that refused it, and every problem it
/// found there, one sentence each (ADR-0055: refused at the door, in words).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub phase: StartupPhase,
    pub problems: Vec<String>,
}

impl Refusal {
    pub(crate) const fn at(phase: StartupPhase, problems: Vec<String>) -> Self {
        Self { phase, problems }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "refused at {}: {}", self.phase, self.problems.join("; "))
    }
}

/// A node, started and serving until [`Running::stop`], or until it is
/// dropped.
pub struct Running {
    cluster: String,
    node: String,
    /// Whether its configuration says it may reach the internet (ADR-0045).
    online: bool,
    capabilities: CapabilityRegistry,
    host_services: Vec<HostService>,
    locations: Vec<(&'static str, ConfiguredLocation)>,
    /// Each Location it knows and did not start, by stage and name.
    not_started: Vec<(&'static str, String)>,
    stopping: Arc<Stopping>,
    serving: Option<JoinHandle<()>>,
    tally: Arc<Tally>,
    pickup: Arc<Pickup>,
    send: Arc<SendStep>,
    data: PathBuf,
    storage: Reached,
    /// `[operate]`, and the file it was read from ([`Running::operate`]).
    operate: Option<configure::OperateConfiguration>,
    /// When each certificate it presents is due for renewal (ADR-0034,
    /// amendment 2026-10-22).
    certificates: certificate_standing::CertificateStanding,
    /// `[tuning] local_timeout`: how long a surface's local call waits.
    local_timeout: std::time::Duration,
    configuration: PathBuf,
    #[cfg(feature = "dynamic-loading")]
    libraries: Option<crate::library::Libraries>,
}

impl Running {
    /// Start the node configured at `path`, with the technologies `linked`.
    ///
    /// Everything that can refuse does so before anything serves: a
    /// configuration that names what the program was not built with, a
    /// Location its technology's declaration refuses, a filter that does not
    /// compile, a Module that will not load. What serves then carries every
    /// Stream through arrival, routing and departure.
    ///
    /// # Errors
    /// The phase that refused the node, and every problem it found there.
    pub fn start(path: &str, mut linked: Linked) -> Result<Self, Refusal> {
        let (document, applications, files) = read(path)
            .map_err(|unread| Refusal::at(StartupPhase::ReadConfiguration, vec![unread.reason]))?;
        let data = document.service.data_directory(Path::new(path));
        let base = Path::new(path).parent().unwrap_or_else(|| Path::new("."));
        let certificates = certificate_standing::CertificateStanding::configured(&document, base);
        let operate = document.operate.clone();
        let reaching = crate::storage::plan(&document, path, &linked)?;
        let guard = crate::receive_certificate::guard(&document, Path::new(path))
            .map_err(|problems| Refusal::at(StartupPhase::ValidateStartup, problems))?;

        let declared: Declarations = linked.declarations();
        // ADR-0066, amendment 2026-10-22: a call to a compiled unit is read
        // and validated, and running one is decided, not built.
        let unrun = configure::step::unrun(&document, &applications);
        if !unrun.is_empty() {
            return Err(Refusal::at(StartupPhase::ValidateStartup, unrun));
        }
        let (tree, _) = build_execution_tree(document, &applications, &declared)
            .map_err(|report| Refusal::at(StartupPhase::ValidateStartup, report.errors))?;
        let Checked { gates, gathering } = check(&tree, &linked)
            .map_err(|problems| Refusal::at(StartupPhase::ValidateStartup, problems))?;
        // Set up from the Locations the node starts, before the
        // capabilities are registered, so each is registered as the rest.
        let started = crate::linked::Started {
            receive: &gates,
            send: &tree.send_locations_to_start,
        };
        let set_up: Vec<_> = linked
            .location_policies
            .iter()
            .map(|policy| policy(started))
            .collect();
        linked.policies.extend(set_up);

        let mut host_services = host::plan(
            &tree
                .modules_to_start
                .iter()
                .map(|module| module.manifest.clone())
                .collect::<Vec<_>>(),
        );
        start_host_services(&mut host_services)
            .map_err(|problems| Refusal::at(StartupPhase::StartHostServices, problems))?;

        #[cfg(feature = "dynamic-loading")]
        let libraries = crate::library::Libraries::open(&tree.modules_to_start)
            .map_err(|problems| Refusal::at(StartupPhase::LoadModules, problems))?;
        #[cfg(not(feature = "dynamic-loading"))]
        crate::library::refuse(&tree.modules_to_start)
            .map_err(|problems| Refusal::at(StartupPhase::LoadModules, problems))?;

        let capabilities = load(&tree, &linked, &gathering)
            .map_err(|problems| Refusal::at(StartupPhase::RegisterCapabilities, problems))?;

        // The handshake read under its own bound, `[tuning]
        // receive_handshake`, apart from each Location's own wait.
        let guard = guard.map(|guard| guard.handshaking_within(tree.tuning.receive_handshake));
        // The keys its far ends presented first, kept across restarts
        // (ADR-0019, amendment 2026-10-28).
        let pins =
            std::sync::Arc::new(transport::Pinned::kept_at(data.join(crate::linked::PINNED)));
        // Xmip Storage before the Locations: a Location's secret is read
        // from its Administration Database as it connects (ADR-0019,
        // amendment 2026-10-29).
        let storage = reaching.open(&linked, &tree.tuning)?;
        let secrets: Arc<dyn xcore::Secrets> = Arc::new(persist::storage::StoredSecrets(
            Arc::clone(storage.storage()),
        ));
        let (receiving, sends) = open(&tree, &linked, (gates, guard.as_ref(), &pins, &secrets))
            .map_err(|problems| Refusal::at(StartupPhase::AcceptWork, problems))?;
        let scope = publication::location(&tree.service.cluster_name, &tree.service.node_name);
        let configured = ConfiguredSubscription::of(&applications, &files);
        let pickup = Pickup::open(
            &scope,
            configured,
            Arc::clone(storage.storage()),
            linked.audit.clone(),
        )
        .map_err(|problem| Refusal::at(StartupPhase::AcceptWork, vec![problem]))?;

        // Only what the configuration named goes on: the authenticators its
        // Receive Locations accept. Policies and identifiers are consulted at
        // every gate, and no configuration selects among them yet; the
        // receive policies were set up from the Locations above.
        let accepted: BTreeSet<String> = receiving
            .iter()
            .flat_map(|receiving| receiving.configured.accept.mechanism.clone())
            .collect();
        linked
            .authenticators
            .retain(|authenticator| accepted.contains(authenticator.mechanism().name()));

        let locations = receiving
            .iter()
            .map(|r| ("receive", r.configured.clone()))
            .chain(
                sends
                    .locations
                    .iter()
                    .map(|s| ("send", s.configured.clone())),
            )
            .collect();
        let not_started = tree.not_started();
        let send = Arc::new(SendStep::new(
            (
                &publication::cluster_location(&tree.service.cluster_name),
                &scope,
            ),
            Arc::clone(storage.storage()),
            &tree.tuning,
            linked.audit.clone(),
        ));
        SendStep::register(&send);
        let cluster = publication::cluster_location(&tree.service.cluster_name);
        #[cfg(feature = "dynamic-loading")]
        let running = crate::work_step::opened(&tree, &cluster, &libraries, &linked)
            .map_err(|problems| Refusal::at(StartupPhase::LoadModules, problems))?;
        #[cfg(not(feature = "dynamic-loading"))]
        let running = Vec::new();
        let work = Arc::new(WorkStep::new(
            (&cluster, &scope),
            Arc::clone(storage.storage()),
            tree.tuning.send(),
            linked.audit.clone(),
            running,
        ));
        let stopping = Arc::new(Stopping::default());
        let tally = Arc::new(Tally::default());
        let origin = origin(linked.audit.as_ref(), &scope);
        let serving = serve(
            Served {
                storage: Arc::clone(storage.storage()),
                chunk: storage.chunk(),
                origin,
                linked,
                gathering,
                subscriptions: tree.subscriptions,
                parties: Recognized(tree.parties),
                pickup: Arc::clone(&pickup),
                sends,
                send: Arc::clone(&send),
                work: Arc::clone(&work),
                budget: NodeBudget::of(&tree.tuning),
                receiving,
            },
            Arc::clone(&stopping),
            Arc::clone(&tally),
        );

        Ok(Self {
            online: tree.service.online,
            cluster: tree.service.cluster_name,
            node: tree.service.node_name,
            capabilities,
            host_services,
            locations,
            not_started,
            stopping,
            serving: Some(serving),
            tally,
            pickup,
            send,
            data,
            storage,
            operate,
            certificates,
            local_timeout: tree.tuning.local_timeout,
            configuration: PathBuf::from(path),
            #[cfg(feature = "dynamic-loading")]
            libraries: Some(libraries),
        })
    }

    /// The cluster the node belongs to, `service.cluster_name`.
    #[must_use]
    pub fn cluster(&self) -> &str {
        &self.cluster
    }

    /// The node's name, `service.node_name`.
    #[must_use]
    pub fn node(&self) -> &str {
        &self.node
    }

    /// Every capability loaded, once each, by the Module serving it.
    #[must_use]
    pub const fn capabilities(&self) -> &CapabilityRegistry {
        &self.capabilities
    }

    /// The Host Services the node's Modules needed, as started.
    #[must_use]
    pub fn host_services(&self) -> &[HostService] {
        &self.host_services
    }

    /// The node's Subscriptions, their standing and what they hold, which
    /// an operator pauses and resumes (ADR-0013, amendment 2026-09-30).
    #[must_use]
    pub fn pickup(&self) -> &Pickup {
        &self.pickup
    }

    /// The node's send step: what it sends from the Ledger, and its figures
    /// per Send Port.
    #[must_use]
    pub fn send(&self) -> &SendStep {
        &self.send
    }

    /// Its data directory (`configure::ServiceConfiguration::data`):
    /// where the orders an operator leaves for it and its last snapshot
    /// are kept.
    #[must_use]
    pub fn data(&self) -> &Path {
        &self.data
    }

    /// How the node reaches Xmip Storage, which its receives write the
    /// Ledger through.
    #[must_use]
    pub const fn storage(&self) -> &Reached {
        &self.storage
    }

    /// What became of every Stream so far.
    #[must_use]
    pub fn outcomes(&self) -> Outcomes {
        self.tally.outcomes()
    }

    /// Stop: every Receive Location takes nothing more once its current
    /// receive returns — one whose far end already let go of what it
    /// handed over first drains what is queued for it (ADR-0018, amendment
    /// 2026-10-15) — what it took is carried whole, and then the
    /// transports and the loaded Modules are let go (ADR-0018 clause 12).
    /// Returns what became of every Stream.
    pub fn stop(mut self) -> Outcomes {
        self.halt();
        self.tally.outcomes()
    }

    fn halt(&mut self) {
        self.stopping.raise();
        if let Some(serving) = self.serving.take()
            && serving.join().is_err()
        {
            self.tally
                .fail(&self.node, "the node's serving thread panicked".to_string());
        }
        for service in &mut self.host_services {
            service.stop();
        }
        // The node's own work stopped, what it serves the others stops: a
        // primary Storage node hands its standbys what it wrote first.
        self.storage.stop();
        #[cfg(feature = "dynamic-loading")]
        drop(self.libraries.take());
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.halt();
    }
}

/// Who a running node's audit records say they came from: the program's
/// origin where it audits, this process as the runtime otherwise, and the
/// node's location on each (ADR-0062, amendment 2026-09-29).
#[must_use]
pub fn origin(program: Option<&ProgramAudit>, node: &str) -> Origin {
    Origin {
        location: Some(node.to_string()),
        ..program.map_or_else(
            || Origin::here(env!("CARGO_PKG_NAME")),
            |audit| audit.origin(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::{Always, Open};
    use crate::linked::{LinkedTransport, Opened};
    use http::HttpTransport;
    use net::fixture::unheld;
    use observe::Health;
    use std::cell::Cell;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};
    use tcp::TcpTransport;
    use transport::{Configured, Transport};
    use xcore::settings::{Applies, Given};

    thread_local! {
        /// How often this test's thread built a tcp transport: startup runs on
        /// the thread that calls it, so each test counts its own.
        static OPENED: Cell<usize> = const { Cell::new(0) };
        /// The node each of this test's thread's transports was given.
        static GIVEN: std::cell::RefCell<Vec<String>> = const {
            std::cell::RefCell::new(Vec::new())
        };
    }

    fn counted<T: Configured + Send + Sync + 'static>(
        address: &str,
        side: Applies,
        given: &[(String, Given)],
        on: crate::linked::OnNode<'_>,
    ) -> Opened {
        OPENED.with(|opened| opened.set(opened.get() + 1));
        GIVEN.with(|nodes| nodes.borrow_mut().push(on.0.to_string()));
        crate::linked::open::<T>(address, side, given, on)
    }

    /// What the tests' program links, and the test Storage node it opened
    /// beside the configuration at `file`: `RocksDB` on disk for the runtime
    /// database, `SQLite` in memory for the administration and the audit
    /// databases.
    fn linked(file: &Path) -> Linked {
        static PLACES: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let place = file.parent().expect("its directory").join(format!(
            "ledger-{}",
            PLACES.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        Linked {
            transports: vec![
                LinkedTransport::opened_by::<TcpTransport>(counted::<TcpTransport>),
                LinkedTransport::opened_by::<HttpTransport>(counted::<HttpTransport>),
            ],
            authenticators: vec![Box::new(Always::circumstance())],
            policies: vec![Box::new(Open)],
            storage: Some(Arc::new(test_storage(&place))),
            ..Linked::default()
        }
    }

    /// The Loopback Application, as its section of the node's configuration.
    const APPLICATION: &str = r#"
[[xmip_applications]]
name = "Loopback"

[[xmip_applications.receive_ports]]
name = "Loopback"

[[xmip_applications.receive_locations]]
name = "In"
receive_port = "Loopback"
depth = "light"

[[xmip_applications.send_ports]]
name = "Out"

[[xmip_applications.subscriptions]]
id = "onward"
destination = { send-port = "Out" }
filter = "xmip.transport.mechanism = 'circumstance'"
"#;

    /// The test cluster's first node, and its scope.
    fn first() -> (String, String) {
        let cluster = configure::fixture::test_cluster();
        let node = cluster.node(0).name.clone();
        let scope = format!("xmip:///{}/node/{node}", cluster.name);
        (node, scope)
    }

    /// The test cluster's first node takes both ends of the Application: a
    /// tcp Receive Location on `receive`, and a tcp Send Port to `far`.
    fn node(receive: &str, far: &str) -> String {
        let cluster = configure::fixture::test_cluster();
        let (node, _) = first();
        format!(
            r#"[service]
name = "xmip"
cluster_name = "{cluster}"
node_name = "{node}"

[[applications]]
name = "Loopback"

[[applications.receive_locations]]
name = "In"
node = "{node}"
start = true
address = "tcp://{receive}"
[applications.receive_locations.settings]
timeout = "100ms"
[applications.receive_locations.accept]
mechanism = ["circumstance"]

[[applications.send_ports]]
name = "Out"
node = "{node}"
start = true
address = "tcp://{far}"
{APPLICATION}"#,
            cluster = cluster.name
        )
    }

    /// [`node`], its Send Port `Out` stating `policy` — its `retry`,
    /// its `correlation` and the rest, one key a line.
    fn node_sending(receive: &str, far: &str, policy: &str) -> String {
        node(receive, far).replace(
            "[[xmip_applications.send_ports]]\nname = \"Out\"\n",
            &format!("[[xmip_applications.send_ports]]\nname = \"Out\"\n{policy}\n"),
        )
    }

    /// A test Storage node at `place`, its key-encryption key in memory and
    /// so as new as the node: a database already at `place` was sealed
    /// under a key that ended with whatever opened it.
    fn test_storage(place: &Path) -> persist::storage::Embedded<rocksdb::RocksDb, sqlite::Sqlite> {
        let keys = secret::Held::new(secret::fixture::Memory::default());
        persist::storage::Embedded::open(
            rocksdb::RocksDb::open(place).expect("the runtime database"),
            sqlite::Sqlite::in_memory().expect("the administration database"),
            sqlite::Sqlite::in_memory().expect("the audit database"),
            &keys,
            &secret::KekName::new(crate::storage::KEK).expect("a name"),
        )
        .expect("the test Storage node")
    }

    /// A directory of its own holding `configuration` and nothing else, and
    /// the configuration's path. Emptied first: it is named for the process,
    /// and an earlier process of the same id may have left it.
    fn written(test: &str, configuration: &str) -> PathBuf {
        let directory =
            std::env::temp_dir().join(format!("xmip-running-{test}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).expect("a directory");
        let path = directory.join("node.toml");
        std::fs::write(&path, configuration).expect("writes the node");
        path
    }

    fn path_text(path: &Path) -> &str {
        path.to_str().expect("a UTF-8 path")
    }

    /// Send `payload` to the node at `target` by `sender`, asking again
    /// while its Receive Location has not yet bound — it binds on its first
    /// receive, and nothing else says when that was. Bounded, and never a
    /// sleep.
    fn deliver(sender: &dyn Transport, target: &str, payload: &[u8]) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match sender.send(target, payload) {
                Ok(()) => return,
                Err(refused) if refused.retryable && Instant::now() < deadline => {
                    std::thread::yield_now();
                }
                Err(failed) => panic!("the node took nothing at {target}: {failed:?}"),
            }
        }
    }

    /// [`node`] over HTTP, the Send Port posting to `far`: a test carrying
    /// hundreds of Messages through a node keeps one connection a sender,
    /// where raw TCP spends one a Message, each waiting minutes to close on
    /// its sender's side.
    fn node_keeping_connections(receive: &str, far: &str) -> String {
        node(receive, &format!("{far}/orders")).replace("address = \"tcp://", "address = \"http://")
    }

    /// A far end over HTTP, listening before anything is sent to it, and
    /// where it listens.
    fn kept_far_end() -> (HttpTransport, String) {
        let far = HttpTransport::loopback();
        let address = far.listening().expect("the far end binds").to_string();
        (far, address)
    }

    /// The next Message `far` takes, accepted: its sender is answered.
    fn taken_at(far: &HttpTransport) -> Vec<u8> {
        far.receive()
            .expect("it reaches the far end")
            .remove(0)
            .taken()
            .expect("accepted")
            .bytes
    }

    #[test]
    fn a_node_carries_every_message_from_its_receive_location_to_the_far_end() {
        const MESSAGES: u32 = 200;
        let far = TcpTransport::loopback();
        let (listener, far_address) = far.bind().expect("the far end binds");
        let receive = unheld().to_string();
        let path = written("carries", &node(&receive, &far_address));

        OPENED.with(|opened| opened.set(0));
        let running = Running::start(path_text(&path), linked(&path)).expect("the node starts");

        // One module per technology, however many Locations use it; one
        // transport instance per Location.
        let registered: Vec<&str> = running
            .capabilities()
            .capabilities()
            .map(|c| c.capability.as_str())
            .collect();
        assert_eq!(
            registered,
            [
                "authenticate:circumstance",
                "authorize:open",
                "transport:xmip-core-transport-tcp"
            ]
        );
        assert_eq!(OPENED.with(Cell::get), 2, "one transport per Location");
        assert!(
            crate::catalogue::declarations().contains_key("tcp"),
            "loading carries the declaration"
        );

        deliver(&TcpTransport::loopback(), &receive, b"order 0");
        let first = far
            .accept_one(&listener)
            .expect("the first arrives")
            .taken()
            .expect("read whole");
        assert_eq!(first.bytes, b"order 0");

        // Each Message timed on its own, and the load sampled between them,
        // so both meet the same machine; the medians decide.
        let (load_far, (load_listener, load_address)) = {
            let far = TcpTransport::loopback();
            let bound = far.bind().expect("a far end for the load binds");
            (far, bound)
        };
        let mut times = Vec::new();
        let mut loads = Vec::new();
        for message in 1..=MESSAGES {
            let payload = format!("order {message}");
            let started = Instant::now();
            TcpTransport::loopback()
                .send(&receive, payload.as_bytes())
                .expect("the node takes it");
            let arrived = far
                .accept_one(&listener)
                .expect("it reaches the far end")
                .taken()
                .expect("read whole");
            times.push(started.elapsed());
            assert_eq!(arrived.bytes, payload.as_bytes());
            if message % 5 == 0 {
                loads.push(load_of_one_message(
                    &running,
                    (&load_far, &load_listener, &load_address),
                    message,
                ));
            }
        }
        let each = median(times);
        let load = median(loads);
        eprintln!("LEDGER loopback end to end: {each:?} per Message, median");
        eprintln!("LEDGER the load of one Message here: {load:?}, median");

        let outcomes = running.stop();
        let carried = u64::from(MESSAGES) + 1;
        assert_eq!(outcomes.received, carried);
        assert_eq!(outcomes.routed, carried, "{outcomes:?}");
        assert_eq!(outcomes.sent, carried, "{outcomes:?}");
        assert_eq!(
            outcomes.refused + outcomes.failed + outcomes.unroutable + outcomes.not_sent,
            0
        );
        // The millisecond rule, with the load counted as load (the owner,
        // 2026-10-03: *Go for A*): each Message costs one durable sync on
        // this machine's disk and the test's own two loopback connections,
        // measured here; the whole message path around them may add a
        // millisecond, no more.
        assert!(
            each < load + Duration::from_millis(1),
            "{each:?} per Message against {load:?} of load"
        );
        let _ = std::fs::remove_dir_all(path.parent().expect("its directory"));
    }

    /// The middle one of `times`, so one slow round decides nothing.
    fn median(mut times: Vec<Duration>) -> Duration {
        times.sort();
        times[times.len() / 2]
    }

    /// What one Message costs that is not the message path, sampled once:
    /// one durable write through the node's own Xmip Storage — its sync —
    /// and two loopback connections carrying a few bytes to `far`.
    fn load_of_one_message(
        running: &Running,
        (far, listener, address): (&TcpTransport, &std::net::TcpListener, &str),
        round: u32,
    ) -> Duration {
        let record = persist::storage::JourneyRecord {
            journey: xcore::JourneyId::new(u128::MAX - u128::from(round)),
            body: vec![0; 512],
            facts: persist::storage::JourneyFacts::default(),
        };
        let started = Instant::now();
        running
            .storage()
            .storage()
            .write_journey(&record)
            .expect("written durably");
        let sync = started.elapsed();
        let started = Instant::now();
        TcpTransport::loopback()
            .send(address, b"load")
            .expect("sent");
        far.accept_one(listener)
            .expect("taken")
            .taken()
            .expect("read whole");
        sync + 2 * started.elapsed()
    }

    /// `body` posted over `connection` as the sender `who` names itself in
    /// its `X-Sender` header, and the node's answer read: accepted.
    fn posted_as(connection: &mut std::net::TcpStream, who: &str, body: &[u8]) {
        use std::io::{BufRead, BufReader, Read, Write};
        let head = format!(
            "POST /orders HTTP/1.1\r\nHost: node\r\nX-Sender: {who}\r\n\
             Content-Length: {}\r\n\r\n",
            body.len()
        );
        connection.write_all(head.as_bytes()).expect("writes");
        connection.write_all(body).expect("writes");
        let mut reader = BufReader::new(connection.try_clone().expect("clones"));
        let mut line = String::new();
        reader.read_line(&mut line).expect("answered");
        assert!(line.contains(" 2"), "the node answered {line}");
        let mut length = 0usize;
        loop {
            line.clear();
            reader.read_line(&mut line).expect("a header");
            if line == "\r\n" {
                break;
            }
            if let Some((name, value)) = line.split_once(':')
                && name.eq_ignore_ascii_case("content-length")
            {
                length = value.trim().parse().expect("a length");
            }
        }
        let mut answer = vec![0; length];
        reader.read_exact(&mut answer).expect("the answer's body");
    }

    #[test]
    fn eight_senders_at_once_are_carried_side_by_side() {
        // A Receive Location carries one Stream at a time end to end unless a
        // Correlation spreads them (`crate::sequence`): this one's is keyed
        // by the sender each request names, so one sender's Streams go one at
        // a time and eight senders' side by side, their Ledger writes sharing a
        // group commit's disk sync.
        const SENDERS: u32 = 8;
        const EACH: u32 = 50;
        let (far, far_address) = kept_far_end();
        let receive = unheld().to_string();
        let spread = format!(
            "{}\n[[correlations]]\nname = \"PerSender\"\nkeys = [\"http.header.x-sender\"]\n",
            node_keeping_connections(&receive, &far_address).replace(
                "receive_port = \"Loopback\"\n",
                "receive_port = \"Loopback\"\ncorrelation = \"PerSender\"\n",
            )
        );
        let path = written("eight", &spread);
        let running = Running::start(path_text(&path), linked(&path)).expect("the node starts");
        posted_as(
            &mut std::net::TcpStream::connect(&receive).expect("connects"),
            "warm",
            b"warm",
        );
        taken_at(&far);

        let started = Instant::now();
        let taking = std::thread::spawn(move || {
            let mut taken: Vec<Vec<u8>> = (0..SENDERS * EACH).map(|_| taken_at(&far)).collect();
            taken.sort();
            taken.dedup();
            taken.len()
        });
        let senders: Vec<_> = (0..SENDERS)
            .map(|sender| {
                let at = receive.clone();
                std::thread::spawn(move || {
                    // Each sender keeps its one connection, and names itself.
                    let mut connection = std::net::TcpStream::connect(&at).expect("connects");
                    for message in 0..EACH {
                        let body = format!("S{sender} {message}");
                        posted_as(&mut connection, &format!("S{sender}"), body.as_bytes());
                    }
                })
            })
            .collect();
        for sender in senders {
            sender.join().expect("a sender");
        }
        assert_eq!(
            taking.join().expect("the far end"),
            (SENDERS * EACH) as usize
        );
        let each = started.elapsed() / (SENDERS * EACH);
        eprintln!("eight senders, loopback end to end: {each:?} per Message");

        let outcomes = running.stop();
        assert_eq!(outcomes.sent, u64::from(SENDERS * EACH) + 1, "{outcomes:?}");
        assert!(each < Duration::from_millis(5), "{each:?} per Message");
        let _ = std::fs::remove_dir_all(path.parent().expect("its directory"));
    }

    #[test]
    fn a_location_is_held_to_its_technologys_declaration_as_the_node_starts() {
        let unsound = node(&unheld().to_string(), &unheld().to_string())
            .replace("timeout = \"100ms\"", "timeout = 5\ncolor = \"lime\"");
        let path = written("declared", &unsound);

        let refused = Running::start(path_text(&path), linked(&path))
            .err()
            .expect("refused");

        assert_eq!(refused.phase, StartupPhase::ValidateStartup);
        assert_eq!(refused.problems.len(), 2, "{:?}", refused.problems);
        for setting in ["\"timeout\"", "\"color\""] {
            assert!(
                refused
                    .problems
                    .iter()
                    .any(|p| p.contains(setting) && p.contains("xmip-core-transport-tcp")),
                "{setting}: {:?}",
                refused.problems
            );
        }

        // Once a node has loaded tcp, a surface validating in this process
        // holds a tcp Location to the same declaration (xmip_validate_v1).
        let sound = written(
            "declared-sound",
            &node(&unheld().to_string(), &unheld().to_string()),
        );
        Running::start(path_text(&sound), linked(&sound))
            .expect("the node starts")
            .stop();
        let problems = crate::start::validate(&unsound);
        assert!(
            problems.iter().any(|p| p.contains("\"color\"")),
            "{problems:?}"
        );
        for written in [path, sound] {
            let _ = std::fs::remove_dir_all(written.parent().expect("its directory"));
        }
    }

    #[test]
    fn every_transport_is_given_its_nodes_location_as_it_is_built() {
        let path = written("given", &node(&unheld().to_string(), &unheld().to_string()));
        GIVEN.with(|nodes| nodes.borrow_mut().clear());
        let running = Running::start(path_text(&path), linked(&path)).expect("the node starts");
        let given = GIVEN.with(|nodes| nodes.borrow().clone());
        assert_eq!(
            given.len(),
            2,
            "the Receive and the Send Location: {given:?}"
        );
        assert!(
            given.iter().all(|node| *node == running.location()),
            "{given:?}"
        );
        assert_eq!(running.location(), first().1);
        running.stop();
        let _ = std::fs::remove_dir_all(path.parent().expect("its directory"));
    }

    #[test]
    fn a_node_stops_cleanly_and_lets_its_listener_go() {
        let far = TcpTransport::loopback();
        let (listener, far_address) = far.bind().expect("the far end binds");
        let receive = unheld().to_string();
        let path = written("stops", &node(&receive, &far_address));
        let running = Running::start(path_text(&path), linked(&path)).expect("the node starts");
        deliver(&TcpTransport::loopback(), &receive, b"before the stop");
        far.accept_one(&listener)
            .expect("it reaches the far end")
            .taken()
            .expect("read whole");

        let health = running.snapshot().health(&first().1);
        assert!(
            !health.is_empty() && health.iter().all(|record| record.health == Health::Fine),
            "{health:?}"
        );

        let stopping = Instant::now();
        let outcomes = running.stop();
        let took = stopping.elapsed();

        assert_eq!(outcomes.sent, 1);
        // Bounded by the Location's own wait, 100 ms, not by a timeout of
        // the runtime's.
        assert!(took < Duration::from_secs(2), "stopping took {took:?}");
        let address: std::net::SocketAddr = receive.parse().expect("an address");
        assert!(
            std::net::TcpStream::connect_timeout(&address, Duration::from_millis(500)).is_err(),
            "the listener is let go"
        );

        // Dropped without a stop, a node stops all the same.
        let again = Running::start(path_text(&path), linked(&path)).expect("starts again");
        deliver(&TcpTransport::loopback(), &receive, b"after");
        far.accept_one(&listener)
            .expect("it reaches the far end")
            .taken()
            .expect("read whole");
        drop(again);
        assert!(
            std::net::TcpStream::connect_timeout(&address, Duration::from_millis(500)).is_err()
        );
        let _ = std::fs::remove_dir_all(path.parent().expect("its directory"));
    }

    #[test]
    fn what_the_program_was_not_built_with_refuses_the_node_at_start() {
        let base = node(&unheld().to_string(), &unheld().to_string());
        let cases = [
            (
                base.replacen("address = \"tcp://", "address = \"sftp://", 1),
                "and this node carries no transport for sftp://; it carries tcp, http, https",
            ),
            (
                base.replace("[\"circumstance\"]", "[\"mutual-tls\"]"),
                "accepts 'mutual-tls', and no authenticator this node was built with verifies it",
            ),
            (
                base.replace(
                    "address = \"tcp://127",
                    "contract = \"xmip-core-contract-json\"\naddress = \"tcp://127",
                ),
                "holds no Stream to a contract at arrival yet",
            ),
        ];

        for (configuration, reason) in cases {
            let path = written("unlinked", &configuration);
            let refused = Running::start(path_text(&path), linked(&path))
                .err()
                .expect("refused");
            assert_eq!(refused.phase, StartupPhase::ValidateStartup);
            assert!(
                refused.problems.iter().any(|p| p.contains(reason)),
                "{reason}: {:?}",
                refused.problems
            );
            let _ = std::fs::remove_dir_all(path.parent().expect("its directory"));
        }

        // ADR-0066 clause 1: a filter naming what no route technology this
        // node was built with reads is refused now, not at the first Message.
        let directory = written(
            "unread",
            &base.replace("xmip.transport.mechanism", "party:sender"),
        );
        let refused = Running::start(path_text(&directory), linked(&directory))
            .err()
            .expect("refused");
        assert_eq!(refused.phase, StartupPhase::ValidateStartup);
        assert!(
            refused.problems[0].contains("no route technology"),
            "{refused}"
        );
        let _ = std::fs::remove_dir_all(directory.parent().expect("its directory"));
    }

    /// The directories are named for the process, and Windows gives a
    /// process id again: what an earlier process of the same id left —
    /// a ledger sealed under a key-encryption key that ended with it — is
    /// not what the next one's test Storage node opens.
    #[test]
    fn what_an_earlier_process_of_the_same_id_left_is_gone() {
        let earlier = written("left", "");
        let place = earlier.parent().expect("its directory").join("ledger");
        drop(test_storage(&place));

        let path = written("left", "");

        drop(test_storage(&place));
        let _ = std::fs::remove_dir_all(path.parent().expect("its directory"));
    }

    const LIBRARY_MODULE: &str = "\n[[modules]]\nname = \"contract-rust\"\nstart = true\n\
        [modules.manifest]\noffline = true\n\
        [modules.manifest.identity]\nname = \"xmip-core-contract-rust\"\nversion = \"0.1.0\"\n\
        [[modules.manifest.capabilities]]\ncapability = \"contract\"\n\
        execution_host = \"c-abi\"\ntrusted_required = false\n\
        [modules.manifest.entrypoint]\n";

    #[cfg(not(feature = "dynamic-loading"))]
    #[test]
    fn a_library_module_is_refused_where_the_runtime_opens_none() {
        let configuration = format!(
            "{}{LIBRARY_MODULE}library_path = \"xmip_core_contract_rust.dll\"\n",
            node(&unheld().to_string(), &unheld().to_string())
        );
        let path = written("library", &configuration);

        let refused = Running::start(path_text(&path), linked(&path))
            .err()
            .expect("refused");

        assert_eq!(refused.phase, StartupPhase::LoadModules);
        assert!(refused.problems[0].contains("dynamic-loading"), "{refused}");
        let _ = std::fs::remove_dir_all(path.parent().expect("its directory"));
    }

    /// ADR-0057: a Module the configuration starts is opened from its
    /// library once, through the C ABI, held while the node runs and let go
    /// when it stops. `module/core/capability/contract/rust` builds it, or
    /// `XMIP_MODULE_LIBRARY` names one.
    #[cfg(feature = "dynamic-loading")]
    #[test]
    fn a_library_module_is_opened_once_and_let_go_at_the_stop() {
        let library = std::env::var("XMIP_MODULE_LIBRARY").map_or_else(
            |_| {
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../core/capability/contract/rust/target/debug")
                    .join(if cfg!(windows) {
                        "xmip_core_contract_rust.dll"
                    } else if cfg!(target_os = "macos") {
                        "libxmip_core_contract_rust.dylib"
                    } else {
                        "libxmip_core_contract_rust.so"
                    })
            },
            PathBuf::from,
        );
        assert!(
            library.exists(),
            "build the module first: {}",
            library.display()
        );
        let configuration = format!(
            "{}{LIBRARY_MODULE}library_path = '{}'\n",
            node(&unheld().to_string(), &unheld().to_string()),
            library.display()
        );
        let path = written("opened", &configuration);

        let running = Running::start(path_text(&path), linked(&path)).expect("the node starts");

        let contract = running
            .capabilities()
            .get("contract")
            .expect("registered once");
        assert_eq!(contract.module, "xmip-core-contract-rust");
        assert_eq!(
            contract.load,
            crate::capability_registry::Load::Library(library.clone())
        );
        assert!(running.host_services().iter().all(HostService::in_process));
        running.stop();
        let _ = std::fs::remove_dir_all(path.parent().expect("its directory"));
    }

    #[test]
    fn a_paused_subscription_holds_at_the_node_and_its_resume_sends_what_it_held_in_order() {
        let far = TcpTransport::loopback();
        let (listener, far_address) = far.bind().expect("the far end binds");
        let receive = unheld().to_string();
        // In order: a Send Port naming a set keyed by itself keeps it, one
        // Journey at a time (`crate::sequence`).
        let sequential = "correlation = \"InOrder\"";
        let configured = format!(
            "{}\n[[correlations]]\nname = \"InOrder\"\nkeys = [\"send-port\"]\n",
            node_sending(&receive, &far_address, sequential)
        );
        let path = written("paused", &configured);
        let running = Running::start(path_text(&path), linked(&path)).expect("the node starts");
        deliver(&TcpTransport::loopback(), &receive, b"before the pause");
        far.accept_one(&listener)
            .expect("it reaches the far end")
            .taken()
            .expect("read whole");

        let pickup = running.pickup();
        assert_eq!(pickup.node(), first().1);
        let standing = &pickup.standing()[0];
        assert_eq!(standing.name, "onward");
        assert_eq!(standing.application, "Loopback");
        assert!(standing.file.ends_with("node.toml"));
        assert!(
            standing
                .configuration
                .starts_with("[[xmip_applications.subscriptions]]")
        );
        pickup
            .act("onward", observe::Act::Pause, "ilian")
            .expect("paused");
        // Each held before the next is sent: TCP's connections arrive in no
        // order of their own (`Arrivals::Unordered`), so the order held is
        // the order the receive cycles finished.
        for n in 1..=3 {
            deliver(
                &TcpTransport::loopback(),
                &receive,
                format!("held {n}").as_bytes(),
            );
            let deadline = Instant::now() + Duration::from_secs(5);
            while pickup.standing()[0].held < n && Instant::now() < deadline {
                std::thread::yield_now();
            }
            assert_eq!(pickup.standing()[0].held, n, "held, not sent");
        }

        pickup
            .act("onward", observe::Act::Resume, "ilian")
            .expect("resumed");
        for n in 1..=3 {
            let arrived = far
                .accept_one(&listener)
                .expect("it reaches the far end")
                .taken()
                .expect("read whole");
            assert_eq!(
                arrived.bytes,
                format!("held {n}").as_bytes(),
                "oldest first"
            );
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while pickup.standing()[0].held > 0 && Instant::now() < deadline {
            std::thread::yield_now();
        }
        let outcomes = running.stop();
        assert_eq!((outcomes.held, outcomes.sent), (3, 4), "{outcomes:?}");
        let _ = std::fs::remove_dir_all(path.parent().expect("its directory"));
    }
}
