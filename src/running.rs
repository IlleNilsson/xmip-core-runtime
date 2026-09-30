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
//! 9 accept-work            each Location's transport built once; the Runtime
//!                          built once; every Receive Location serving
//! ```

use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;

use authenticate::Authenticator;
use authorize::Authorizer;
use configure::{ConfiguredLocation, Declarations};
use identify::{MessageIdentifier, TransportIdentifier};
use message::MessageTreatment;
use observe::{Health, HealthRecord, Snapshot, now_unix_nanos};
use route::Gathering;
use xcore::{SystemClock, UuidV7Generator};

use crate::capability_registry::{CapabilityRegistry, Load};
use crate::configured_subscription::ConfiguredSubscription;
use crate::execution_tree::build_execution_tree;
use crate::held_work::pick_up_released;
use crate::host::{self, HostService};
use crate::linked::Linked;
use crate::message_path::{Parties, Runtime};
use crate::outcome::{Outcomes, Tally};
use crate::pickup::Pickup;
use crate::receiving::Receiving;
use crate::sending::Sends;
use crate::service::StartupPhase;
use crate::start::read;
use crate::startup::{Checked, check, load, open, start_host_services};
use crate::store::Opened;

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
    capabilities: CapabilityRegistry,
    host_services: Vec<HostService>,
    locations: Vec<(&'static str, ConfiguredLocation)>,
    stopping: Arc<AtomicBool>,
    serving: Option<JoinHandle<()>>,
    tally: Arc<Tally>,
    pickup: Arc<Pickup>,
    store: Opened,
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
        let planned = crate::store::plan(&document, path, &linked)?;

        let declared: Declarations = linked
            .transports
            .iter()
            .map(|linked| (linked.technology(), linked.settings()))
            .collect();
        let (tree, _) = build_execution_tree(document, &applications, &declared)
            .map_err(|report| Refusal::at(StartupPhase::ValidateStartup, report.errors))?;
        let Checked { gates, gathering } = check(&tree, &linked)
            .map_err(|problems| Refusal::at(StartupPhase::ValidateStartup, problems))?;

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

        let (receiving, sends) = open(&tree, &linked, gates)
            .map_err(|problems| Refusal::at(StartupPhase::AcceptWork, problems))?;
        let scope = format!(
            "xmip:///{}/node/{}",
            tree.service.cluster_name, tree.service.node_name
        );
        let configured = ConfiguredSubscription::of(&applications, &files);
        let store = planned.open(&linked)?;
        let pickup = Pickup::open(&scope, configured, store.held(), linked.audit.clone())
            .map_err(|problem| Refusal::at(StartupPhase::AcceptWork, vec![problem]))?;

        // Only what the configuration named goes on: the authenticators its
        // Receive Locations accept. Policies and identifiers are consulted at
        // every gate, and no configuration selects among them yet.
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
        let stopping = Arc::new(AtomicBool::new(false));
        let tally = Arc::new(Tally::default());
        let serving = serve(
            Served {
                linked,
                gathering,
                subscriptions: tree.subscriptions,
                pickup: Arc::clone(&pickup),
                sends,
                receiving,
            },
            Arc::clone(&stopping),
            Arc::clone(&tally),
        );

        Ok(Self {
            cluster: tree.service.cluster_name,
            node: tree.service.node_name,
            capabilities,
            host_services,
            locations,
            stopping,
            serving: Some(serving),
            tally,
            pickup,
            store,
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

    /// Its runtime store as opened, and its data directory.
    #[must_use]
    pub const fn store(&self) -> &Opened {
        &self.store
    }

    /// What became of every Stream so far.
    #[must_use]
    pub fn outcomes(&self) -> Outcomes {
        self.tally.outcomes()
    }

    /// What the node says of itself now: itself, each capability loaded, and
    /// each Location with what it is doing — `Fine` while it serves, `Done`
    /// with the reason where a Receive Location stopped.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        let now = now_unix_nanos();
        let node = format!("xmip:///{}", self.node);
        let failures = self.tally.failures();
        let mut snapshot = Snapshot::new();
        let mut record = |scope: String, health: Health, evidence: String| {
            snapshot.record_health(HealthRecord {
                scope,
                health,
                severity: if health == Health::Fine { 0 } else { 90 },
                evidence,
                observed_unix_nanos: now,
            });
        };

        record(
            node.clone(),
            Health::Fine,
            format!(
                "running: {} capability(ies) loaded, {} Location(s) started",
                self.capabilities.capabilities().count(),
                self.locations.len()
            ),
        );
        for capability in self.capabilities.capabilities() {
            let how = match &capability.load {
                Load::Linked => "linked".to_string(),
                Load::Library(path) => format!("from {}", path.display()),
            };
            record(
                format!("{node}/module/{}", capability.module),
                Health::Fine,
                format!("loaded ({how}), serving {}", capability.capability),
            );
        }
        for (stage, location) in &self.locations {
            let scope = format!("{node}/{stage}/{}", location.name);
            match failures.iter().find(|(name, _)| name == &location.name) {
                Some((_, why)) => record(scope, Health::Done, why.clone()),
                None => record(
                    scope,
                    Health::Fine,
                    format!("started; {} at {}", location.transport, location.address),
                ),
            }
        }

        snapshot
    }

    /// Stop: every Receive Location takes nothing more once its current
    /// receive returns, what it took is carried whole, and then the
    /// transports and the loaded Modules are let go (ADR-0018 clause 12).
    /// Returns what became of every Stream.
    pub fn stop(mut self) -> Outcomes {
        self.halt();
        self.tally.outcomes()
    }

    fn halt(&mut self) {
        self.stopping.store(true, Ordering::Release);
        if let Some(serving) = self.serving.take()
            && serving.join().is_err()
        {
            self.tally
                .fail(&self.node, "the node's serving thread panicked".to_string());
        }
        for service in &mut self.host_services {
            service.stop();
        }
        #[cfg(feature = "dynamic-loading")]
        drop(self.libraries.take());
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.halt();
    }
}

/// What the serving thread owns for the node's life.
struct Served {
    linked: Linked,
    gathering: Gathering,
    subscriptions: Vec<route::Subscription>,
    pickup: Arc<Pickup>,
    sends: Sends,
    receiving: Vec<Receiving>,
}

/// Startup phase 9's second half: the Runtime built once, and every Receive
/// Location serving on a thread of its own until `stopping` is raised. What
/// the thread owns is let go when the last Location has stopped — listeners
/// closed, sessions ended.
fn serve(served: Served, stopping: Arc<AtomicBool>, tally: Arc<Tally>) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let Served {
            linked,
            gathering,
            subscriptions,
            pickup,
            sends,
            receiving,
        } = served;
        let authenticators: Vec<&dyn Authenticator> =
            linked.authenticators.iter().map(AsRef::as_ref).collect();
        let policies: Vec<&dyn Authorizer> = linked.policies.iter().map(AsRef::as_ref).collect();
        let transport_identifiers: Vec<&dyn TransportIdentifier> = linked
            .transport_identifiers
            .iter()
            .map(AsRef::as_ref)
            .collect();
        let message_identifiers: Vec<&dyn MessageIdentifier> = linked
            .message_identifiers
            .iter()
            .map(AsRef::as_ref)
            .collect();
        let parties = Parties::default();

        let runtime = Runtime {
            ids: &UuidV7Generator,
            authenticators: &authenticators,
            parties: &parties,
            directory: &parties,
            subscriptions: &subscriptions,
            gathering: &gathering,
            treatment: MessageTreatment::default(),
            sends: &sends,
            transport_identifiers: &transport_identifiers,
            message_identifiers: &message_identifiers,
            policies: &policies,
            clock: &SystemClock,
        };

        std::thread::scope(|scope| {
            for location in &receiving {
                let (runtime, pickup, stopping, tally) = (&runtime, &*pickup, &*stopping, &*tally);
                scope.spawn(move || {
                    let served =
                        location.serve(runtime, pickup, stopping, |carried| tally.record(carried));
                    if let Err(why) = served {
                        tally.fail(&location.configured.name, why);
                    }
                });
            }
            let (runtime, pickup, stopping, tally) = (&runtime, &*pickup, &*stopping, &*tally);
            scope.spawn(move || pick_up_released(runtime, pickup, stopping, tally));
        });
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linked::{LinkedTransport, Opened};
    use authenticate::AuthenticateError;
    use authorize::{Attempt, Decision};
    use context::{IdentityFacts, Verified};
    use identify::Presented;
    use std::cell::Cell;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};
    use tcp::TcpTransport;
    use transport::{Configured, Transport};
    use xcore::settings::{Applies, Given};
    use xcore::{Layer, Mechanism, mechanism};

    /// ADR-0019 clause 7: where nothing was presented, the circumstance is
    /// the transport identity, and is authenticated as that — claimed, since
    /// nothing cryptographic stands behind a loopback connection.
    struct Circumstance;

    impl Authenticator for Circumstance {
        fn mechanism(&self) -> Mechanism {
            mechanism::circumstance()
        }

        fn verify(&self, _presented: &Presented) -> Result<Verified, AuthenticateError> {
            Ok(Verified::Claimed)
        }
    }

    /// Allows what the gates authenticated. The estate's real policies are
    /// technologies; this is the smallest thing that is not "nothing
    /// configured", which permits nothing.
    struct Open;

    impl Authorizer for Open {
        fn name(&self) -> &str {
            "open"
        }

        fn layer(&self) -> Layer {
            Layer::Transport
        }

        fn decide(&self, _identity: &IdentityFacts, _attempt: &Attempt) -> Option<Decision> {
            Some(Decision::Allowed)
        }
    }

    thread_local! {
        /// How often this test's thread built a tcp transport: startup runs on
        /// the thread that calls it, so each test counts its own.
        static OPENED: Cell<usize> = const { Cell::new(0) };
    }

    fn counted(address: &str, side: Applies, given: &[(String, Given)]) -> Opened {
        OPENED.with(|opened| opened.set(opened.get() + 1));
        Ok(Box::new(TcpTransport::open(address, side, given)?))
    }

    fn linked() -> Linked {
        Linked {
            transports: vec![LinkedTransport::new(TcpTransport::SETTINGS, counted)],
            authenticators: vec![Box::new(Circumstance)],
            policies: vec![Box::new(Open)],
            ..Linked::default()
        }
    }

    const APPLICATION: &str = r#"[application]
name = "Loopback"

[[receive_locations]]
name = "In"

[[send_ports]]
name = "Out"

[[subscriptions]]
id = "onward"
destination = { send-port = "Out" }
filter = "xmip.transport.mechanism = 'circumstance'"
"#;

    /// Node alpha takes both ends of the Application: a tcp Receive Location
    /// on `receive`, and a tcp Send Port to `far`.
    fn node(receive: &str, far: &str) -> String {
        format!(
            r#"[service]
name = "xmip-alpha"
cluster_name = "loopback"
node_name = "alpha"

[[applications]]
name = "Loopback"
document = "loopback.application.toml"

[[applications.receive_locations]]
name = "In"
node = "alpha"
start = true
transport = "xmip-core-transport-tcp"
address = "{receive}"
[applications.receive_locations.settings]
timeout = "100ms"
[applications.receive_locations.accept]
mechanism = ["circumstance"]

[[applications.send_ports]]
name = "Out"
node = "alpha"
start = true
transport = "xmip-core-transport-tcp"
address = "{far}"
"#
        )
    }

    /// A directory of its own holding `configuration` beside the
    /// Application, and the configuration's path.
    fn written(test: &str, configuration: &str) -> PathBuf {
        let directory =
            std::env::temp_dir().join(format!("xmip-running-{test}-{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("a directory");
        std::fs::write(directory.join("loopback.application.toml"), APPLICATION)
            .expect("writes the Application");
        let path = directory.join("alpha.toml");
        std::fs::write(&path, configuration).expect("writes the node");
        path
    }

    fn path_text(path: &Path) -> &str {
        path.to_str().expect("a UTF-8 path")
    }

    /// A loopback address nothing listens on yet.
    fn free_address() -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a free port");
        listener.local_addr().expect("its address").to_string()
    }

    /// Send `payload` to the node, asking again while its Receive Location
    /// has not yet bound — it binds on its first receive, and nothing else
    /// says when that was. Bounded, and never a sleep.
    fn deliver(address: &str, payload: &[u8]) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match TcpTransport::loopback().send(address, payload) {
                Ok(()) => return,
                Err(refused) if refused.retryable && Instant::now() < deadline => {
                    std::thread::yield_now();
                }
                Err(failed) => panic!("the node took nothing at {address}: {failed:?}"),
            }
        }
    }

    #[test]
    fn a_node_carries_every_message_from_its_receive_location_to_the_far_end() {
        const MESSAGES: u32 = 200;
        let far = TcpTransport::loopback();
        let (listener, far_address) = far.bind().expect("the far end binds");
        let receive = free_address();
        let path = written("carries", &node(&receive, &far_address));

        OPENED.with(|opened| opened.set(0));
        let running = Running::start(path_text(&path), linked()).expect("the node starts");

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
            crate::catalogue::declarations().contains_key("xmip-core-transport-tcp"),
            "loading carries the declaration"
        );

        deliver(&receive, b"order 0");
        let first = far.accept_one(&listener).expect("the first arrives");
        assert_eq!(first.bytes, b"order 0");

        let started = Instant::now();
        for message in 1..=MESSAGES {
            let payload = format!("order {message}");
            TcpTransport::loopback()
                .send(&receive, payload.as_bytes())
                .expect("the node takes it");
            let arrived = far.accept_one(&listener).expect("it reaches the far end");
            assert_eq!(arrived.bytes, payload.as_bytes());
        }
        let each = started.elapsed() / MESSAGES;

        let outcomes = running.stop();
        let carried = u64::from(MESSAGES) + 1;
        assert_eq!(outcomes.received, carried);
        assert_eq!(outcomes.routed, carried, "{outcomes:?}");
        assert_eq!(outcomes.sent, carried, "{outcomes:?}");
        assert_eq!(
            outcomes.refused + outcomes.unroutable + outcomes.not_sent,
            0
        );
        // Two loopback connections and the whole message path, per Message —
        // about a millisecond in a debug build on a quiet machine, 2026-09-28.
        // Five is generous for one under load; beyond it, something around
        // the payload is taking longer than its load (the millisecond rule).
        assert!(each < Duration::from_millis(5), "{each:?} per Message");
        let _ = std::fs::remove_dir_all(path.parent().expect("its directory"));
    }

    #[test]
    fn a_location_is_held_to_its_technologys_declaration_as_the_node_starts() {
        let unsound = node(&free_address(), &free_address())
            .replace("timeout = \"100ms\"", "timeout = 5\ncolour = \"lime\"");
        let path = written("declared", &unsound);

        let refused = Running::start(path_text(&path), linked())
            .err()
            .expect("refused");

        assert_eq!(refused.phase, StartupPhase::ValidateStartup);
        assert_eq!(refused.problems.len(), 2, "{:?}", refused.problems);
        for setting in ["\"timeout\"", "\"colour\""] {
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
        let sound = written("declared-sound", &node(&free_address(), &free_address()));
        Running::start(path_text(&sound), linked())
            .expect("the node starts")
            .stop();
        let problems = crate::start::validate(&unsound);
        assert!(
            problems.iter().any(|p| p.contains("\"colour\"")),
            "{problems:?}"
        );
        for written in [path, sound] {
            let _ = std::fs::remove_dir_all(written.parent().expect("its directory"));
        }
    }

    #[test]
    fn a_node_stops_cleanly_and_lets_its_listener_go() {
        let far = TcpTransport::loopback();
        let (listener, far_address) = far.bind().expect("the far end binds");
        let receive = free_address();
        let path = written("stops", &node(&receive, &far_address));
        let running = Running::start(path_text(&path), linked()).expect("the node starts");
        deliver(&receive, b"before the stop");
        far.accept_one(&listener).expect("it reaches the far end");

        let health = running.snapshot();
        assert!(
            health
                .health("xmip:///alpha")
                .iter()
                .all(|record| record.health == Health::Fine),
            "{:?}",
            health.health("xmip:///alpha")
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
        let again = Running::start(path_text(&path), linked()).expect("starts again");
        deliver(&receive, b"after");
        far.accept_one(&listener).expect("it reaches the far end");
        drop(again);
        assert!(
            std::net::TcpStream::connect_timeout(&address, Duration::from_millis(500)).is_err()
        );
        let _ = std::fs::remove_dir_all(path.parent().expect("its directory"));
    }

    #[test]
    fn what_the_program_was_not_built_with_refuses_the_node_at_start() {
        let base = node(&free_address(), &free_address());
        let cases = [
            (
                base.replacen(
                    "transport = \"xmip-core-transport-tcp\"",
                    "transport = \"xmip-core-transport-sftp\"",
                    1,
                ),
                "names the transport 'xmip-core-transport-sftp', which this node was not \
                 built with",
            ),
            (
                base.replace("[\"circumstance\"]", "[\"mutual-tls\"]"),
                "accepts 'mutual-tls', and no authenticator this node was built with verifies it",
            ),
            (
                base.replace(
                    "address = \"127",
                    "contract = \"xmip-core-contract-json\"\naddress = \"127",
                ),
                "holds no Stream to a contract at arrival yet",
            ),
        ];

        for (configuration, reason) in cases {
            let path = written("unlinked", &configuration);
            let refused = Running::start(path_text(&path), linked())
                .err()
                .expect("refused");
            assert_eq!(refused.phase, StartupPhase::ValidateStartup);
            assert!(
                refused.problems.iter().any(|p| p.contains(reason)),
                "{reason}: {:?}",
                refused.problems
            );
        }

        // ADR-0066 clause 1: a filter naming what no route technology this
        // node was built with reads is refused now, not at the first Message.
        let directory = written("unread", &base);
        std::fs::write(
            directory
                .parent()
                .expect("its directory")
                .join("loopback.application.toml"),
            APPLICATION.replace("xmip.transport.mechanism", "party:sender"),
        )
        .expect("writes");
        let refused = Running::start(path_text(&directory), linked())
            .err()
            .expect("refused");
        assert_eq!(refused.phase, StartupPhase::ValidateStartup);
        assert!(
            refused.problems[0].contains("no route technology"),
            "{refused}"
        );
        let _ = std::fs::remove_dir_all(directory.parent().expect("its directory"));
    }

    const LIBRARY_MODULE: &str = "\n[[modules]]\nname = \"contract-rust\"\nstart = true\n\
        [modules.manifest.identity]\nname = \"xmip-core-contract-rust\"\nversion = \"0.1.0\"\n\
        [[modules.manifest.capabilities]]\ncapability = \"contract\"\n\
        execution_host = \"c-abi\"\ntrusted_required = false\n\
        [modules.manifest.entrypoint]\n";

    #[cfg(not(feature = "dynamic-loading"))]
    #[test]
    fn a_library_module_is_refused_where_the_runtime_opens_none() {
        let configuration = format!(
            "{}{LIBRARY_MODULE}library_path = \"xmip_core_contract_rust.dll\"\n",
            node(&free_address(), &free_address())
        );
        let path = written("library", &configuration);

        let refused = Running::start(path_text(&path), linked())
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
            node(&free_address(), &free_address()),
            library.display()
        );
        let path = written("opened", &configuration);

        let running = Running::start(path_text(&path), linked()).expect("the node starts");

        let contract = running
            .capabilities()
            .get("contract")
            .expect("registered once");
        assert_eq!(contract.module, "xmip-core-contract-rust");
        assert_eq!(contract.load, Load::Library(library.clone()));
        assert!(running.host_services().iter().all(HostService::in_process));
        running.stop();
        let _ = std::fs::remove_dir_all(path.parent().expect("its directory"));
    }

    #[test]
    fn a_paused_subscription_holds_at_the_node_and_its_resume_sends_what_it_held_in_order() {
        let far = TcpTransport::loopback();
        let (listener, far_address) = far.bind().expect("the far end binds");
        let receive = free_address();
        let path = written("paused", &node(&receive, &far_address));
        let running = Running::start(path_text(&path), linked()).expect("the node starts");
        deliver(&receive, b"before the pause");
        far.accept_one(&listener).expect("it reaches the far end");

        let pickup = running.pickup();
        assert_eq!(pickup.node(), "xmip:///loopback/node/alpha");
        let standing = &pickup.standing()[0];
        assert_eq!(standing.name, "onward");
        assert_eq!(standing.application, "Loopback");
        assert!(standing.file.ends_with("loopback.application.toml"));
        assert!(standing.configuration.starts_with("[[subscriptions]]"));
        pickup
            .act("onward", observe::Act::Pause, "ilian")
            .expect("paused");
        for n in 1..=3 {
            deliver(&receive, format!("held {n}").as_bytes());
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while pickup.standing()[0].held < 3 && Instant::now() < deadline {
            std::thread::yield_now();
        }
        assert_eq!(pickup.standing()[0].held, 3, "held, not sent");

        pickup
            .act("onward", observe::Act::Resume, "ilian")
            .expect("resumed");
        for n in 1..=3 {
            let arrived = far.accept_one(&listener).expect("it reaches the far end");
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
