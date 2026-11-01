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
        // The rate a thread's processor time is read at, measured now, so
        // it never lands in a Message's own share (`xcore::spent`).
        xcore::processor_time::ProcessorTime::calibrate();
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
