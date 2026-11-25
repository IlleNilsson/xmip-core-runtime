//! [`Running::start`]: ADR-0018's nine startup phases over one slice of a
//! node's configuration and the technologies its program linked, each phase
//! that can refuse doing so before anything serves (`super`'s table). What
//! would serve is built and held; serving begins at the node's activation
//! (`super::activation`; ADR-0031, amendment 2026-11-12).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use configure::{ConfiguredLocation, XmipApplication, XmipConfigurationDocument};
use node::Stage;
use transport::{Guard, Pinned};
use xcore::{Clock, SystemClock};

use super::activation::Attempt;
use super::serving::Served;
use super::{Refusal, Running, certificate_standing, origin, publication};
use crate::budget::NodeBudget;
use crate::configured_subscription::ConfiguredSubscription;
use crate::execution_tree::{ExecutionTree, build_execution_tree};
use crate::host::{self, HostService};
use crate::linked::Linked;
use crate::outcome::Tally;
use crate::parties::Parties;
use crate::pickup::Pickup;
use crate::receiving::{ReceiveGate, Receiving};
use crate::send_step::SendStep;
use crate::sending::{SendGuards, Sends};
use crate::service::StartupPhase;
use crate::startup::{Checked, check, load, open, start_host_services};
use crate::stopping::Stopping;
use crate::storage::Reached;
use crate::work_step::WorkStep;

/// What phases 2 to 5 made of the configuration: the tree, what its gates
/// check, the Parties lent to the process, and the Host Services started.
struct Validated {
    tree: ExecutionTree,
    gates: Vec<ReceiveGate>,
    gathering: route::Gathering,
    parties: Arc<Parties>,
    guards: SendGuards,
    host_services: Vec<HostService>,
}

impl Running {
    /// Start the node configured at `path` by the slice `attempt` tries,
    /// with the technologies `linked`, serving nothing until
    /// [`Running::activate`].
    ///
    /// Everything that can refuse does so before anything serves: a
    /// configuration that names what the program was not built with, a
    /// Location its technology's declaration refuses, a filter that does not
    /// compile, a Module that will not load, a Storage node that does not
    /// open. What serves, once activated, carries every Stream through
    /// arrival, routing and departure. Dropped unactivated, it lets go of
    /// everything it opened.
    ///
    /// # Errors
    /// The phase that refused the slice, and every problem it found there.
    pub fn start(path: &str, attempt: Attempt, mut linked: Linked) -> Result<Self, Refusal> {
        // The rate a thread's processor time is read at, measured now, so
        // it never lands in a Message's own share (`xcore::spent`).
        xcore::processor_time::ProcessorTime::calibrate();
        let (document, applications, files) = crate::start::parsed(path, &attempt.slice.text)
            .map_err(|unread| Refusal::at(StartupPhase::ReadConfiguration, vec![unread.reason]))?;
        let data = document.service.data_directory(Path::new(path));
        let provision = document.provision.clone();
        let base = Path::new(path).parent().unwrap_or_else(|| Path::new("."));
        let certificates = certificate_standing::CertificateStanding::configured(&document, base);
        let operate = document.operate.clone();
        let bound = bound_nodes(&document);
        // Read once more as the storage plan below refuses words that are no
        // role: by then this is the node's declaration.
        let roles =
            node::NodeRole::declared(document.roles.as_deref().unwrap_or("")).unwrap_or_default();
        // Its Node capabilities, read as words once (ADR-0056, amendment
        // 2026-11-24): a slice naming one that is none is refused here.
        let node_capabilities = node::Capability::node_capabilities(&document.capabilities)
            .map_err(|refused| Refusal::at(StartupPhase::ReadConfiguration, vec![refused]))?;
        let reaching = crate::storage::plan(&document, path, &linked)?;
        let guard = crate::receive_certificate::guard(&document, Path::new(path))
            .map_err(|problems| Refusal::at(StartupPhase::ValidateStartup, problems))?;
        let Validated {
            tree,
            gates,
            gathering,
            parties,
            guards,
            host_services,
        } = validated(document, &applications, &mut linked)?;
        cfg_select! {
            feature = "dynamic-loading" => {
                let libraries = crate::library::Libraries::open(&tree.modules_to_start, base)
                    .map_err(|problems| Refusal::at(StartupPhase::LoadModules, problems))?;
            }
            _ => {
                crate::library::refuse(&tree.modules_to_start)
                    .map_err(|problems| Refusal::at(StartupPhase::LoadModules, problems))?;
            }
        }
        let capabilities = load(&tree, &linked, &gathering, base)
            .map_err(|problems| Refusal::at(StartupPhase::RegisterCapabilities, problems))?;

        // Xmip Storage before the Locations: a Location's secret is read
        // from its Administration Database as it connects (ADR-0019,
        // amendment 2026-10-29).
        let storage = reaching.open(&linked, &tree.tuning)?;
        // The node's one Clock: what its message path, its Locations, its
        // pickup and its steps tell time by (ADR-0068, amendment 2026-11-15).
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        // Which start of the node this is: the process its membership row
        // is keyed by, drawn once, so the row and every Location's
        // transport carry the one (ADR-0024, amendment 2026-11-22).
        let process = crate::membership::process();
        let handed = (gates, (guards, process), guard, data.as_path());
        let (receiving, sends) = opened(&tree, &linked, handed, &storage, &clock)?;
        let scope = publication::location(&tree.service.cluster_name, &tree.service.node_name);
        let routes = routes(&receiving, &tree);
        let configured = routes.then(|| ConfiguredSubscription::of(&applications, &files));
        let pickup = picked_up(&scope, configured, (&storage, &linked), &clock)?;
        accepted_only(&mut linked, &receiving);
        let locations = locations(&receiving, &sends, &tree);
        let not_started = tree.not_started();
        let running = cfg_select! {
            feature = "dynamic-loading" => {
                crate::work_step::opened(
                    &tree,
                    &publication::cluster_location(&tree.service.cluster_name),
                    &libraries,
                    &linked,
                )
                .map_err(|problems| Refusal::at(StartupPhase::LoadModules, problems))?
            }
            _ => Vec::new(),
        };
        let (send, work) = steps(&tree, &scope, (&storage, &linked), (running, &clock));
        let stopping = Arc::new(Stopping::default());
        let received = receiving.iter().map(|one| one.configured.name.as_str());
        let tally = Arc::new(Tally::of(received, &tree.subscriptions));
        let served = Served {
            storage: Arc::clone(storage.storage()),
            chunk: storage.chunk(),
            origin: origin(linked.audit.as_ref(), &scope),
            linked,
            gathering,
            subscriptions: tree.subscriptions,
            parties: Arc::clone(&parties),
            pickup: Arc::clone(&pickup),
            sends,
            send: Arc::clone(&send),
            work: Arc::clone(&work),
            budget: NodeBudget::of(&tree.tuning),
            receiving,
            clock: Arc::clone(&clock),
        };

        Ok(Self {
            node_capabilities,
            cluster: tree.service.cluster_name,
            node: tree.service.node_name,
            bound,
            roles,
            capabilities,
            host_services,
            locations,
            not_started,
            stopping,
            served: Some(served),
            serving: None,
            tally,
            pickup,
            send,
            work,
            data,
            process,
            numbered: None,
            attempt,
            standing: None,
            provision,
            storage,
            membership: None,
            unregistered: None,
            operate,
            operated: std::sync::OnceLock::new(),
            monitoring: std::sync::OnceLock::new(),
            acts: std::sync::Mutex::default(),
            certificates,
            tuning: tree.tuning,
            configuration: PathBuf::from(path),
            clock,
            #[cfg(feature = "dynamic-loading")]
            libraries: Some(libraries),
        })
    }
}

/// Phases 2 to 5: what the node starts, bound; every gate, filter and
/// compiled call checked against what the program linked; the Parties lent
/// to this process while it serves (the operate library's `ffi::event`), and its connects' SYN
/// retransmission (`net::retransmit_by`); the receive policies set
/// up from the Locations it starts, before the capabilities are registered;
/// and the Host Services its Modules need, started.
fn validated(
    document: XmipConfigurationDocument,
    applications: &[XmipApplication],
    linked: &mut Linked,
) -> Result<Validated, Refusal> {
    let declared = linked.declarations();
    // ADR-0066, amendment 2026-10-22: a call to a compiled unit is read and
    // validated, and running one is decided, not built.
    let unrun = configure::step::unrun(&document, applications);
    if !unrun.is_empty() {
        return Err(Refusal::at(StartupPhase::ValidateStartup, unrun));
    }
    let (tree, _) = build_execution_tree(document, applications, &declared)
        .map_err(|report| Refusal::at(StartupPhase::ValidateStartup, report.errors))?;
    let Checked {
        gates,
        gathering,
        parties,
        guards,
    } = check(&tree, linked)
        .map_err(|problems| Refusal::at(StartupPhase::ValidateStartup, problems))?;
    // Lent to this process while the node serves: a program in it is
    // resolved through them, never by a Party it names (the operate library's
    // `ffi::event`).
    let parties = Arc::new(parties);
    Parties::serve(&parties);
    // Lent the same way: every TCP connect the process makes from here on,
    // Xmip Storage's first, sends a SYN nobody answered again as the node's
    // `[tuning]` says, and a refusal is answered at once (`net::connect`).
    net::retransmit_by(tree.tuning.retransmission());
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
    let manifests: Vec<_> = tree
        .modules_to_start
        .iter()
        .map(|module| module.manifest.clone())
        .collect();
    let mut host_services = host::plan(&manifests);
    start_host_services(&mut host_services)
        .map_err(|problems| Refusal::at(StartupPhase::StartHostServices, problems))?;
    Ok(Validated {
        tree,
        gates,
        gathering,
        parties,
        guards,
        host_services,
    })
}

/// Phase 9's Locations: each Location's transport built once, on the start
/// `guards` carries with the Send Ports' guards, its handshake read under
/// its own bound, `[tuning] receive_handshake`, apart from each Location's
/// own wait; the keys its far ends presented first kept across
/// restarts under `data` (ADR-0019, amendment 2026-10-28); a secret read
/// from `storage` as a Location connects; its spans counted on `clock`.
fn opened(
    tree: &ExecutionTree,
    linked: &Linked,
    (gates, guards, guard, data): (Vec<ReceiveGate>, (SendGuards, u128), Option<Guard>, &Path),
    storage: &Reached,
    clock: &Arc<dyn Clock>,
) -> Result<(Vec<Receiving>, Sends), Refusal> {
    let guard = guard.map(|guard| guard.handshaking_within(tree.tuning.receive_handshake));
    let pins = Arc::new(Pinned::kept_at(data.join(crate::linked::PINNED)));
    let sharing: Arc<dyn transport::Sharing> = Arc::new(transport::Shared::default());
    let secrets: Arc<dyn xcore::Secrets> = Arc::new(persist::storage::StoredSecrets(Arc::clone(
        storage.storage(),
    )));
    open(
        tree,
        linked,
        (gates, guard.as_ref(), &pins, &sharing, &secrets, clock),
        guards,
    )
    .map_err(|problems| Refusal::at(StartupPhase::AcceptWork, problems))
}

/// The node's send step, registered for the operate library, and its work
/// step over the Work Processes `running` opened, both over `storage`, each
/// step's decisions — scans, timers, leases, retries due — on `clock`.
fn steps(
    tree: &ExecutionTree,
    scope: &str,
    (storage, linked): (&Reached, &Linked),
    (running, clock): (Vec<crate::work_step::Running>, &Arc<dyn Clock>),
) -> (Arc<SendStep>, Arc<WorkStep>) {
    let cluster = publication::cluster_location(&tree.service.cluster_name);
    let send = Arc::new(SendStep::new(
        (&cluster, scope),
        Arc::clone(storage.storage()),
        &tree.tuning,
        (linked.audit.clone(), Arc::clone(clock)),
    ));
    SendStep::register(&send);
    let work = WorkStep::new(
        (&cluster, scope),
        Arc::clone(storage.storage()),
        tree.tuning.work(),
        linked.audit.clone(),
        running,
    );
    let work = Arc::new(work.timed_by(Arc::clone(clock)));
    WorkStep::register(&work);
    (send, work)
}

/// Whether the node routes: a Receive Location starts, whose receive cycle
/// publishes and routes each Stream (`message_path`), or a Work Process
/// runs. Every slice carries every Subscription, so holding one says
/// nothing (ADR-0056, amendment 2026-10-01; ADR-0018, amendment
/// 2026-11-11).
fn routes(receiving: &[Receiving], tree: &ExecutionTree) -> bool {
    !receiving.is_empty() || !tree.work_processes_to_start.is_empty()
}

/// The node's Subscriptions as an operator pauses them: `configured` where
/// it routes, none where it does not ([`Pickup::routing_none`]); a queue
/// read again waits on `clock`.
fn picked_up(
    scope: &str,
    configured: Option<Vec<ConfiguredSubscription>>,
    (storage, linked): (&Reached, &Linked),
    clock: &Arc<dyn Clock>,
) -> Result<Arc<Pickup>, Refusal> {
    let (storage, audit) = (Arc::clone(storage.storage()), linked.audit.clone());
    Pickup::timed_by(scope, configured, storage, (audit, Arc::clone(clock)))
        .map_err(|problem| Refusal::at(StartupPhase::AcceptWork, vec![problem]))
}

/// Only what the configuration named goes on: the authenticators its
/// Receive Locations accept. Policies and identifiers are consulted at
/// every gate, and no configuration selects among them yet; the receive
/// policies were set up from the Locations already.
fn accepted_only(linked: &mut Linked, receiving: &[Receiving]) {
    let accepted: BTreeSet<String> = receiving
        .iter()
        .flat_map(|receiving| receiving.configured.accept.mechanism.clone())
        .collect();
    linked
        .authenticators
        .retain(|authenticator| accepted.contains(authenticator.mechanism().name()));
}

/// Every Location the node started: its stage, where it is published
/// beneath that stage (`ExecutionTree::beneath`), and its configuration.
fn locations(
    receiving: &[Receiving],
    sends: &Sends,
    tree: &ExecutionTree,
) -> Vec<(Stage, String, ConfiguredLocation)> {
    let at = |stage: Stage, configured: &ConfiguredLocation| {
        (
            stage,
            tree.beneath(stage, &configured.name),
            configured.clone(),
        )
    };
    receiving
        .iter()
        .map(|r| at(Stage::Receive, &r.configured))
        .chain(
            sends
                .locations
                .iter()
                .map(|s| at(Stage::Send, &s.configured)),
        )
        .collect()
}

/// The nodes the cluster's bindings place a Receive Location or a Send Port
/// on: the nodes that hand work on through Xmip Storage, and the only ones
/// a Storage node draws traffic from and to (`publication::drawn`). A
/// certificate of node standing naming any other — one from an authority
/// another cluster shares, a host name an outside authority issued — is no
/// node of this cluster (ADR-0052, amendment 2026-11-11).
fn bound_nodes(document: &XmipConfigurationDocument) -> Vec<String> {
    let bound: BTreeSet<&str> = document
        .applications
        .iter()
        .flat_map(|binding| binding.receive_locations.iter().chain(&binding.send_ports))
        .map(|location| location.node.as_str())
        .collect();
    bound.into_iter().map(str::to_string).collect()
}
