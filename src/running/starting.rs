//! [`Running::start`]: ADR-0018's nine startup phases over a node's
//! configuration and the technologies its program linked, each phase that
//! can refuse doing so before anything serves (`super`'s table).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use configure::{ConfiguredLocation, XmipApplication, XmipConfigurationDocument};
use node::Stage;
use transport::{Guard, Pinned};

use super::serving::{Served, serve};
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
use crate::sending::Sends;
use crate::service::StartupPhase;
use crate::start::read_accepted;
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
    host_services: Vec<HostService>,
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
        let ((document, applications, files), refused) = read_accepted(path)
            .map_err(|unread| Refusal::at(StartupPhase::ReadConfiguration, vec![unread.reason]))?;
        let data = document.service.data_directory(Path::new(path));
        let base = Path::new(path).parent().unwrap_or_else(|| Path::new("."));
        let certificates = certificate_standing::CertificateStanding::configured(&document, base);
        let operate = document.operate.clone();
        let bound = bound_nodes(&document);
        let reaching = crate::storage::plan(&document, path, &linked)?;
        let guard = crate::receive_certificate::guard(&document, Path::new(path))
            .map_err(|problems| Refusal::at(StartupPhase::ValidateStartup, problems))?;
        let Validated {
            tree,
            gates,
            gathering,
            parties,
            host_services,
        } = validated(document, &applications, &mut linked)?;
        cfg_select! {
            feature = "dynamic-loading" => {
                let libraries = crate::library::Libraries::open(&tree.modules_to_start)
                    .map_err(|problems| Refusal::at(StartupPhase::LoadModules, problems))?;
            }
            _ => {
                crate::library::refuse(&tree.modules_to_start)
                    .map_err(|problems| Refusal::at(StartupPhase::LoadModules, problems))?;
            }
        }
        let capabilities = load(&tree, &linked, &gathering)
            .map_err(|problems| Refusal::at(StartupPhase::RegisterCapabilities, problems))?;

        // Xmip Storage before the Locations: a Location's secret is read
        // from its Administration Database as it connects (ADR-0019,
        // amendment 2026-10-29).
        let storage = reaching.open(&linked, &tree.tuning)?;
        let (receiving, sends) = opened(&tree, &linked, (gates, guard, &data), &storage)?;
        let scope = publication::location(&tree.service.cluster_name, &tree.service.node_name);
        let routes = routes(&receiving, &tree);
        let configured = routes.then(|| ConfiguredSubscription::of(&applications, &files));
        let pickup = picked_up(&scope, configured, &storage, &linked)?;
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
        let (send, work) = steps(&tree, &scope, (&storage, &linked), running);
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
        };
        let serving = serve(served, Arc::clone(&stopping), Arc::clone(&tally));

        Ok(Self {
            online: tree.service.online,
            cluster: tree.service.cluster_name,
            node: tree.service.node_name,
            bound,
            capabilities,
            host_services,
            locations,
            not_started,
            stopping,
            serving: Some(serving),
            tally,
            routes,
            pickup,
            send,
            data,
            refused,
            storage,
            operate,
            certificates,
            tuning: tree.tuning,
            configuration: PathBuf::from(path),
            #[cfg(feature = "dynamic-loading")]
            libraries: Some(libraries),
        })
    }
}

/// Phases 2 to 5: what the node starts, bound; every gate, filter and
/// compiled call checked against what the program linked; the Parties lent
/// to this process while it serves (`ffi::event`); the receive policies set
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
    } = check(&tree, linked)
        .map_err(|problems| Refusal::at(StartupPhase::ValidateStartup, problems))?;
    // Lent to this process while the node serves: a program in it is
    // resolved through them, never by a Party it names (`ffi::event`).
    let parties = Arc::new(parties);
    Parties::serve(&parties);
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
        host_services,
    })
}

/// Phase 9's Locations: each Location's transport built once, its handshake
/// read under its own bound, `[tuning] receive_handshake`, apart from each
/// Location's own wait; the keys its far ends presented first kept across
/// restarts under `data` (ADR-0019, amendment 2026-10-28); a secret read
/// from `storage` as a Location connects.
fn opened(
    tree: &ExecutionTree,
    linked: &Linked,
    (gates, guard, data): (Vec<ReceiveGate>, Option<Guard>, &Path),
    storage: &Reached,
) -> Result<(Vec<Receiving>, Sends), Refusal> {
    let guard = guard.map(|guard| guard.handshaking_within(tree.tuning.receive_handshake));
    let pins = Arc::new(Pinned::kept_at(data.join(crate::linked::PINNED)));
    let secrets: Arc<dyn xcore::Secrets> = Arc::new(persist::storage::StoredSecrets(Arc::clone(
        storage.storage(),
    )));
    open(tree, linked, (gates, guard.as_ref(), &pins, &secrets))
        .map_err(|problems| Refusal::at(StartupPhase::AcceptWork, problems))
}

/// The node's send step, registered for the runtime's library, and its work
/// step over the Work Processes `running` opened, both over `storage`.
fn steps(
    tree: &ExecutionTree,
    scope: &str,
    (storage, linked): (&Reached, &Linked),
    running: Vec<crate::work_step::Running>,
) -> (Arc<SendStep>, Arc<WorkStep>) {
    let cluster = publication::cluster_location(&tree.service.cluster_name);
    let send = Arc::new(SendStep::new(
        (&cluster, scope),
        Arc::clone(storage.storage()),
        &tree.tuning,
        linked.audit.clone(),
    ));
    SendStep::register(&send);
    let work = Arc::new(WorkStep::new(
        (&cluster, scope),
        Arc::clone(storage.storage()),
        tree.tuning.work(),
        linked.audit.clone(),
        running,
    ));
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
/// it routes, none where it does not ([`Pickup::routing_none`]).
fn picked_up(
    scope: &str,
    configured: Option<Vec<ConfiguredSubscription>>,
    storage: &Reached,
    linked: &Linked,
) -> Result<Arc<Pickup>, Refusal> {
    let (storage, audit) = (Arc::clone(storage.storage()), linked.audit.clone());
    match configured {
        Some(configured) => Pickup::open(scope, configured, storage, audit),
        None => Pickup::routing_none(scope, storage, audit),
    }
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
