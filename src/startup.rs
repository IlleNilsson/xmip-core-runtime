//! The work of startup phases 3 to 9 that only the program starting a node
//! can answer (ADR-0018): whether what the configuration names is what the
//! program was built with, which Host Services and capabilities that is, and
//! each Location's transport built once. `running.rs` runs them in order.

use std::collections::BTreeSet;

use authenticate::Authenticator;
use configure::ConfiguredLocation;
use route::{CONTEXT, Gathering, Source, split};
use transport::NodeLocation;
use xcore::settings::Applies;

use crate::capability_registry::{CapabilityRegistry, Load};
use crate::catalogue::{self, Capability};
use crate::execution_tree::ExecutionTree;
use crate::host::HostService;
use crate::linked::Linked;
use crate::receiving::{ReceiveGate, Receiving};
use crate::running::publication::location;
use crate::sending::{Sending, Sends};

/// What startup phase 3 found the configuration needs of what was linked.
pub(crate) struct Checked {
    pub(crate) gates: Vec<ReceiveGate>,
    pub(crate) gathering: Gathering,
}

/// Startup phase 3's checks of what only the program can answer: that every
/// started Location's transport, every accepted mechanism and every name a
/// filter uses is one this node was built with.
pub(crate) fn check(tree: &ExecutionTree, linked: &Linked) -> Result<Checked, Vec<String>> {
    let mut problems = Vec::new();

    for (stage, location) in started(tree) {
        if linked.transport(&location.transport).is_none() {
            problems.push(format!(
                "the {stage} '{}' names the transport '{}', which this node was not built with",
                location.name, location.transport
            ));
        }
        if let Some(contract) = &location.contract {
            problems.push(format!(
                "the {stage} '{}' names the contract '{contract}', and this runtime holds no \
                 Stream to a contract at arrival yet",
                location.name
            ));
        }
    }

    let authenticators: Vec<&dyn Authenticator> =
        linked.authenticators.iter().map(AsRef::as_ref).collect();
    let mut gates = Vec::new();
    for location in &tree.receive_locations_to_start {
        match ReceiveGate::of(location, &authenticators) {
            Ok(gate) => gates.push(gate),
            Err(refused) => problems.extend(refused),
        }
    }

    // ADR-0066 clause 1: a filter is compiled as the node starts, and one
    // naming what no route technology this node was built with reads is
    // refused now, not at the first Message.
    let sources: Vec<&dyn Source> = linked.sources.iter().map(AsRef::as_ref).collect();
    let gathering = Gathering::of(&sources, &tree.subscriptions);
    problems.extend(
        gathering
            .refusals()
            .map(|refused| format!("a Subscription's filter cannot be read: {refused}")),
    );

    if problems.is_empty() {
        Ok(Checked { gates, gathering })
    } else {
        Err(problems)
    }
}

/// Startup phase 5: the Host Service this process is, started; any other a
/// Module needs is refused, since this node starts no Host Process of its own
/// yet (ADR-0018 clause 3).
pub(crate) fn start_host_services(services: &mut [HostService]) -> Result<(), Vec<String>> {
    let mut problems = Vec::new();
    for service in services {
        if service.in_process() {
            service.start();
        } else {
            problems.push(format!(
                "{} Module(s) need a {}, a Host Service in a process of its own, and this \
                 node starts none yet",
                service.plan.modules.len(),
                service.plan.host_type
            ));
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems)
    }
}

/// Startup phases 6 and 7 for what was linked, and 7 for what was opened:
/// each technology the configuration uses, loaded once — its declaration
/// carried into the catalogue, so every surface's validation in this process
/// reads it too — and each capability registered once.
pub(crate) fn load(
    tree: &ExecutionTree,
    linked: &Linked,
    gathering: &Gathering,
) -> Result<CapabilityRegistry, Vec<String>> {
    let mut registry = CapabilityRegistry::default();
    let mut problems = Vec::new();
    let mut register = |capability: String, module: &str, load: Load| {
        if let Err(problem) = registry.register(&capability, module, load) {
            problems.push(problem);
        }
    };

    let used: BTreeSet<&str> = started(tree)
        .map(|(_, location)| location.transport.as_str())
        .collect();
    for linked in linked
        .transports
        .iter()
        .filter(|t| used.contains(t.technology()))
    {
        catalogue::carry(Capability::Transport, linked.settings());
        let technology = linked.technology();
        register(format!("transport:{technology}"), technology, Load::Linked);
    }

    let read: BTreeSet<&str> = gathering
        .properties()
        .map(|property| split(property).0)
        .filter(|technology| *technology != CONTEXT)
        .collect();
    for source in linked
        .sources
        .iter()
        .filter(|s| read.contains(s.technology()))
    {
        register(
            format!("route:{}", source.technology()),
            source.technology(),
            Load::Linked,
        );
    }

    let accepted: BTreeSet<&str> = tree
        .receive_locations_to_start
        .iter()
        .flat_map(|location| location.accept.mechanism.iter().map(String::as_str))
        .collect();
    for mechanism in &accepted {
        register(format!("authenticate:{mechanism}"), mechanism, Load::Linked);
    }
    for policy in &linked.policies {
        register(
            format!("authorize:{}", policy.name()),
            policy.name(),
            Load::Linked,
        );
    }
    for identifier in &linked.transport_identifiers {
        let mechanism = identifier.mechanism();
        let name = mechanism.name();
        register(format!("identify:transport:{name}"), name, Load::Linked);
    }
    for identifier in &linked.message_identifiers {
        let mechanism = identifier.mechanism();
        let name = mechanism.name();
        register(format!("identify:message:{name}"), name, Load::Linked);
    }

    for module in &tree.modules_to_start {
        let path = crate::library::library(module).unwrap_or_default();
        if let Err(problem) =
            registry.register_module(&module.manifest, &Load::Library(path.into()))
        {
            problems.push(problem);
        }
    }

    if problems.is_empty() {
        Ok(registry)
    } else {
        Err(problems)
    }
}

/// Startup phase 9's first half: each started Location's transport built
/// once, from its address and settings, given the node's location (the
/// owner's *Option A*, 2026-10-03: the runtime gives every transport its
/// node's identity once, as it builds it), and held to the direction it
/// serves.
pub(crate) fn open(
    tree: &ExecutionTree,
    linked: &Linked,
    gates: Vec<ReceiveGate>,
) -> Result<(Vec<Receiving>, Sends), Vec<String>> {
    let node = NodeLocation::new(location(
        &tree.service.cluster_name,
        &tree.service.node_name,
    ));
    let mut problems = Vec::new();
    let mut built = |location: &ConfiguredLocation, side: Applies| {
        let technology = linked.transport(&location.transport)?;
        match technology.open(location, side, &node) {
            Ok(transport) => {
                let serves = match side {
                    Applies::Receive => transport.directions().receives(),
                    _ => transport.directions().sends(),
                };
                if serves {
                    Some(transport)
                } else {
                    problems.push(format!(
                        "the Location '{}': {} does not {} (ADR-0010)",
                        location.name,
                        location.transport,
                        if side == Applies::Receive {
                            "receive"
                        } else {
                            "send"
                        }
                    ));
                    None
                }
            }
            Err(failure) => {
                problems.push(format!(
                    "the Location '{}': {}",
                    location.name, failure.message
                ));
                None
            }
        }
    };

    let receiving: Vec<Receiving> = tree
        .receive_locations_to_start
        .iter()
        .zip(gates)
        .filter_map(|(configured, gate)| {
            built(configured, Applies::Receive).map(|transport| Receiving {
                configured: configured.clone(),
                gate,
                transport,
                limits: tree.tuning.receive(),
            })
        })
        .collect();
    let locations = tree
        .send_locations_to_start
        .iter()
        .filter_map(|configured| {
            built(configured, Applies::Send).map(|transport| Sending {
                configured: configured.clone(),
                chain: send::SendChain::default(),
                transport,
            })
        })
        .collect();

    if problems.is_empty() {
        Ok((
            receiving,
            Sends {
                locations,
                groups: tree.send_port_groups.clone(),
            },
        ))
    } else {
        Err(problems)
    }
}

/// Every Location the tree starts, with its stage.
fn started(tree: &ExecutionTree) -> impl Iterator<Item = (&'static str, &ConfiguredLocation)> {
    tree.receive_locations_to_start
        .iter()
        .map(|location| ("Receive Location", location))
        .chain(
            tree.send_locations_to_start
                .iter()
                .map(|location| ("Send Location", location)),
        )
}
