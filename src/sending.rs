//! A Send Location as a node runs it, the node's Send Ports with their
//! policy, and where a Journey bound for one waits in the Ledger.
//!
//! Routing decides *that* a Message goes to `SendPort.Billing`. Which
//! Location that is, and whose identity it presents, is configuration — and
//! it is resolved here rather than by routing, because ADR-0019 clause 3
//! keeps the two apart: routing never decides *how* something gets somewhere.
//! A bound Send Port is the Send Location its binding gives it, named as the
//! Port (ADR-0064), or the Send Locations its `send_locations` names, in
//! that order; a Send Port Group reaches each of its Ports by a Journey of
//! its own, opened at its Publication. Each Port's
//! policy — `retry`, `failover`, `execution_style`, `order_key`,
//! `on_failure` (ADR-0031, amendment 2026-10-01) — is its design's.

use std::time::Duration;

use configure::{ConfiguredLocation, DesignedSendPort, ExecutionStyle, OnFailure, SendPortGroup};
use persist::storage::named;
use route::Subscriber;
use send::SendChain;
use transport::Transport;

/// A Send Location running: its configuration, the chain that resolves the
/// identity it presents (ADR-0006), and the transport built for it once,
/// which keeps its connections and sessions between sends
/// (`transport::pool`).
pub struct Sending {
    pub configured: ConfiguredLocation,
    pub chain: SendChain,
    pub transport: Box<dyn Transport + Send + Sync>,
}

/// A Send Port as this node sends through it: its name, its Send
/// Locations in the order they are tried — none where this node has none —
/// and its policy, where its design states one.
pub struct Port<'a> {
    pub name: &'a str,
    pub locations: Vec<&'a Sending>,
    pub policy: Option<&'a DesignedSendPort>,
}

impl Port<'_> {
    /// How often the active Send Location is tried: once, and again as
    /// often as `retry.attempts` says.
    #[must_use]
    pub fn tries(&self) -> u32 {
        self.policy
            .and_then(|policy| policy.retry.as_ref())
            .map_or(1, |retry| retry.attempts.saturating_add(1))
    }

    /// How long after a failed try the next is due: `retry.backoff`.
    #[must_use]
    pub fn backoff(&self) -> Duration {
        self.policy
            .and_then(|policy| policy.retry.as_ref())
            .and_then(|retry| xcore::settings::duration(&retry.backoff).ok())
            .unwrap_or(Duration::ZERO)
    }

    /// Whether a Send Location that failed its tries hands on to the next:
    /// `failover = "next"`.
    #[must_use]
    pub fn fails_over(&self) -> bool {
        self.policy
            .and_then(|policy| policy.failover)
            .is_some_and(|failover| failover == configure::Failover::Next)
    }

    /// Where the Port is Sequential: the property its sequences are ordered
    /// by — none orders them all as one — and what a sequence does when
    /// one of it fails (`runtime-model.md` section 3, *A claim is not
    /// ordering*).
    #[must_use]
    pub fn sequence(&self) -> Option<(Option<&str>, OnFailure)> {
        let policy = self.policy?;
        if policy.execution_style != Some(ExecutionStyle::Sequential) {
            return None;
        }
        // A Sequential Port states on_failure, or it is refused at startup.
        let on_failure = policy.on_failure.unwrap_or(OnFailure::Block);
        Some((policy.order_key.as_deref(), on_failure))
    }
}

/// Where a destination routing matched is sent.
pub enum Destination<'a> {
    /// A Send Port, or every Port of a Send Port Group in the group's order.
    Ports(Vec<Port<'a>>),
    /// An Xmip Process. Running one is not built: a Process is compiled at
    /// design time into a module a node loads (ADR-0066 clause 4), and none
    /// is yet.
    Process,
    /// A Send Port Group no bound Application declares.
    Nowhere,
}

/// The node's Send Locations, the Send Ports of the Applications it binds
/// with their policy, and their Send Port Groups.
#[derive(Default)]
pub struct Sends {
    pub locations: Vec<Sending>,
    pub groups: Vec<SendPortGroup>,
    pub ports: Vec<DesignedSendPort>,
}

impl Sends {
    /// Where `to` is sent on this node.
    #[must_use]
    pub fn to<'a>(&'a self, to: &'a Subscriber) -> Destination<'a> {
        match to {
            Subscriber::SendPort(port) => Destination::Ports(vec![self.port(port)]),
            Subscriber::SendGroup(group) => self
                .groups
                .iter()
                .find(|declared| &declared.name == group)
                .map_or(Destination::Nowhere, |group| {
                    Destination::Ports(group.send_ports.iter().map(|p| self.port(p)).collect())
                }),
            Subscriber::Process(_) => Destination::Process,
        }
    }

    /// Whether this node sends what is bound for `to`: a Send Port, or a
    /// Send Port Group, every Port of which has a Send Location here. What
    /// it does not send waits in the Ledger for a node that does.
    #[must_use]
    pub fn serves(&self, to: &Subscriber) -> bool {
        match self.to(to) {
            Destination::Ports(ports) => {
                !ports.is_empty() && ports.iter().all(|port| !port.locations.is_empty())
            }
            Destination::Process | Destination::Nowhere => false,
        }
    }

    /// Every Send Port this node sends, by the Ports its Applications
    /// declare and its Locations serve. A Send Port Group is not among
    /// them: its Journeys are one per Port, each in its Port's queue.
    #[must_use]
    pub fn served(&self) -> Vec<Subscriber> {
        // A Send Port by its design, or a bound one by the Location named as
        // it — never a Location a Port's `send_locations` names.
        let named = |name: &str| {
            self.ports
                .iter()
                .any(|port| port.send_locations.iter().any(|location| location == name))
        };
        let mut names: Vec<&str> = self.ports.iter().map(|port| port.name.as_str()).collect();
        for location in &self.locations {
            let name = location.configured.name.as_str();
            if !names.contains(&name) && !named(name) {
                names.push(name);
            }
        }
        names
            .into_iter()
            .map(|name| Subscriber::SendPort(name.to_string()))
            .filter(|to| self.serves(to))
            .collect()
    }

    /// The Send Port `name` as this node sends through it.
    #[must_use]
    pub fn port<'a>(&'a self, name: &'a str) -> Port<'a> {
        let policy = self.ports.iter().find(|port| port.name == name);
        let named: Vec<&str> = match policy {
            Some(policy) if !policy.send_locations.is_empty() => {
                policy.send_locations.iter().map(String::as_str).collect()
            }
            _ => vec![name],
        };
        Port {
            name,
            locations: named
                .into_iter()
                .filter_map(|location| self.location(location))
                .collect(),
            policy,
        }
    }

    fn location(&self, name: &str) -> Option<&Sending> {
        self.locations
            .iter()
            .find(|sending| sending.configured.name == name)
    }
}

/// The queue in the Ledger where the Journeys bound for `to` in the cluster
/// at `cluster` (`xmip:///<cluster>`) wait until they are sent: found by
/// the name-based identifier of `<cluster>/<kind>/<name>`, the same on
/// every node, so any node that sends it takes up what another left
/// (`runtime-model.md` section 3, *Work moves by claim*).
#[must_use]
pub fn queue(cluster: &str, to: &Subscriber) -> u128 {
    named(&format!("{cluster}/{}/{}", to.kind(), to.name()))
}
