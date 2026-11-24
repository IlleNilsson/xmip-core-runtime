//! A Send Location as a node runs it, the node's Send Ports with their
//! policy, and where a Message bound for one waits in the Ledger.
//!
//! Routing decides *that* a Message goes to `SendPort.Billing`. Which
//! Location that is, and whose identity it presents, is configuration — and
//! it is resolved here rather than by routing, because ADR-0019 clause 3
//! keeps the two apart: routing never decides *how* something gets somewhere.
//! A bound Send Port is the Send Location its binding gives it, named as the
//! Port (ADR-0064), or the Send Locations its `send_locations` names, in
//! that order; a Send Port Group reaches each of its Ports by a Journey of
//! its own, opened at its Publication. Each Port's
//! policy — `retry` and `failover` (ADR-0031, amendment 2026-10-01) — is
//! its design's; the Correlation it names is the sequence its Messages
//! pass it in, one at a time per key (`crate::sequence`). Its `retry` is
//! the retry guard its program linked, built once as the node starts
//! ([`guards`]), which judges every try of it that did not send (ADR-0048,
//! amendment 2026-11-14).

use std::collections::BTreeMap;
use std::time::Duration;

use configure::{ConfiguredLocation, DesignedSendPort, SendPortGroup};
use persist::storage::named;
use resilience::{Attempt, Decision, Guard, judged};
use route::Subscriber;
use send::SendChain;
use transport::Transport;
use xcore::Failure;

use crate::departure::{Departed, said};
use crate::linked::RetryGuard;
use crate::sequence::{Point, PointKind};

/// Each Send Port's guards, by its name, in the order they are asked.
pub type SendGuards = BTreeMap<String, Vec<Box<dyn Guard>>>;

/// A Send Location running: its configuration, the chain that resolves the
/// identity it presents (ADR-0006), and the transport built for it once,
/// which keeps its connections and sessions between sends
/// (`transport::pool`).
pub struct Sending {
    pub configured: ConfiguredLocation,
    /// What each send names as its target, as its technology says
    /// (`crate::linked::LinkedTransport::target`): its address in the
    /// technology's own terms, or the destination its settings name.
    pub target: String,
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
    /// The sequences its Messages pass it in: its own, where it names a
    /// set, and those of the Send Locations it may leave by that name one.
    pub points: Vec<&'a Point>,
}

impl Port<'_> {
    /// Whether a Send Location that failed its tries hands on to the next:
    /// `failover = "next"`.
    #[must_use]
    pub fn fails_over(&self) -> bool {
        self.policy
            .and_then(|policy| policy.failover)
            .is_some_and(|failover| failover == configure::Failover::Next)
    }
}

/// Where a destination routing matched is sent.
pub enum Destination<'a> {
    /// A Send Port, or every Port of a Send Port Group in the group's order.
    Ports(Vec<Port<'a>>),
    /// A Work Process. Running one is not built: a Process is compiled at
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
    /// The sequences of the Send Ports, the Send Locations and the Work
    /// Processes that name a Correlation, each by its kind and name.
    pub points: Vec<Point>,
    /// Each Send Port's guards, which judge every try of it that did not
    /// send ([`guards`]).
    pub guards: SendGuards,
}

impl Sends {
    /// How long until the active Send Location of the Send Port `port` is
    /// tried again after its try `number`, which took `elapsed` on the node's
    /// clock and came to `tried`, not sent: the wait the Port's guards ask for, asked as
    /// `resilience::execute` asks after an attempt (ADR-0048, amendment
    /// 2026-11-14), the try's failure retryable only where its transport
    /// said so. None where they let the try stand — a Port with no guards
    /// lets every try stand — and it fails over or is given up.
    #[must_use]
    pub fn again(
        &self,
        port: &str,
        (number, elapsed): (u32, Duration),
        tried: &Departed,
    ) -> Option<Duration> {
        let guards = self.guards.get(port)?;
        let retryable = matches!(
            tried,
            Departed::Failed {
                retryable: true,
                ..
            }
        );
        let attempt = Attempt {
            number,
            elapsed,
            failure: Some(Failure {
                message: said(std::slice::from_ref(tried)),
                retryable,
            }),
        };
        match judged(guards.iter().map(AsRef::as_ref), &attempt) {
            Decision::Wait(after) => Some(after),
            Decision::Proceed | Decision::Refuse(_) | Decision::Fallback => None,
        }
    }

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
            Subscriber::WorkProcess(_) => Destination::Process,
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
    /// them: its Journeys are one per Port, each Message in its Port's queue.
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
        let points = self
            .points
            .iter()
            .filter(|point| match point.kind {
                PointKind::SendPort => point.name == name,
                PointKind::SendLocation => named.contains(&point.name.as_str()),
                _ => false,
            })
            .collect();
        Port {
            name,
            locations: named
                .into_iter()
                .filter_map(|location| self.location(location))
                .collect(),
            policy,
            points,
        }
    }

    fn location(&self, name: &str) -> Option<&Sending> {
        self.locations
            .iter()
            .find(|sending| sending.configured.name == name)
    }
}

/// The queue in the Ledger where the Messages bound for `to` in the cluster
/// at `cluster` (`xmip:///<cluster>`) wait until they are sent: found by
/// the name-based identifier of `<cluster>/<kind>/<name>`, the same on
/// every node, so any node that sends it takes up what another left
/// (`runtime-model.md` section 3, *Work moves by claim*).
#[must_use]
pub fn queue(cluster: &str, to: &Subscriber) -> u128 {
    named(&format!("{cluster}/{}/{}", to.kind(), to.name()))
}

/// Each of `ports`' guards, built once as the node starts from what its
/// program linked: a Port's `retry` as the retry guard `retry` builds, for
/// one try and `attempts` more, `backoff` after each that failed, flat
/// (ADR-0048, amendment 2026-11-14). A Port without `retry` is given none,
/// and is tried once.
///
/// # Errors
/// Each Port stating `retry` where the program linked no retry guard, in
/// words.
pub fn guards(
    ports: &[DesignedSendPort],
    retry: Option<RetryGuard>,
) -> Result<SendGuards, Vec<String>> {
    let mut guards = SendGuards::new();
    let mut problems = Vec::new();
    for port in ports {
        let Some(policy) = &port.retry else {
            continue;
        };
        let Some(built) = retry else {
            problems.push(format!(
                "the Send Port '{}' states a retry, and this node carries no retry guard",
                port.name
            ));
            continue;
        };
        // Refused as the configuration is read where it is no duration
        // (`configure`'s Send Port problems).
        let backoff = xcore::settings::duration(&policy.backoff).unwrap_or(Duration::ZERO);
        let tries = policy.attempts.saturating_add(1);
        guards
            .entry(port.name.clone())
            .or_default()
            .push(built(tries, backoff));
    }
    if problems.is_empty() {
        Ok(guards)
    } else {
        Err(problems)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use configure::{DesignedSendPort, Retry};
    use resilience::Guard;
    use route::Subscriber;

    use super::{Sends, guards};
    use crate::departure::Departed;

    /// The retry guard, as a program links it.
    fn retry(tries: u32, backoff: Duration) -> Box<dyn Guard> {
        Box::new(::retry::Retry::new(tries, backoff))
    }

    /// The Send Port `Out`, retrying `retry`.
    fn out(retry: Option<Retry>) -> DesignedSendPort {
        DesignedSendPort {
            name: "Out".to_string(),
            send_locations: Vec::new(),
            retry,
            failover: None,
            correlation: None,
            prepare: Vec::new(),
            transform: None,
            promote: None,
            demote: None,
            debatch: None,
            requires: Vec::new(),
        }
    }

    /// A try of `Out` its transport failed, `retryable` or not.
    fn failed(retryable: bool) -> Departed {
        Departed::Failed {
            to: Subscriber::SendPort("Out".to_string()),
            retryable,
            detail: "the far end is down".to_string(),
        }
    }

    /// How long after its try `number`, failed `retryable` or not, `Out`
    /// is tried again.
    fn again(sends: &Sends, number: u32, retryable: bool) -> Option<Duration> {
        sends.again("Out", (number, Duration::ZERO), &failed(retryable))
    }

    fn guarded(ports: &[DesignedSendPort]) -> Sends {
        Sends {
            guards: guards(ports, Some(retry)).expect("built"),
            ..Sends::default()
        }
    }

    #[test]
    fn a_retrying_send_port_is_tried_once_and_again_as_often_as_it_says_after_its_backoff() {
        let sends = guarded(&[out(Some(Retry {
            attempts: 2,
            backoff: "5s".to_string(),
        }))]);
        let backoff = Some(Duration::from_secs(5));

        assert_eq!(again(&sends, 1, true), backoff);
        assert_eq!(again(&sends, 2, true), backoff, "flat");
        assert_eq!(
            again(&sends, 3, true),
            None,
            "once, and again twice: the third try stands"
        );
        assert_eq!(
            again(&sends, 1, false),
            None,
            "a permanent failure is never tried again"
        );
        let refused = Departed::NoSuchDestination {
            to: Subscriber::SendPort("Out".to_string()),
        };
        assert_eq!(
            sends.again("Out", (1, Duration::ZERO), &refused),
            None,
            "nor a try that never reached the transport"
        );
    }

    #[test]
    fn a_send_port_without_retry_is_given_no_guard_and_every_try_stands() {
        let sends = guarded(&[out(None)]);
        assert!(sends.guards.is_empty());
        assert_eq!(again(&sends, 1, true), None);
    }

    #[test]
    fn a_retrying_send_port_is_refused_where_the_program_linked_no_retry_guard() {
        let retrying = out(Some(Retry {
            attempts: 1,
            backoff: "1s".to_string(),
        }));
        let refused = guards(&[retrying, out(None)], None).err().expect("refused");
        assert_eq!(
            refused,
            ["the Send Port 'Out' states a retry, and this node carries no retry guard"]
        );
    }
}
