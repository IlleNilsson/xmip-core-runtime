//! The departure path: what a Host Service does with a Message that is going
//! somewhere.
//!
//! The mirror of [`crate::arrival`], and the same shape. A Stream arrives at a
//! Receive Location; a Message departs from a Send Location. Both are gated,
//! both are recorded, and the vocabulary is deliberately symmetric because an
//! operator watching an estate is reading one board.
//!
//! ```text
//! a Journey's destination   a Send Port, or every Port of a Group
//!   -> resolve   its Send Locations on this node, in configured order
//!   -> authorize may this identity still send, now
//!   -> identity  whose identity Xmip presents, per ADR-0006
//!   -> depart    through the Location's transport, built once
//! ```
//!
//! Authorization runs again here rather than being inherited from arrival.
//! Time has passed — a Process may have waited days for a human — and what was
//! true then is never a licence to act now.
//!
//! **One pass, never a wait.** [`depart_to`] tries each Port once on its
//! active Send Location and fails over at once where the Port says so; a
//! Location that may be tried again after its backoff is left waiting in
//! the [`Progress`] the send step keeps, never slept on here
//! (`runtime-model.md` section 10: *A retry waiting for its backoff holds no
//! thread*).

use std::collections::BTreeMap;

use authorize::{Action, Attempt, Decision, authorize};
use context::IdentityFacts;
use route::Subscriber;
use send::SendLevel;
use xcore::Purpose;

use crate::generation::ReceivedWork;
use crate::message_path::Runtime;
use crate::sending::{Destination, Port, Sending};

/// What became of one Message on its way out to one destination.
#[derive(Clone, Debug)]
pub enum Departed {
    Sent {
        to: Subscriber,
        /// Which artifact decided the identity presented, or `None` where
        /// nothing in the chain declared one.
        presented_from: Option<SendLevel>,
        /// The value of the identity the chain resolved to, as its Party
        /// holds it for sending (ADR-0006). The transport's `send` takes no
        /// identity, so a Location presents what its own settings give it;
        /// this records what the chain decided.
        presented: Option<String>,
    },
    /// Routing named a destination this node has no Send Location for.
    ///
    /// A Send Port bound to another node, or one no configuration gives a
    /// Location: the same class of mistake `never_satisfiable` catches on the
    /// receive side, found here at run time.
    NoSuchDestination { to: Subscriber },
    /// Routing matched an Xmip Process, and this runtime runs none yet: a
    /// Process is compiled at design time into a module a node loads
    /// (ADR-0066 clause 4).
    ProcessNotRun { to: Subscriber },
    /// Authorized to arrive, and not authorized to leave this way.
    ///
    /// The two are different questions and time may have passed between them.
    NotPermitted { to: Subscriber, decision: Decision },
    /// The transport tried and failed. `retryable` is the transport's answer,
    /// not the runtime's: only it knows whether a refused connection is a
    /// restart away from working.
    Failed {
        to: Subscriber,
        retryable: bool,
        detail: String,
    },
}

impl Departed {
    #[must_use]
    pub const fn sent(&self) -> bool {
        matches!(self, Self::Sent { .. })
    }
}

/// Where one Port stands in a Journey's send, across passes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PortProgress {
    /// Sent: not tried again.
    pub sent: bool,
    /// The active Send Location, by its place in the Port's order.
    pub location: usize,
    /// How often the active Location has been tried.
    pub tries: u32,
    /// Every Location failed its tries: why, in words. Not tried again.
    pub given_up: Option<String>,
}

impl PortProgress {
    /// Still to be tried, after its backoff.
    #[must_use]
    pub const fn waiting(&self) -> bool {
        !self.sent && self.given_up.is_none()
    }
}

/// Where a Journey's send stands, Port by Port: what the send step keeps
/// between passes, so a retry tries again where the last pass left off.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Progress {
    pub ports: BTreeMap<String, PortProgress>,
}

impl Progress {
    /// Every Port sent.
    #[must_use]
    pub fn delivered(&self) -> bool {
        !self.ports.is_empty() && self.ports.values().all(|port| port.sent)
    }

    /// Some Port still to be tried after its backoff.
    #[must_use]
    pub fn waiting(&self) -> bool {
        self.ports.values().any(PortProgress::waiting)
    }

    /// Why the Ports that gave up did, in words.
    #[must_use]
    pub fn reasons(&self) -> String {
        self.ports
            .iter()
            .filter_map(|(port, progress)| {
                progress
                    .given_up
                    .as_ref()
                    .map(|why| format!("{port}: {why}"))
            })
            .collect::<Vec<_>>()
            .join("; ")
    }
}

/// One pass of a Message to `to`: every Port not yet sent, or given up,
/// tried once on its active Send Location, failing over at once to the
/// next where its policy says `failover = "next"`, `progress` keeping where
/// each stands. The departures of this pass, one per Location tried. A
/// Location that may be tried again is left waiting, its backoff the send
/// step's to keep.
pub fn depart_to(
    runtime: &Runtime<'_>,
    work: &ReceivedWork,
    facts: &IdentityFacts,
    to: &Subscriber,
    progress: &mut Progress,
) -> Vec<Departed> {
    match runtime.sends.to(to) {
        Destination::Ports(ports) => ports
            .into_iter()
            .flat_map(|port| {
                let standing = progress.ports.entry(port.name.to_string()).or_default();
                if standing.waiting() {
                    depart_port(runtime, (work, facts), &port, standing)
                } else {
                    Vec::new()
                }
            })
            .collect(),
        Destination::Process => vec![Departed::ProcessNotRun { to: to.clone() }],
        Destination::Nowhere => {
            let to = to.clone();
            progress.ports.entry(to.to_string()).or_default().given_up =
                Some(format!("no Send Port Group {} is declared", to.name()));
            vec![Departed::NoSuchDestination { to }]
        }
    }
}

/// One Port's part of a pass: its active Location tried, and the next
/// after it where it fails over.
fn depart_port(
    runtime: &Runtime<'_>,
    (work, facts): (&ReceivedWork, &IdentityFacts),
    port: &Port<'_>,
    standing: &mut PortProgress,
) -> Vec<Departed> {
    let to = Subscriber::SendPort(port.name.to_string());
    let mut departed = Vec::new();
    loop {
        let Some(sending) = port.locations.get(standing.location) else {
            standing.given_up = Some(format!("no Send Location for {to} on this node"));
            departed.push(Departed::NoSuchDestination { to });
            return departed;
        };
        let one = depart_one(runtime, work, facts, to.clone(), sending);
        standing.tries += 1;
        let again = match &one {
            Departed::Sent { .. } => {
                standing.sent = true;
                departed.push(one);
                return departed;
            }
            Departed::Failed { retryable, .. } => *retryable,
            _ => false,
        };
        let said = said(std::slice::from_ref(&one));
        departed.push(one);
        if again && standing.tries < port.tries() {
            return departed;
        }
        if port.fails_over() && standing.location + 1 < port.locations.len() {
            standing.location += 1;
            standing.tries = 0;
            continue;
        }
        standing.given_up = Some(said);
        return departed;
    }
}

fn depart_one(
    runtime: &Runtime<'_>,
    work: &ReceivedWork,
    facts: &IdentityFacts,
    to: Subscriber,
    sending: &Sending,
) -> Departed {
    let location = &sending.configured;

    // Authorized again, now, against the clock. What receive concluded may be
    // days old by the time a Process finished waiting for a human.
    let permitted = authorize(
        runtime.policies,
        facts,
        &Attempt::new(Action::Send, &location.name).at(runtime.clock.unix_timestamp_nanos()),
        context::OnMisalignment::Accept,
    );

    if !permitted.allowed() {
        return Departed::NotPermitted {
            to,
            decision: permitted,
        };
    }

    // ADR-0006. The first identity found walking Location, Port, Group,
    // Sending Process is the one presented — resolved independently of
    // whatever identity the Message arrived under, because the target only
    // cares which identity Xmip presents.
    let resolved = sending.chain.resolve();
    let party = resolved.and_then(|(party_id, _)| runtime.directory.party(party_id));
    let presented = party.as_ref().and_then(|party| {
        party
            .configured_for(Purpose::Send)
            .next()
            .map(|identity| identity.value.clone())
    });

    // Read whole from the Ledger here, where a transport's send takes it
    // whole; a send that streams reads it a chunk at a time
    // (`runtime-model.md` section 10).
    let bytes = match work.message.sections()[0].stream.load() {
        Ok(bytes) => bytes,
        Err(unread) => {
            return Departed::Failed {
                to,
                retryable: true,
                detail: unread.to_string(),
            };
        }
    };

    match sending.transport.send(&location.address, bytes) {
        Ok(()) => Departed::Sent {
            to,
            presented_from: resolved.map(|(_, level)| level),
            presented,
        },
        Err(failure) => Departed::Failed {
            to,
            retryable: failure.retryable,
            detail: failure.message,
        },
    }
}

/// What departures came to, in words, as a Journey records it.
#[must_use]
pub fn said(departed: &[Departed]) -> String {
    if departed.is_empty() {
        return "nowhere to go".to_string();
    }
    departed
        .iter()
        .map(|one| match one {
            Departed::Sent { to, .. } => format!("sent to {to}"),
            Departed::NoSuchDestination { to } => format!("no Send Location for {to}"),
            Departed::ProcessNotRun { to } => format!("{to} is run by no runtime yet"),
            Departed::NotPermitted { to, decision } => format!("not permitted to {to}: {decision}"),
            Departed::Failed { to, detail, .. } => format!("not sent to {to}: {detail}"),
        })
        .collect::<Vec<_>>()
        .join("; ")
}
