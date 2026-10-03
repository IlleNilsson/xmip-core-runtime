//! The departure path: what a Host Service does with a Message that is going
//! somewhere.
//!
//! The mirror of [`crate::arrival`], and the same shape. A Stream arrives at a
//! Receive Location; a Message departs from a Send Location. Both are gated,
//! both are recorded, and the vocabulary is deliberately symmetric because an
//! operator watching an estate is reading one board.
//!
//! ```text
//! Routing        every destination the Message matched
//!   -> resolve   which Send Location, on this node
//!   -> authorize may this identity still send, now
//!   -> identity  whose identity Xmip presents, per ADR-0006
//!   -> depart    through the Location's transport, built once
//! ```
//!
//! Authorization runs again here rather than being inherited from arrival.
//! Time has passed — a Process may have waited days for a human — and what was
//! true then is never a licence to act now.

use authorize::{Action, Attempt, Decision, authorize};
use context::IdentityFacts;
use route::{Routing, Subscriber};
use send::SendLevel;
use xcore::Purpose;

use crate::generation::ReceivedWork;
use crate::message_path::Runtime;
use crate::sending::{Destination, Sending};

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

/// Carry a routed Message to every destination that matched.
///
/// The mirror of [`crate::arrival::arrive`]. One departure per Send Location
/// reached, and one result per departure. A Message routed to three Send
/// Ports that reaches two of them is two successes and one failure, not a
/// single verdict — which is why this returns a list rather than a `Result`.
pub fn depart(
    runtime: &Runtime<'_>,
    work: &ReceivedWork,
    facts: &IdentityFacts,
    routing: &Routing,
) -> Vec<Departed> {
    routing
        .destinations()
        .into_iter()
        .flat_map(|to| depart_to(runtime, work, facts, to))
        .collect()
}

/// Carry a Message to one destination: every Send Location it reaches.
/// What [`depart`] does for each destination routing matched, and what a
/// Subscription does for a Message it held once it is resumed
/// ([`crate::held_work`]).
pub fn depart_to(
    runtime: &Runtime<'_>,
    work: &ReceivedWork,
    facts: &IdentityFacts,
    to: &Subscriber,
) -> Vec<Departed> {
    match runtime.sends.to(to) {
        Destination::Ports(ports) => ports
            .into_iter()
            .map(|(port, sending)| {
                let to = Subscriber::SendPort(port.to_string());
                match sending {
                    Some(sending) => depart_one(runtime, work, facts, to, sending),
                    None => Departed::NoSuchDestination { to },
                }
            })
            .collect(),
        Destination::Process => vec![Departed::ProcessNotRun { to: to.clone() }],
        Destination::Nowhere => vec![Departed::NoSuchDestination { to: to.clone() }],
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
    // whole; a send that streams reads it a chunk at a time, with the send
    // step (`runtime-model.md` section 10).
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
