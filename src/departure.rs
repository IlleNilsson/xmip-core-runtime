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
//!   -> authorize may this identity still send, now
//!   -> resolve   whose identity Xmip presents, per ADR-0006
//!   -> depart    pushed, collected or scheduled
//! ```
//!
//! **The ToDo holds the Message until every departure is settled.** A
//! Journey with two destinations reached and one awaiting collection is
//! unfinished, and the work store is the only place that state can live without
//! either lying about it.
//!
//! Authorization runs again here rather than being inherited from arrival.
//! Time has passed — a Process may have waited days for a human — and what was
//! true then is never a licence to act now.

use authorize::{Action, Attempt, Decision, authorize};
use context::IdentityFacts;
use route::{Routing, Subscriber};
use send::{SendError, SendLevel, SendRequest};
use xcore::{Departing, Purpose};

use crate::engine::Runtime;
use crate::generation::ReceivedWork;

/// What became of one Message on its way out to one destination.
#[derive(Clone, Debug)]
pub enum Departed {
    Sent {
        to: Subscriber,
        /// Which artifact decided the identity presented, or `None` where
        /// nothing in the chain declared one.
        presented_from: Option<SendLevel>,
        status: String,
    },
    /// Available, and waiting to be collected.
    ///
    /// Not a success and not a failure. Xmip has done everything it can and the
    /// departure completes when somebody turns up — so the Message stays in the
    /// ToDo, and an unreachable partner and an idle one stay
    /// distinguishable, which they are not if this is reported as sent.
    Awaiting { to: Subscriber, at: String },
    /// Routing named a destination that configuration does not have.
    ///
    /// A deploy-time defect found at run time, and the same class of mistake
    /// `never_satisfiable` catches on the receive side.
    NoSuchDestination { to: Subscriber },
    /// No loaded transport speaks the Location's technology.
    NoTransport { to: Subscriber, technology: String },
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

    /// Whether the ToDo must keep holding this.
    ///
    /// True while a collected departure has not been collected. The Message is
    /// not done and is not failed, and the work store is the only thing that
    /// can hold that state without either lying.
    #[must_use]
    pub const fn holds(&self) -> bool {
        matches!(self, Self::Awaiting { .. })
    }
}

/// Carry a routed Message to every destination that matched.
///
/// The mirror of [`arrive`]. One departure per destination, and one result per
/// departure. A Message routed to three Send Ports that reaches two of them is
/// two successes and one failure, not a single verdict — which is why this
/// returns a list rather than a `Result`.
///
/// **The ToDo holds the Message until every departure is settled.** Not
/// until the first succeeds, and not until routing decided where it was going:
/// a Journey with two destinations reached and one refused is unfinished, and
/// the work store is what makes that recoverable rather than lost.
pub fn depart(
    runtime: &Runtime<'_>,
    work: &ReceivedWork,
    facts: &IdentityFacts,
    routing: &Routing,
) -> Vec<Departed> {
    routing
        .destinations()
        .into_iter()
        .map(|to| depart_one(runtime, work, facts, to))
        .collect()
}

fn depart_one(
    runtime: &Runtime<'_>,
    work: &ReceivedWork,
    facts: &IdentityFacts,
    to: &Subscriber,
) -> Departed {
    let Some((location, chain)) = runtime.sends.location(to) else {
        return Departed::NoSuchDestination { to: to.clone() };
    };

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
            to: to.clone(),
            decision: permitted,
        };
    }

    // Xmip is the server here: the Stream is made available and something comes
    // and takes it. There is nothing to send and no identity for Xmip to
    // present — the collector presents one, and is put through the same three
    // gates an arrival is, when it turns up.
    if location.departing == Departing::Collected {
        return Departed::Awaiting {
            to: to.clone(),
            at: location.uri.clone(),
        };
    }

    let Some(transport) = runtime
        .transports
        .iter()
        .find(|candidate| candidate.technology() == location.transport)
    else {
        return Departed::NoTransport {
            to: to.clone(),
            technology: location.transport.clone(),
        };
    };

    // ADR-0006. The first identity found walking Location, Port, Group,
    // Sending Process is the one presented — resolved independently of
    // whatever identity the Message arrived under, because the target only
    // cares which identity Xmip presents.
    let resolved = chain.resolve();
    let party = resolved.and_then(|(party_id, _)| runtime.directory.party(party_id));
    let presented = party.as_ref().and_then(|party| {
        party
            .configured_for(Purpose::Send)
            .find(|identity| identity.mechanism.name() == location.transport)
            .or_else(|| party.configured_for(Purpose::Send).next())
    });

    let request = SendRequest {
        message: &work.message,
        location: &location,
        present: presented,
        present_from: resolved.map(|(_, level)| level),
        dynamic_properties: &[],
    };

    match transport.send(request) {
        Ok(result) => Departed::Sent {
            to: to.clone(),
            presented_from: resolved.map(|(_, level)| level),
            status: result.status,
        },
        Err(SendError { retryable, message }) => Departed::Failed {
            to: to.clone(),
            retryable,
            detail: message,
        },
    }
}
