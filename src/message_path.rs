//! What both halves of the path need, and neither owns.
//!
//! Arrival and departure are mirror images and share one runtime. Putting the
//! shared thing here keeps `arrival.rs` and `departure.rs` about what happens
//! rather than about what is wired up. [`carry`] is the receive cycle: one
//! Stream in, arrival — its Stream into the Ledger once the transport gates
//! have passed — routing, and Publication into the Ledger. What it returns
//! says whether the receive cycle finished ([`Carried::cycle`]), so the
//! Receive Location acknowledges the sender, or not. Departure is the send
//! step's, from the Ledger ([`crate::send_step`]).

use std::sync::Arc;

use authenticate::{Authenticator, PartyRegistry};
use authorize::Authorizer;
use identify::{MessageIdentifier, TransportIdentifier};
use journey::Journey;
use message::MessageTreatment;
use party::Party;
use persist::storage::XmipStorage;
use receive::ReceivedStream;
use route::{Gathering, Subscription};
use xaudit::origin::Origin;
use xcore::{Clock, IdGenerator, PartyId, Purpose};

use crate::arrival::arrive;
use crate::dead_message::Unmatched;
use crate::ledger::{self, Published};
use crate::outcome::Arrived;
use crate::pickup::Pickup;
use crate::receiving::ReceiveGate;
use crate::send_step::SendStep;
use crate::sending::Sends;

/// A Party, by the identifier the gates handed back.
///
/// Separate from [`PartyRegistry`], which answers with a `PartyId` and nothing
/// more. `architecture.toml` gives the three gates no dependency on
/// `xmip-core-party`, so a gate cannot read a Party's identities even by
/// accident; the runtime can, because the send side genuinely needs to —
/// ADR-0006 resolves *which* Party's identity to present through the Send
/// Location chain, and something then has to produce it.
pub trait PartyDirectory: Send + Sync {
    fn party(&self, party_id: PartyId) -> Option<Party>;
}

/// The Parties a node knows, answering both the gates' question (whose is
/// this verified value) and the send side's (which identity does this Party
/// present). One list, because a deployment has one set of Parties.
#[derive(Clone, Debug, Default)]
pub struct Parties(pub Vec<Party>);

impl PartyRegistry for Parties {
    fn resolve(&self, mechanism: &str, purpose: Purpose, value: &str) -> Option<PartyId> {
        self.0
            .iter()
            .find(|party| party.identity(mechanism, purpose) == Some(value))
            .map(|party| party.party_id)
    }
}

impl PartyDirectory for Parties {
    fn party(&self, party_id: PartyId) -> Option<Party> {
        self.0
            .iter()
            .find(|party| party.party_id == party_id)
            .cloned()
    }
}

/// Everything the message path needs that is not the Message itself, built
/// once as a node starts and shared by every Receive Location it runs.
pub struct Runtime<'a> {
    pub ids: &'a dyn IdGenerator,
    pub authenticators: &'a [&'a dyn Authenticator],
    pub parties: &'a dyn PartyRegistry,
    pub directory: &'a dyn PartyDirectory,
    pub subscriptions: &'a [Subscription],

    /// Every name the Subscriptions' filters use, compiled once, when the
    /// Runtime is built, through the route technologies loaded
    /// (`Gathering::of`): each reads the properties its prefix names in a
    /// filter, `header:`, `party:` and the rest (ADR-0046). A bare name is
    /// context and needs none of them. A node refuses to start while a name
    /// does not compile (ADR-0066 clause 1); a gathering used without asking
    /// refuses each Message at arrival instead.
    pub gathering: &'a Gathering,
    pub treatment: MessageTreatment,

    /// The node's Send Locations, each with the transport built for it once,
    /// by the Send Port name routing resolves, and its Send Ports' policy.
    pub sends: &'a Sends,

    /// The node's send step: what a Publication claims it hands to it, and
    /// it sends every Journey this node sends from the Ledger
    /// ([`crate::send_step`]).
    pub send: &'a SendStep,

    /// The first gate, before a Message exists.
    pub transport_identifiers: &'a [&'a dyn TransportIdentifier],

    /// The first gate again, after one does. ADR-0013 runs it twice because the
    /// two layers become readable at different moments, not because they are two
    /// different questions.
    pub message_identifiers: &'a [&'a dyn MessageIdentifier],

    /// The policies consulted before any work is done, at every point.
    pub policies: &'a [&'a dyn Authorizer],

    /// Read at each gate rather than once. A Journey may wait days between
    /// arriving and sending, and both gates need to know when they are.
    pub clock: &'a dyn Clock,

    /// Xmip Storage, the doorway to the Ledger: every Stream permitted in is
    /// written there in chunks, and every Publication's Message and
    /// Journeys, durably, before the receive cycle finishes
    /// ([`crate::ledger`]).
    pub storage: &'a Arc<dyn XmipStorage>,

    /// The size a Stream is written to the Ledger in ([`ledger::CHUNK`]).
    pub chunk: usize,

    /// Where the node's audit records say they came from: a Publication's
    /// among them.
    pub origin: &'a Origin,
}

/// How a receive cycle ended, which is what the sender is told: only a
/// completed one is acknowledged (`runtime-model.md` section 5: *The sender
/// is acknowledged after the whole receive cycle*).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiveCycle {
    /// Accepted and durable: the Stream, the Message and its Journeys are
    /// in the Ledger. Acknowledge it.
    Completed,
    /// Refused at a gate: nothing is kept before Message creation, and the
    /// sender is refused, not acknowledged.
    Refused,
    /// Permitted and not kept: Xmip Storage did not take it, or the Stream
    /// could not be read. Not acknowledged, so the sender sends again.
    Failed,
}

/// What became of one Stream: its arrival, the Journeys its Publication
/// opened — none when it was refused, failed or unroutable — and how many
/// paused Subscriptions held it. Where each goes is the send step's.
#[derive(Debug)]
pub struct Carried {
    pub arrived: Arrived,
    /// Paused Subscriptions that matched it and hold its Journey in the
    /// Ledger (ADR-0013, amendment 2026-09-30).
    pub held: usize,
    /// The Journeys its Publication wrote to the Ledger, one per matched
    /// Subscription; none where it was refused, failed or matched nothing.
    pub journeys: Vec<Journey>,
}

impl Carried {
    /// How the receive cycle ended: whether to acknowledge the sender.
    #[must_use]
    pub const fn cycle(&self) -> ReceiveCycle {
        match self.arrived {
            Arrived::Routed { .. } | Arrived::Unroutable { .. } => ReceiveCycle::Completed,
            Arrived::Refused { .. } => ReceiveCycle::Refused,
            Arrived::Failed { .. } => ReceiveCycle::Failed,
        }
    }
}

/// One Stream through the receive cycle: arrival at `gate` — the Stream
/// into the Ledger once its transport gates pass — routing, and the
/// Publication into the Ledger, with what a paused Subscription of
/// `pickup`'s holds and every other Journey in the queue of where it
/// leads. **The cycle sends nothing** (`runtime-model.md` section 5): it
/// ends at the Publication's durable write, and the Journeys this node
/// claimed in it are handed to its send step, which sends them from there.
pub fn carry(
    runtime: &Runtime<'_>,
    pickup: &Pickup,
    gate: &ReceiveGate,
    received: ReceivedStream,
) -> Carried {
    // One statement, one Storage node: the Stream's chunks, the Publication
    // and its Journeys (the owner, 2026-10-03).
    let statement = persist::storage::statement(runtime.storage);
    let runtime = &Runtime {
        storage: &statement,
        ..*runtime
    };
    let (arrived, published) = published(runtime, pickup, gate, arrive(runtime, gate, received));
    let Some(Published {
        journeys,
        holding,
        lined,
    }) = published
    else {
        return Carried {
            arrived,
            held: 0,
            journeys: Vec::new(),
        };
    };
    if let Arrived::Routed { work, facts, .. } = &arrived {
        runtime.send.handed(lined, &journeys, work, facts);
    } else {
        runtime.send.withdrawn(&lined);
    }
    Carried {
        arrived,
        held: holding.holds().len(),
        journeys,
    }
}

/// Publication into the Ledger of what arrival published: the Message
/// record, its Journeys, what a paused Subscription holds — or, where
/// nothing matched, its Dead Message Queue entry — and the audit record,
/// durable, or the cycle failed.
fn published(
    runtime: &Runtime<'_>,
    pickup: &Pickup,
    gate: &ReceiveGate,
    arrived: Arrived,
) -> (Arrived, Option<Published>) {
    let (work, facts, routing, unmatched) = match &arrived {
        Arrived::Routed {
            work,
            facts,
            routing,
        } => (work, facts, routing, Unmatched::default()),
        Arrived::Unroutable {
            work,
            facts,
            routing,
            promoted,
        } => (
            work,
            facts,
            routing,
            Unmatched {
                promoted: Some(promoted),
                facts: Some(facts),
            },
        ),
        Arrived::Refused { .. } | Arrived::Failed { .. } => return (arrived, None),
    };
    let publisher = ledger::Publisher {
        storage: runtime.storage.as_ref(),
        ids: runtime.ids,
        clock: runtime.clock,
        origin: runtime.origin,
        send: runtime.send,
        sends: runtime.sends,
    };
    let (message, location) = (&work.message, &gate.location);
    match ledger::publish(
        &publisher,
        pickup,
        location,
        message,
        routing,
        &unmatched,
        || facts.record(),
    ) {
        Ok(published) => (arrived, Some(published)),
        Err(reason) => (Arrived::Failed { reason }, None),
    }
}
