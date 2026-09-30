//! What both halves of the path need, and neither owns.
//!
//! Arrival and departure are mirror images and share one runtime. Putting the
//! shared thing here keeps `arrival.rs` and `departure.rs` about what happens
//! rather than about what is wired up. [`carry`] is the join: one Stream in,
//! arrival, routing, and a departure to every destination it matched.

use authenticate::{Authenticator, PartyRegistry};
use authorize::Authorizer;
use identify::{MessageIdentifier, TransportIdentifier};
use message::MessageTreatment;
use party::Party;
use receive::ReceivedStream;
use route::{Gathering, Subscription};
use xcore::{Clock, IdGenerator, PartyId, Purpose};

use crate::arrival::arrive;
use crate::departure::{Departed, depart};
use crate::held_work::held;
use crate::outcome::Arrived;
use crate::pickup::Pickup;
use crate::receiving::ReceiveGate;
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
    /// by the Send Port name routing resolves.
    pub sends: &'a Sends,

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
}

/// What became of one Stream: its arrival, a departure for every
/// destination routing matched — none when it was refused or unroutable —
/// and how many paused Subscriptions held it instead.
#[derive(Debug)]
pub struct Carried {
    pub arrived: Arrived,
    pub departed: Vec<Departed>,
    /// Paused Subscriptions that matched it and hold it (ADR-0013,
    /// amendment 2026-09-30).
    pub held: usize,
}

/// One Stream along the whole path: arrival at `gate`, routing, and
/// departure to every destination the Message matched whose Subscription
/// `pickup` does not hold it for.
pub fn carry(
    runtime: &Runtime<'_>,
    pickup: &Pickup,
    gate: &ReceiveGate,
    received: ReceivedStream,
) -> Carried {
    let arrived = arrive(runtime, gate, received);

    let (departed, held) = match &arrived {
        Arrived::Routed {
            work,
            facts,
            routing,
        } => {
            let picked = pickup.route(routing, &|| held(work, facts));
            let held = routing.destinations().len() - picked.destinations().len();
            (depart(runtime, work, facts, &picked), held)
        }
        Arrived::Refused { .. } | Arrived::Unroutable { .. } => (Vec::new(), 0),
    };

    Carried {
        arrived,
        departed,
        held,
    }
}
