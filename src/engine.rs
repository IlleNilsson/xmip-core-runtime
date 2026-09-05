//! What both halves of the path need, and neither owns.
//!
//! Arrival and departure are mirror images and share one runtime. Putting the
//! shared thing here keeps `arrival.rs` and `departure.rs` about what happens
//! rather than about what is wired up.

use authenticate::{Authenticator, PartyRegistry};
use authorize::Authorizer;
use identify::{MessageIdentifier, TransportIdentifier};
use message::MessageTreatment;
use party::Party;
use route::{Subscriber, Subscription};
use send::{SendChain, SendLocation, SendTransport};
use xcore::{Clock, IdGenerator, PartyId};

/// Where a matched Subscriber is configured.
///
/// Routing decides *that* a Message goes to `SendPort.Billing`. Which Location
/// that is, and whose identity it presents, is configuration — and it is
/// resolved here rather than by routing, because ADR-0019 clause 3 keeps the
/// two apart: routing never decides *how* something gets somewhere.
pub trait SendRegistry: Send + Sync {
    fn location(&self, subscriber: &Subscriber) -> Option<(SendLocation, SendChain)>;
}

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

/// Everything the arrival path needs that is not the arrival itself.
pub struct Runtime<'a> {
    pub ids: &'a dyn IdGenerator,
    pub authenticators: &'a [&'a dyn Authenticator],
    pub parties: &'a dyn PartyRegistry,
    pub directory: &'a dyn PartyDirectory,
    pub subscriptions: &'a [Subscription],
    pub treatment: MessageTreatment,
    pub sends: &'a dyn SendRegistry,
    pub transports: &'a [&'a dyn SendTransport],

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
