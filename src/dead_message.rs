//! What a node's Dead Message Queue keeps of a Message no Subscription
//! matched, and what the node publishes of it (`runtime-model.md` section
//! 9, *The Dead Message Queue is Ledger state*; ADR-0013, amendments
//! 2026-10-01 and 2026-10-03).
//!
//! **Decided before the acknowledgement.** Routing runs inside the receive
//! cycle; where it matched nothing, the Publication carries the Message's
//! entry — its receive context, what its gates concluded, its promoted
//! properties and every Subscription's reason for declining — and Xmip
//! Storage writes it with the Message in one write ([`crate::ledger::publish`],
//! `persist::storage::DeadMessage`). The operator's question is *what were
//! the promoted properties, and which Subscription nearly matched*, so that
//! is what is kept; the body is the Message's, in the Ledger beside it.
//!
//! **Replay** is the Operator's act on an entry, once a Subscription is
//! added or fixed ([`crate::pickup::Pickup::replay`]).

use context::IdentityFacts;
use journey::JourneyMessageRef;
use persist::storage::{Dead, DeadMessage, Named, dead_message_queue};
use route::{Promoted, Routing};

/// What the Dead Message Queue keeps of a Message beyond its record, where
/// nothing matched it: the properties routing read, and the identities its
/// gates concluded. Either may be absent where the publisher has none.
#[derive(Clone, Copy, Debug, Default)]
pub struct Unmatched<'a> {
    pub promoted: Option<&'a Promoted>,
    pub facts: Option<&'a IdentityFacts>,
}

/// Where and when a Message was received: its node
/// (`xmip:///<cluster>/node/<name>`), its Receive Location, and the time,
/// in nanoseconds since the Unix epoch.
pub(crate) type Received<'a> = (&'a str, &'a str, i128);

/// The entry the node's Dead Message Queue keeps for the Message `held`
/// names, received as `received` says, that `routing` matched to nothing:
/// with what `unmatched` says, every Subscription's decline in the order
/// asked, and `body`, what a Replay holds beside each Journey it opens.
pub(crate) fn entry(
    (node, location, received_unix_nanos): Received<'_>,
    held: JourneyMessageRef,
    routing: &Routing,
    unmatched: &Unmatched<'_>,
    body: Vec<u8>,
) -> DeadMessage {
    DeadMessage {
        queue: dead_message_queue(node),
        message: held.message_id,
        stream: held.stream_id,
        node: node.to_string(),
        location: location.to_string(),
        received_unix_nanos,
        validation: unmatched.facts.map(validation).unwrap_or_default(),
        promoted: unmatched
            .promoted
            .map(|promoted| {
                promoted
                    .names()
                    .into_iter()
                    .map(|name| Named::new(name, promoted.get(name).unwrap_or_default()))
                    .collect()
            })
            .unwrap_or_default(),
        declines: routing
            .evaluations
            .iter()
            .filter(|evaluation| !evaluation.matched())
            .map(|evaluation| {
                let why = evaluation
                    .outcome
                    .reason()
                    .unwrap_or("its filter did not hold");
                Named::new(&evaluation.subscription_id, why)
            })
            .collect(),
        body,
    }
}

/// What each gate concluded of a Message's identity, in the order they ran:
/// the transport's, the message's where it carried one, and their
/// alignment.
#[must_use]
pub fn validation(facts: &IdentityFacts) -> Vec<Named> {
    let said = |identity: &context::AuthenticatedIdentity| {
        format!(
            "{} by {}: {}",
            identity.verified.word(),
            identity.mechanism.name(),
            identity.value
        )
    };
    let mut gates = vec![Named::new("transport identity", said(&facts.transport))];
    if let Some(message) = &facts.message {
        gates.push(Named::new("message identity", said(message)));
    }
    gates.push(Named::new("alignment", facts.alignment.word()));
    gates
}

/// An entry as the node publishes it.
#[must_use]
pub fn published(dead: &Dead) -> observe::DeadMessage {
    let pairs = |named: &[Named]| -> Vec<[String; 2]> {
        named
            .iter()
            .map(|one| [one.name.clone(), one.value.clone()])
            .collect()
    };
    let entry = &dead.message;
    observe::DeadMessage {
        node: entry.node.clone(),
        message: entry.message.to_string(),
        sequence: dead.sequence,
        location: entry.location.clone(),
        received_unix_nanos: i64::try_from(entry.received_unix_nanos).unwrap_or(i64::MAX),
        validation: pairs(&entry.validation),
        promoted: pairs(&entry.promoted),
        declines: pairs(&entry.declines),
    }
}
