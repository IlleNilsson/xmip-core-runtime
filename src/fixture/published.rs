//! A Message published through a pickup as the receive path publishes it,
//! and the Subscription it is matched to: the pickup's tests and the
//! subscriptions export's tests in xmip-core-operate take both from here.

use journey::{Journey, JourneyMessageRef};
use path::expression::Expression;
use persist::storage::{
    AuditEntry, AuditFacts, MessageFacts, MessageRecord, Publication, XmipStorage,
};
use route::{Promoted, Subscriber, publish};
use xcore::{AuditId, IdGenerator, MessageId, StreamId, UuidV7Generator};

use crate::pickup::Pickup;

/// A Subscription named `name` that matches every Message and sends it to
/// the Send Port `Out`.
///
/// # Panics
/// Never: its filter, `true`, compiles.
#[must_use]
pub fn subscription(name: &str) -> route::Subscription {
    route::Subscription::new(
        name,
        Subscriber::SendPort("Out".to_string()),
        Expression::parse("true").expect("compiles"),
    )
}

/// One Message matched to every one of `subscriptions`, published
/// through `pickup` into `storage` as the receive path publishes it,
/// `body` kept beside what is held: how many were held, or why the
/// Publication was not taken.
///
/// # Errors
/// Xmip Storage's words when it does not take the Publication.
pub fn published(
    pickup: &Pickup,
    storage: &dyn XmipStorage,
    subscriptions: &[route::Subscription],
    body: &str,
) -> Result<usize, String> {
    let ids = UuidV7Generator;
    let routing = publish(&Promoted::new(), subscriptions);
    let message = MessageId::new(ids.next_u128());
    let held = JourneyMessageRef {
        message_id: message,
        stream_id: StreamId::new(ids.next_u128()),
    };
    let opened = crate::ledger::opened(&routing, pickup, held, &ids);
    let journeys: Vec<Journey> = opened.iter().map(|o| o.journey.clone()).collect();
    let holding = pickup.holding(&opened, || body.as_bytes().to_vec());
    let publication = Publication {
        message: MessageRecord {
            message,
            body: Vec::new(),
            facts: MessageFacts::default(),
        },
        journeys: journeys.iter().map(crate::ledger::journey_record).collect(),
        held: holding.holds().to_vec(),
        dead: None,
        audit: AuditEntry {
            id: AuditId::new(ids.next_u128()),
            body: Vec::new(),
            audited: None,
            facts: AuditFacts::default(),
        },
        claims: Vec::new(),
        lease_nanos: 0,
    };
    storage.publish(publication).map_err(|e| e.to_string())?;
    pickup.published(&holding);
    Ok(holding.holds().len())
}
