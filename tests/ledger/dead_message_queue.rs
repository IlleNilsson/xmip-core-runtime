//! A node's Dead Message Queue, through the receive path, over Xmip Storage
//! that fails on demand (`runtime-model.md` section 9, *The Dead Message
//! Queue is Ledger state*):
//!
//! - a Message nothing matched is kept with its entry — its receive
//!   context, what its gates concluded, its promoted properties and each
//!   Subscription's decline — and its receive cycle completes;
//! - a Publication Xmip Storage did not take keeps neither the Message nor
//!   its entry, and is not acknowledged;
//! - a Replay against the Subscriptions of then is refused, the entry kept;
//!   one after a matching Subscription is added opens and holds its
//!   Journeys and takes the entry out, once; one Xmip Storage did not take
//!   leaves the entry;
//! - the queue is listed oldest first, in pages.

use std::io::Cursor;
use std::sync::Arc;
use std::time::Duration;

use persist::fixture::Memory;
use persist::storage::{Ask, Embedded, Query, Span, XmipStorage, dead_message_queue, named};
use receive::ReceivedStream;
use route::Subscription;
use secret::{Held, KekName};
use xcore::{AuditId, MessageId};
use xmip_core_runtime::configured_subscription::ConfiguredSubscription;
use xmip_core_runtime::fixture::{Failing, Operation};
use xmip_core_runtime::ledger::CHUNK;
use xmip_core_runtime::message_path::{ReceiveCycle, carry};
use xmip_core_runtime::outcome::Arrived;
use xmip_core_runtime::pickup::Pickup;

use super::receive_cycle::{node, on_runtime_with, subscription};

/// The operator acting in these tests.
const WHO: &str = "an operator";

fn failing() -> (Arc<Failing>, Arc<dyn XmipStorage>) {
    let keys = Held::new(secret::fixture::Memory::default());
    let kek = KekName::new("storage").expect("a name");
    let node = Embedded::open(
        Memory::default(),
        Memory::default(),
        Memory::default(),
        &keys,
        &kek,
    )
    .expect("opened");
    let failing = Failing::over(Arc::new(node));
    let storage: Arc<dyn XmipStorage> = failing.clone();
    (failing, storage)
}

fn invoice(number: u32) -> ReceivedStream {
    ReceivedStream::new(
        Cursor::new(format!("invoice {number}").into_bytes()),
        "tcp://127.0.0.1:1",
    )
}

/// The Subscription the node routes by first: it matches nothing that
/// arrives here.
fn elsewhere() -> Subscription {
    subscription("elsewhere", "xmip.transport.mechanism = 'nothing'")
}

/// The Subscription added once the Messages were kept: it matches them.
fn onward() -> Subscription {
    subscription("onward", "xmip.transport.mechanism = 'circumstance'")
}

/// The node's pickup taken up again with `subscriptions`, as a node
/// restarted with a changed configuration takes its own.
fn taken_up(storage: &Arc<dyn XmipStorage>, subscriptions: &[Subscription]) -> Arc<Pickup> {
    let configured = subscriptions
        .iter()
        .cloned()
        .map(ConfiguredSubscription::unfiled)
        .collect();
    Pickup::open(&node(), configured, Arc::clone(storage), None).expect("opened")
}

/// Carry `count` invoices nothing matches through the receive path: the
/// Messages they became.
fn unmatched(storage: &Arc<dyn XmipStorage>, count: u32) -> Vec<MessageId> {
    on_runtime_with(storage, CHUNK, &[elsewhere()], |runtime, pickup, gate| {
        (0..count)
            .map(|number| {
                let carried = carry(runtime, pickup, gate, invoice(number));
                assert_eq!(carried.cycle(), ReceiveCycle::Completed, "acknowledged");
                let Arrived::Unroutable { work, .. } = &carried.arrived else {
                    panic!("nothing matched: {:?}", carried.arrived);
                };
                assert!(carried.journeys.is_empty());
                work.message.message_id()
            })
            .collect()
    })
}

#[test]
fn a_message_nothing_matched_is_kept_with_why_and_listed_oldest_first() {
    let (_, storage) = failing();
    let messages = unmatched(&storage, 5);
    let pickup = taken_up(&storage, &[elsewhere()]);
    let (count, dead) = pickup.dead_messages(2).expect("read");
    assert_eq!(count, 5);
    let listed: Vec<String> = dead.iter().map(|entry| entry.message.clone()).collect();
    assert_eq!(listed, [messages[0].to_string(), messages[1].to_string()]);
    let first = &dead[0];
    assert_eq!(first.node, node());
    assert_eq!(first.declines.len(), 1);
    assert_eq!(first.declines[0][0], "elsewhere");
    assert!(first.declines[0][1].contains("circumstance"), "{first:?}");
    assert!(
        first
            .promoted
            .iter()
            .any(|[name, value]| name == "xmip.transport.mechanism" && value == "circumstance"),
        "{first:?}"
    );
    assert_eq!(first.validation[0][0], "transport identity");
    let message = storage.read_message(messages[0]).expect("read");
    assert!(message.is_some(), "the Message with its entry");

    let queue = dead_message_queue(&node());
    let page = storage
        .read_dead(queue, dead[1].sequence + 1, 2)
        .expect("read");
    let next: Vec<MessageId> = page.dead.iter().map(|one| one.message.message).collect();
    assert_eq!(next, messages[2..4]);
}

#[test]
fn a_publication_xmip_storage_did_not_take_keeps_neither_message_nor_entry() {
    let (failing, storage) = failing();
    failing.fail(Operation::Publish, 1);
    on_runtime_with(&storage, CHUNK, &[elsewhere()], |runtime, pickup, gate| {
        let carried = carry(runtime, pickup, gate, invoice(0));
        assert_eq!(carried.cycle(), ReceiveCycle::Failed, "not acknowledged");
        assert_eq!(pickup.dead_messages(8).expect("read").0, 0);
    });
    assert_eq!(unmatched(&storage, 1).len(), 1, "sent again, and kept");
}

#[test]
fn a_replay_once_a_subscription_matches_opens_its_journeys_and_takes_the_entry_out_once() {
    let (failing, storage) = failing();
    let messages = unmatched(&storage, 2);
    let first = messages[0].to_string();

    let before = taken_up(&storage, &[elsewhere()]);
    let refused = before
        .replay(&first, WHO)
        .expect_err("still nothing matches");
    assert!(refused.starts_with("REFUSED"), "{refused}");
    assert!(refused.contains("'elsewhere'"), "{refused}");
    assert_eq!(before.dead_messages(8).expect("read").0, 2, "kept");
    let stranger = before.replay("not a message", WHO).expect_err("refused");
    assert!(stranger.starts_with("REFUSED"), "{stranger}");
    drop(before);

    let after = taken_up(&storage, &[elsewhere(), onward()]);
    failing.fail(Operation::Replay, 1);
    let failed = after.replay(&first, WHO).expect_err("not taken");
    assert!(failed.starts_with("FAILED"), "{failed}");
    assert_eq!(
        after.dead_messages(8).expect("read").0,
        2,
        "nothing changed"
    );

    let said = after.replay(&first, WHO).expect("replayed");
    assert!(said.contains("1 Journey(s)"), "{said}");
    let (count, dead) = after.dead_messages(8).expect("read");
    assert_eq!(count, 1);
    assert_eq!(dead[0].message, messages[1].to_string());
    let held = named(&format!("{}/subscription/onward", node()));
    let queue = storage.read_held(held, 0, 8).expect("read");
    assert_eq!(queue.count, 1, "held for the node to pick up");
    let journey = queue.held[0].hold.journey;
    assert!(storage.read_journey(journey).expect("read").is_some());
    let standing = after.standing();
    let onward = standing
        .iter()
        .find(|one| one.name == "onward")
        .expect("onward");
    assert_eq!(onward.held, 1);
    // The Replay's audit record, the last written, carries the Message it
    // replayed in full and its Stream's bytes beside it (ADR-0070).
    storage.keep_audit(16, CHUNK).expect("kept");
    let last = Query {
        ask: Ask::AuditOccurred {
            occurred: Span::ALL,
        },
        most: 1,
        newest_first: true,
    };
    let last = storage.query(&last).expect("asked")[0];
    let kept = persist::fixture::kept_as_written(storage.as_ref(), AuditId::new(last));
    let kept = kept.expect("kept");
    let replayed = storage.read_message(messages[0]).expect("read");
    let carried = kept.audited.expect("an act on a Message");
    assert_eq!(Some(carried.message), replayed.map(|record| record.body));
    let stream = carried.streams[0];
    let row = storage
        .read_kept_audit_stream(kept.id, stream)
        .expect("read");
    assert!(row.is_some(), "its Stream beside it");

    let again = after.replay(&first, WHO).expect("asked again");
    assert!(again.contains("replayed already"), "{again}");
    assert_eq!(
        storage.read_held(held, 0, 8).expect("read").count,
        1,
        "once"
    );
    let released = after.released(Duration::ZERO, 8);
    assert_eq!(released.len(), 1);
    assert_eq!(released[0].subscription, "onward");
    assert_eq!(released[0].held.hold.journey, journey);
}
