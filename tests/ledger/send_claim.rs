//! A send whose claim stops being surely this node's while it runs
//! (`runtime-model.md` section 10, *Corrected 2026-10-06*): a Send Port of
//! two Send Locations failing over, the first holding its send until the
//! test lets it go and then refusing it, so whether the second is tried
//! says whether the pass went on.
//!
//! - a renewal that finds the claim another's — it lapsed on the Storage
//!   node's clock and another node took the Journey up — stops the pass: the
//!   second Location is never tried, nothing is written, the loss is
//!   counted at the Port;
//! - a renewal Xmip Storage does not answer leaves the claim unconfirmed,
//!   shown at the Port, and attempts stop once a lease has passed since it
//!   was last confirmed; answered again, the Journey goes on, sent once.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use journey::JourneyState;
use persist::storage::XmipStorage;
use transport::TransportError;
use xcore::JourneyId;
use xmip_core_runtime::fixture::{Answer, FarEnd, Operation};
use xmip_core_runtime::ledger::CHUNK;
use xmip_core_runtime::message_path::carry;
use xmip_core_runtime::sending::Sends;

use super::receive_cycle::{Sender, node, on_node};
use super::sending::{
    Pinned, dispatching, interleaving, journey, onward, order, out, quick, taking, telling, took,
    until,
};

/// A far end that says it was reached, holds its send until `go`, and
/// then refuses it for good.
fn held_up(reached: &Arc<AtomicBool>, go: &Arc<AtomicBool>) -> Answer {
    let (reached, go) = (Arc::clone(reached), Arc::clone(go));
    Box::new(move |_| {
        reached.store(true, Ordering::SeqCst);
        until(|| go.load(Ordering::SeqCst), "the send let go");
        Err(TransportError {
            message: "refused once let go".to_string(),
            retryable: false,
        })
    })
}

/// The test node sending `Out` to `first`, failing over to `second`.
fn failing_over(first: FarEnd, second: FarEnd) -> Sender {
    let port = out(|port| {
        port.send_locations = vec!["First".to_string(), "Second".to_string()];
        port.failover = Some(configure::Failover::Next);
    });
    Sender {
        sends: Sends {
            locations: vec![first.at("First"), second.at("Second")],
            ports: vec![port],
            groups: Vec::new(),
        },
        tuning: quick(),
        node: node(),
        audit: None,
    }
}

/// The Journey `id` taken up by another node once its claim lapsed on
/// `clock`: moved on past every renewal that lands meanwhile.
fn taken_over(clock: &Pinned, storage: &dyn XmipStorage, id: JourneyId) {
    let other = configure::fixture::test_cluster().node_scope(1);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        clock.pass(Duration::from_secs(1));
        let lease = Duration::from_secs(60);
        if storage
            .claim(id, &other, 0x07e5, lease)
            .expect("asked")
            .is_some()
        {
            return;
        }
        assert!(Instant::now() < deadline, "never taken over");
    }
}

#[test]
fn a_send_whose_claim_is_found_another_s_tries_no_further_location_and_writes_nothing() {
    let clock = Arc::new(Pinned::default());
    let storage = telling(&clock);
    let (reached, go) = (Arc::default(), Arc::default());
    let (first, _) = FarEnd::answering(held_up(&reached, &go));
    let (second, taken) = FarEnd::answering(taking());
    on_node(
        &storage,
        (CHUNK, &onward()),
        failing_over(first, second),
        |runtime, pickup, gate| {
            let ((id, before), _) = dispatching(runtime, |told| {
                let id = carry(runtime, pickup, gate, order(1)).journeys[0].journey_id();
                until(
                    || reached.load(Ordering::SeqCst),
                    "the first Location reached",
                );
                let before = storage.read_journey(id).expect("read");
                taken_over(&clock, storage.as_ref(), id);
                until(|| runtime.send.is_lost(id), "the loss found by a renewal");
                assert!(!runtime.send.holds(id), "no longer this node's to send");
                go.store(true, Ordering::SeqCst);
                told.wait_for(id, "lost");
                (id, before)
            });
            assert_eq!(
                storage.read_journey(id).expect("read"),
                before,
                "nothing written over the other holder's"
            );
            assert_eq!(runtime.send.figures()["Out"].lost, 1, "counted at its Port");
        },
    );
    assert!(took(&taken).is_empty(), "the second Location never tried");
}

#[test]
fn a_renewal_storage_does_not_answer_is_shown_and_stops_attempts_after_a_lease() {
    let (interleaved, storage) = interleaving();
    let (reached, go) = (Arc::default(), Arc::default());
    let (first, _) = FarEnd::answering(held_up(&reached, &go));
    let (second, taken) = FarEnd::answering(taking());
    on_node(
        &storage,
        (CHUNK, &onward()),
        failing_over(first, second),
        |runtime, pickup, gate| {
            let (id, _) = dispatching(runtime, |told| {
                let id = carry(runtime, pickup, gate, order(1)).journeys[0].journey_id();
                until(
                    || reached.load(Ordering::SeqCst),
                    "the first Location reached",
                );
                interleaved.fail(Operation::Renew, u32::MAX);
                let unconfirmed = || {
                    let out = &runtime.send.figures()["Out"];
                    out.unconfirmed == 1 && out.unanswered_since.is_some()
                };
                until(unconfirmed, "the unconfirmed claim shown at its Port");
                until(
                    || !runtime.send.holds(id),
                    "a lease past its last confirmation",
                );
                go.store(true, Ordering::SeqCst);
                told.wait_for(id, "waiting");
                assert!(took(&taken).is_empty(), "the second Location not tried");
                interleaved.heal();
                told.wait_for(id, "completed");
                id
            });
            assert_eq!(journey(storage.as_ref(), id).state, JourneyState::Completed);
        },
    );
    assert_eq!(took(&taken), ["order 1"], "sent once, once answered again");
}
