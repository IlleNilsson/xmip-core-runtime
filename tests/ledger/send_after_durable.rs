//! The next Message of a sequence reaches its far end only once its
//! predecessor's hand-on is durable, wherever the predecessor was sent (the
//! owner, 2026-11-15: *Wait for the disk*, so the order survives any crash;
//! ADR-0018, amendment 2026-11-15). A place let go of is readable before
//! its sync: a node's own Publication, handing its Message on in memory,
//! read there that it heads its sequence while another node's hand-on of
//! the one ahead was still syncing, and sent once its own Publication was
//! durable — so a crash then would have the far end take the next before
//! the one ahead of it, sent again.
//!
//! Two nodes on one Storage node whose syncs the test holds, the Receive
//! Location's one sequence end to end: the first node sends the first
//! Stream to a far end that holds it; the second receives the next, its
//! Publication made durable before any sync is held; then the first's far
//! end is let go, its hand-on written and its sync held, and only then is
//! the second's Message handed on to its send, which reads its sequence's
//! head. Its far end holds its delivery back, so a send at its gate is seen
//! written and not let out.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use xcore::lock::Locked;

use persist::storage::XmipStorage;
use transport::TransportError;
use xmip_core_runtime::fixture::{Failing, FarEnd, Operation};
use xmip_core_runtime::ledger::CHUNK;
use xmip_core_runtime::message_path::carry;

use super::claim_ahead::hooked;
use super::receive_cycle::{Sender, node, on_working_node};
use super::sending::{PATIENCE, dispatching, onward, order, out, sender, taking, took, until};

/// How long a send that would not wait for the disk is given to reach its
/// far end: it reaches it within microseconds.
const SETTLE: Duration = Duration::from_millis(50);

/// The node at `node` sending `Out` to `far`, its claims held for a lease
/// no test outlasts and its queues read only as it starts and as it is
/// woken.
fn patient(node: String, far: FarEnd) -> Sender {
    let mut sending = sender(node, far, out(|_| {}));
    sending.tuning.send_lease = Duration::from_secs(30);
    sending.tuning.send_scan = Duration::from_secs(3600);
    sending
}

/// A far end holding each send until `open`, at most the tests' patience.
fn held_until(open: Arc<AtomicBool>) -> FarEnd {
    FarEnd::answering(Box::new(move |_| {
        let deadline = Instant::now() + PATIENCE;
        while !open.load(Ordering::SeqCst) {
            if Instant::now() >= deadline {
                return Err(TransportError {
                    message: "never let go".to_string(),
                    retryable: false,
                });
            }
            std::thread::yield_now();
        }
        Ok(())
    }))
    .0
}

/// Whether `happens` within `span`, looked at without a sleep.
fn within(span: Duration, happens: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + span;
    while Instant::now() < deadline {
        if happens() {
            return true;
        }
        std::thread::yield_now();
    }
    happens()
}

#[test]
fn a_message_its_publication_hands_on_waits_for_another_nodes_hand_on_ahead_to_be_durable() {
    let (beneath, hooks) = hooked();
    let failing = Failing::over(Arc::clone(&beneath));
    let second_storage: Arc<dyn XmipStorage> = Arc::clone(&failing) as _;
    let open = Arc::new(AtomicBool::new(false));
    let first_far = held_until(Arc::clone(&open));
    let first_asked = first_far.keys();
    let (second_far, second_taken) = FarEnd::answering(taking());
    let (second_far, second_written) = second_far.holding();
    let second = configure::fixture::test_cluster().node_scope(1);
    assert_ne!(second, node(), "two nodes");
    let firsts = (patient(node(), first_far), Vec::new());
    let seconds = (patient(second, second_far), Vec::new());
    let mut early = false;
    on_working_node(
        &beneath,
        (CHUNK, &onward()),
        firsts,
        |first, pickup, gate| {
            assert!(!gate.points.is_empty(), "the Location's own sequence");
            dispatching(first, |first_told| {
                let ahead = carry(first, pickup, gate, order(0)).journeys[0].clone();
                let received = ahead.received().expect("received here");
                let (sequence, origin) = (received.sequences[0], received.origin);
                until(|| first_asked.locked().len() == 1, "the first in its send");
                on_working_node(
                    &second_storage,
                    (CHUNK, &onward()),
                    seconds,
                    |at, pickup, gate| {
                        dispatching(at, |second_told| {
                            // Once the next is published, before it is handed on:
                            // its Publication durable, every sync held from then,
                            // and the first's hand-on written and syncing.
                            let (storage, holding, opening) =
                                (Arc::clone(&beneath), Arc::clone(&hooks), Arc::clone(&open));
                            failing.after(
                                Operation::Publish,
                                Box::new(move || {
                                    // A write that writes nothing is durable with the
                                    // latest batch: the Publication's, or after it.
                                    storage.renew(&[], PATIENCE).expect("durable so far");
                                    holding.hold_syncs();
                                    opening.store(true, Ordering::SeqCst);
                                    until(
                                        || {
                                            let page =
                                                storage.read_held(sequence, 0, 1).expect("read");
                                            page.held.first().is_none_or(|held| {
                                                held.hold.journey.value() != origin
                                            })
                                        },
                                        "the first's place let go of, readable",
                                    );
                                    assert!(holding.wait_held(PATIENCE), "its hand-on's sync held");
                                }),
                            );
                            let next = carry(at, pickup, gate, order(1)).journeys[0].journey_id();
                            until(
                                || {
                                    !second_written.locked().is_empty()
                                        || !second_taken.locked().is_empty()
                                },
                                "the next at its far end's gate",
                            );
                            early = within(SETTLE, || !second_taken.locked().is_empty());
                            hooks.release_syncs();
                            first_told.wait_for(ahead.journey_id(), "completed");
                            second_told.wait_for(next, "completed");
                        });
                    },
                );
            });
        },
    );
    assert!(
        !early,
        "the next was let out to its far end before the hand-on ahead of it was durable"
    );
    assert_eq!(took(&second_taken), ["order 1"]);
}
