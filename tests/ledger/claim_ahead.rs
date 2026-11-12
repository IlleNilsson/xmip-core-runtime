//! A Message taken from its queue is sent under a claim answered once
//! readable, and its far end sees it only once that claim is durable
//! (ADR-0018, amendment 2026-11-12): the send step's scan claims ahead of
//! the claim's sync, reads and prepares the send meanwhile, and lets out
//! once the claim is durable and still its node's.
//!
//! - a far end that holds its delivery back is written while the claim's
//!   sync is held, and takes nothing until the sync is let go;
//! - one whose claim's sync fails abandons what it wrote: its far end never
//!   sees it, and the pass counts no try;
//! - one that cannot hold back is not reached before the claim is durable,
//!   though the Message was read under the readable claim;
//! - over the wire, the claim's word read from its second frame lets the
//!   send out; a word that never comes abandons it, and once the Storage
//!   node syncs, the Message is sent once, its abandoned passes counting no
//!   try.
//!
//! Each Message is published by a node that sends nothing, and durable,
//! before the sending node's Storage node holds its syncs: what is held is
//! the claim's sync alone.

use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use xcore::lock::Locked;

use persist::fixture::{Hooked, Hooks, Memory};
use persist::storage::{Embedded, StorageClient, StorageServer, XmipStorage, client};
use secret::{Held, KekName};
use xcore::JourneyId;
use xmip_core_runtime::fixture::{Authority, Failing, FarEnd, Operation};
use xmip_core_runtime::ledger::CHUNK;
use xmip_core_runtime::message_path::{ReceiveCycle, carry};

use super::receive_cycle::{Sender, on_node, on_runtime};
use super::sending::{dispatching, journey, onward, order, out, sender, taking, took, until};

/// How long a test waits for a held sync before it fails.
const PATIENCE: Duration = Duration::from_secs(10);

/// A test Storage node in memory whose runtime database's syncs `hooks`
/// steer.
fn hooked() -> (Arc<dyn XmipStorage>, Arc<Hooks>) {
    let hooks = Arc::new(Hooks::default());
    let keys = Held::new(secret::fixture::Memory::default());
    let kek = KekName::new("storage").expect("a name");
    let runtime = Hooked::new(Memory::default(), &hooks);
    let node = Embedded::open(runtime, Memory::default(), Memory::default(), &keys, &kek);
    (Arc::new(node.expect("opened")), hooks)
}

/// `beneath` served on loopback, and a node's Xmip Storage reaching it over
/// the wire, each read bounded by `timeout`.
fn over_the_wire(
    beneath: &Arc<dyn XmipStorage>,
    timeout: Duration,
) -> (StorageServer, Arc<dyn XmipStorage>) {
    let authority = Authority::new();
    let listener = TcpListener::bind("127.0.0.1:0").expect("bound");
    let identity = authority.identity("storage");
    let server = StorageServer::start(Arc::clone(beneath), listener, &identity).expect("served");
    let at = [server.address().to_string()];
    let identity = authority.identity("node");
    let reached = StorageClient::new(&at, &identity, timeout, client::PASS_OVER);
    (server, Arc::new(reached.expect("a client")))
}

/// `order 1` published, durable, by a node that sends nothing: what the
/// sending node takes from its queue.
fn published(storage: &Arc<dyn XmipStorage>) -> JourneyId {
    on_runtime(storage, CHUNK, |runtime, pickup, gate| {
        let carried = carry(runtime, pickup, gate, order(1));
        assert_eq!(carried.cycle(), ReceiveCycle::Completed);
        carried.journeys[0].journey_id()
    })
}

/// The test cluster's second node sending `Out` to `far`, its claims held
/// for a lease no test outlasts.
fn patient(far: FarEnd) -> Sender {
    let node = configure::fixture::test_cluster().node_scope(1);
    let mut sending = sender(node, far, out(|_| {}));
    sending.tuning.send_lease = Duration::from_secs(30);
    sending
}

#[test]
fn a_taken_send_is_prepared_under_a_readable_claim_and_let_out_once_it_is_durable() {
    let (storage, hooks) = hooked();
    let id = published(&storage);
    let (far, taken) = FarEnd::answering(taking());
    let (far, prepared) = far.holding();
    on_node(&storage, (CHUNK, &onward()), patient(far), |sends, _, _| {
        hooks.hold_syncs();
        dispatching(sends, |told| {
            until(
                || prepared.locked().len() == 1,
                "written where no reader sees it",
            );
            assert!(hooks.wait_held(PATIENCE), "the claim's sync held");
            assert!(
                took(&taken).is_empty(),
                "nothing let out before it is durable"
            );
            hooks.release_syncs();
            told.wait_for(id, "completed");
        });
        let figures = sends.send.figures();
        let steps = &figures["Out"].steps;
        assert!(steps.contains("taken from its queue"), "{steps}");
        assert!(steps.contains("durable in the Ledger"), "{steps}");
    });
    assert_eq!(took(&taken), ["order 1"]);
    assert!(
        prepared.locked().is_empty(),
        "let out, nothing left written"
    );
}

#[test]
fn a_taken_send_whose_claim_is_never_durable_is_abandoned_unseen_and_counts_no_try() {
    let (storage, hooks) = hooked();
    let id = published(&storage);
    let (far, taken) = FarEnd::answering(taking());
    let (far, prepared) = far.holding();
    on_node(&storage, (CHUNK, &onward()), patient(far), |sends, _, _| {
        hooks.hold_syncs();
        dispatching(sends, |told| {
            until(
                || prepared.locked().len() == 1,
                "written where no reader sees it",
            );
            assert!(hooks.wait_held(PATIENCE), "the claim's sync held");
            // The sync fails: the Storage node stops, the claim lost with it.
            hooks.fail_syncs(true);
            hooks.release_syncs();
            told.wait_for(id, "untried");
        });
    });
    assert!(took(&taken).is_empty(), "its far end never saw it");
    assert!(
        prepared.locked().is_empty(),
        "what was written is abandoned"
    );
}

#[test]
fn a_send_that_cannot_hold_back_reaches_no_far_end_before_its_claim_is_durable() {
    let (beneath, hooks) = hooked();
    let id = published(&beneath);
    let failing = Failing::over(Arc::clone(&beneath));
    let storage: Arc<dyn XmipStorage> = Arc::clone(&failing) as _;
    // The far end notes whether a send reached it before the claim's sync
    // was let go.
    let (released, early) = (
        Arc::new(AtomicBool::new(false)),
        Arc::new(AtomicBool::new(false)),
    );
    let (seen, noted) = (Arc::clone(&released), Arc::clone(&early));
    let (far, taken) = FarEnd::answering(Box::new(move |_| {
        noted.fetch_or(!seen.load(Ordering::SeqCst), Ordering::SeqCst);
        Ok(())
    }));
    on_node(&storage, (CHUNK, &onward()), patient(far), |sends, _, _| {
        hooks.hold_syncs();
        dispatching(sends, |told| {
            until(
                || failing.asked_times(Operation::ReadClaimed) >= 1,
                "read under the readable claim",
            );
            assert!(hooks.wait_held(PATIENCE), "the claim's sync held");
            // A while for a send that would not wait to reach its far end.
            std::thread::sleep(Duration::from_millis(50));
            assert!(
                took(&taken).is_empty(),
                "no byte before the claim is durable"
            );
            released.store(true, Ordering::SeqCst);
            hooks.release_syncs();
            told.wait_for(id, "completed");
        });
        let figures = sends.send.figures();
        let steps = &figures["Out"].steps;
        assert!(steps.contains("durable in the Ledger"), "{steps}");
    });
    assert!(
        !early.load(Ordering::SeqCst),
        "reached only once the claim synced"
    );
    assert_eq!(took(&taken), ["order 1"]);
}

#[test]
fn a_send_over_the_wire_is_let_out_once_its_claims_second_frame_says_durable() {
    let (beneath, hooks) = hooked();
    let id = published(&beneath);
    let (server, storage) = over_the_wire(&beneath, PATIENCE);
    let (far, taken) = FarEnd::answering(taking());
    let (far, prepared) = far.holding();
    on_node(&storage, (CHUNK, &onward()), patient(far), |sends, _, _| {
        hooks.hold_syncs();
        dispatching(sends, |told| {
            until(
                || prepared.locked().len() == 1,
                "written where no reader sees it",
            );
            assert!(hooks.wait_held(PATIENCE), "the claim's sync held");
            assert!(
                took(&taken).is_empty(),
                "nothing let out before it is durable"
            );
            hooks.release_syncs();
            told.wait_for(id, "completed");
        });
    });
    assert_eq!(took(&taken), ["order 1"]);
    server.stop();
}

#[test]
fn a_send_whose_claims_word_never_comes_over_the_wire_is_abandoned_and_sent_once_after() {
    let (beneath, hooks) = hooked();
    let id = published(&beneath);
    // No word within half a second: every claim's notice is lost while
    // the Storage node's syncs are held.
    let (server, storage) = over_the_wire(&beneath, Duration::from_millis(500));
    let (far, taken) = FarEnd::answering(taking());
    let (far, prepared) = far.holding();
    on_node(&storage, (CHUNK, &onward()), patient(far), |sends, _, _| {
        hooks.hold_syncs();
        dispatching(sends, |told| {
            until(
                || prepared.locked().len() == 1,
                "written where no reader sees it",
            );
            told.wait_for(id, "untried");
            assert!(
                took(&taken).is_empty(),
                "abandoned, its far end never saw it"
            );
            hooks.release_syncs();
            told.wait_for(id, "completed");
        });
    });
    assert_eq!(took(&taken), ["order 1"], "sent once");
    assert!(prepared.locked().is_empty(), "nothing left written");
    let sent = journey(beneath.as_ref(), id);
    assert_eq!(sent.attempts.tries, 1, "no abandoned pass counted a try");
    server.stop();
}
