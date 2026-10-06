//! Another writer landing between a read of a Journey and the claim taken
//! to act on it (`runtime-model.md` section 3, *A claim is not ordering*),
//! placed there by Xmip Storage that lets it in first
//! (`xmip_core_runtime::fixture::Failing::before`), never by timing:
//!
//! - an operator's Retry that read a Journey Failed, while another node
//!   retried and sent it before the claim, is refused in words and writes
//!   nothing: the Journey stays Completed and is not sent again;
//! - a scan of a Sequential Send Port that read a Journey waiting, while
//!   another node sent it and let go of its place before the claim, does
//!   not send it a second time;
//! - a Publication whose answer was lost, asked again after its claim
//!   lapsed and another node sent its Journey, writes nothing back and
//!   sends nothing from here: the Journey stays Completed, out of its
//!   queue, delivered once.

use journey::JourneyState;
use observe::Act;
use route::Subscriber;
use xmip_core_runtime::fixture::{FarEnd, Operation};
use xmip_core_runtime::ledger::CHUNK;
use xmip_core_runtime::message_path::carry;

use super::receive_cycle::{node, on_node, on_runtime};
use super::sending::{
    Pinned, dispatching, interleaving, journey, onward, order, out, refusing, sender,
    sent_elsewhere, taking, telling, took, waiting,
};

#[test]
fn a_retry_of_a_journey_another_writer_moved_after_it_was_read_is_refused_and_writes_nothing() {
    let (interleaved, storage) = interleaving();
    let (far, taken) = FarEnd::answering(refusing("the far end refused it", false));
    on_node(
        &storage,
        (CHUNK, &onward()),
        sender(node(), far, out(|_| {})),
        |runtime, pickup, gate| {
            let ((), _) = dispatching(runtime, |told| {
                let id = carry(runtime, pickup, gate, order(1)).journeys[0].journey_id();
                told.wait_for(id, "failed");
            });
            let id = waiting(runtime)[0];
            let queue = runtime.send.queue(&Subscriber::SendPort("Out".to_string()));
            let elsewhere = std::sync::Arc::clone(&storage);
            interleaved.before(
                Operation::Claim,
                Box::new(move || sent_elsewhere(elsewhere.as_ref(), queue, id)),
            );

            let acted = runtime.send.act(&id.to_string(), Act::Retry, "ilian");

            let said = acted.expect_err("refused");
            assert!(
                said.starts_with("REFUSED") && said.contains("changed"),
                "{said}"
            );
            assert_eq!(
                journey(storage.as_ref(), id).state,
                JourneyState::Completed,
                "the other writer's state stands"
            );
            assert!(waiting(runtime).is_empty(), "not put back in its queue");
        },
    );
    assert!(took(&taken).is_empty(), "never sent from here");
}

#[test]
fn a_sequential_scan_never_sends_a_journey_another_node_sent_between_its_read_and_its_claim() {
    let (interleaved, storage) = interleaving();
    // Published by a node that sends nothing: nothing is claimed at the
    // Publication, so the scan is the first to take each.
    let ids = on_runtime(&storage, CHUNK, |runtime, pickup, gate| {
        [1, 2].map(|number| carry(runtime, pickup, gate, order(number)).journeys[0].journey_id())
    });
    let (far, taken) = FarEnd::answering(taking());
    let sequential = out(|port| {
        port.execution_style = Some(configure::ExecutionStyle::Sequential);
        port.on_failure = Some(configure::OnFailure::Block);
    });
    on_node(
        &storage,
        (CHUNK, &onward()),
        sender(node(), far, sequential),
        |runtime, _, _| {
            let queue = runtime.send.queue(&Subscriber::SendPort("Out".to_string()));
            let elsewhere = std::sync::Arc::clone(&storage);
            let first = ids[0];
            interleaved.before(
                Operation::Claim,
                Box::new(move || sent_elsewhere(elsewhere.as_ref(), queue, first)),
            );
            dispatching(runtime, |told| told.wait_for(ids[1], "completed"));
            assert_eq!(
                journey(storage.as_ref(), ids[0]).state,
                JourneyState::Completed
            );
        },
    );
    assert_eq!(
        took(&taken),
        ["order 2"],
        "the first went once, from elsewhere"
    );
}

#[test]
fn a_publication_asked_again_after_a_lost_answer_never_resends_what_another_node_sent() {
    let clock = std::sync::Arc::new(Pinned::default());
    let failing = xmip_core_runtime::fixture::Failing::over(telling(&clock));
    let storage: std::sync::Arc<dyn persist::storage::XmipStorage> = failing.clone();
    let (far, taken) = FarEnd::answering(taking());
    // No scan of this node's: the lapsed claim is the other node's to take
    // up, between the clock passing and its claim, never a race with a scan
    // every 20 ms that took it first under load.
    let mut sends = sender(node(), far, out(|_| {}));
    sends.tuning.send_scan = std::time::Duration::from_secs(3600);
    let id = on_node(
        &storage,
        (CHUNK, &onward()),
        sends,
        |runtime, pickup, gate| {
            let queue = runtime.send.queue(&Subscriber::SendPort("Out".to_string()));
            // Between the write and its lost answer the Publication's claim
            // lapses, and another node sends its Journey.
            let elsewhere = std::sync::Arc::clone(&storage);
            let lapsing = std::sync::Arc::clone(&clock);
            failing.lose_answer(Box::new(move || {
                lapsing.pass(std::time::Duration::from_secs(60));
                let read = elsewhere.read_held(queue, 0, 1).expect("read");
                sent_elsewhere(elsewhere.as_ref(), queue, read.held[0].hold.journey);
            }));
            let (id, _) = dispatching(runtime, |_| {
                let id = carry(runtime, pickup, gate, order(1)).journeys[0].journey_id();
                assert!(!runtime.send.holds(id), "not this node's to send");
                id
            });
            assert!(waiting(runtime).is_empty(), "not queued again");
            id
        },
    );
    assert_eq!(
        journey(storage.as_ref(), id).state,
        JourneyState::Completed,
        "the other node's send stands"
    );
    assert!(took(&taken).is_empty(), "never sent from here");
}
