//! The send step, reading its Journeys from the Ledger (`runtime-model.md`
//! section 10, *How a send runs*):
//!
//! - a send that fails is written Failed on its Journey with why, its
//!   Message with it, and the sender of the receive was acknowledged all
//!   the same: the receive cycle completed before anything was sent;
//! - a send that succeeds is written Completed;
//! - a retry waiting for its backoff holds no thread: its due time is the
//!   claim kept in the Ledger, a stop does not wait it out and gives the
//!   claim back, and a short one is tried again and sent;
//! - a Sequential Send Port keeps its order, and a Journey of it that
//!   failed blocks its sequence, or is set aside, as `on_failure` says.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use configure::{ExecutionStyle, OnFailure, Retry};
use journey::JourneyState;
use transport::TransportError;
use xcore::JourneyId;
use xmip_core_runtime::fixture::FarEnd;
use xmip_core_runtime::ledger::CHUNK;
use xmip_core_runtime::message_path::{ReceiveCycle, carry};

use super::receive_cycle::{node, on_node};
use super::sending::{
    dispatching, journey, memory, onward, order, out, refusing, sender, taking, took, until,
    waiting,
};

#[test]
fn a_send_that_fails_is_written_failed_with_why_and_its_sender_was_acknowledged() {
    let storage = memory();
    let (far, taken) = FarEnd::answering(refusing("the far end refused it", false));
    let sending = sender(node(), far, out(|_| {}));
    on_node(
        &storage,
        (CHUNK, &onward()),
        sending,
        |runtime, pickup, gate| {
            dispatching(runtime, |told| {
                let carried = carry(runtime, pickup, gate, order(1));
                assert_eq!(carried.cycle(), ReceiveCycle::Completed, "acknowledged");
                let id = carried.journeys[0].journey_id();
                told.wait_for(id, "failed");

                let failed = journey(storage.as_ref(), id);
                assert_eq!(failed.state, JourneyState::Failed);
                let said = &failed.entries().last().expect("its send").outcome;
                assert!(said.contains("the far end refused it"), "{said}");
                let message = failed.messages()[0].message_id;
                assert!(
                    storage.read_message(message).expect("read").is_some(),
                    "kept"
                );
                assert!(waiting(runtime).is_empty(), "out of its queue, not lost");
                assert!(took(&taken).is_empty());
                let figures = &runtime.send.figures()["Out"];
                assert_eq!((figures.sent, figures.failed), (0, 1));
                let (journey, why) = figures.last_failure.clone().expect("visible");
                assert_eq!(journey, id.to_string());
                assert!(why.contains("the far end refused it"), "{why}");
            });
        },
    );
}

#[test]
fn a_send_that_succeeds_is_written_completed_and_leaves_its_queue() {
    let storage = memory();
    let (far, taken) = FarEnd::answering(taking());
    let sending = sender(node(), far, out(|_| {}));
    on_node(
        &storage,
        (CHUNK, &onward()),
        sending,
        |runtime, pickup, gate| {
            dispatching(runtime, |told| {
                let carried = carry(runtime, pickup, gate, order(1));
                let id = carried.journeys[0].journey_id();
                told.wait_for(id, "completed");
                assert_eq!(journey(storage.as_ref(), id).state, JourneyState::Completed);
                assert_eq!(took(&taken), ["order 1"]);
                assert!(waiting(runtime).is_empty());
                assert_eq!(runtime.send.figures()["Out"].sent, 1);
            });
        },
    );
}

#[test]
fn a_retry_waiting_for_its_backoff_holds_no_thread_and_a_stop_gives_its_claim_back() {
    let storage = memory();
    let (far, _) = FarEnd::answering(refusing("the far end is down", true));
    let retrying = out(|port| {
        port.retry = Some(Retry {
            attempts: 3,
            backoff: "1h".to_string(),
        });
    });
    let sending = sender(node(), far, retrying);
    let mut id = None;
    on_node(
        &storage,
        (CHUNK, &onward()),
        sending,
        |runtime, pickup, gate| {
            let ((), closed) = dispatching(runtime, |told| {
                let carried = carry(runtime, pickup, gate, order(1));
                let waits = carried.journeys[0].journey_id();
                told.wait_for(waits, "waiting");
                let recovering = journey(storage.as_ref(), waits);
                assert_eq!(recovering.state, JourneyState::Recovering);
                let said = &recovering.entries().last().expect("its try").outcome;
                assert!(said.contains("tried again in"), "{said}");
                assert_eq!(runtime.send.figures()["Out"].waiting, 1);
                assert_eq!(waiting(runtime), [waits], "still in its queue");
                let other = configure::fixture::test_cluster().node_scope(1);
                let taken = storage.claim(waits, &other, 7, Duration::from_secs(30));
                assert_eq!(
                    taken.expect("asked"),
                    None,
                    "its claim kept to the due time"
                );
                id = Some(waits);
            });
            assert!(
                closed < Duration::from_secs(1),
                "an hour's backoff held nothing: {closed:?}"
            );
        },
    );
    let other = configure::fixture::test_cluster().node_scope(1);
    let id = id.expect("waited");
    let taken = storage.claim(id, &other, 8, Duration::from_secs(30));
    assert!(taken.expect("asked").is_some(), "given back at the stop");
}

#[test]
fn a_retry_due_is_tried_again_on_the_active_location_and_sent() {
    let storage = memory();
    let tries = Arc::new(AtomicU32::new(0));
    let counted = Arc::clone(&tries);
    let (far, taken) = FarEnd::answering(Box::new(move |_| {
        if counted.fetch_add(1, Ordering::Relaxed) < 2 {
            return Err(TransportError {
                message: "not yet".to_string(),
                retryable: true,
            });
        }
        Ok(())
    }));
    let retrying = out(|port| {
        port.retry = Some(Retry {
            attempts: 2,
            backoff: "20ms".to_string(),
        });
    });
    let sending = sender(node(), far, retrying);
    on_node(
        &storage,
        (CHUNK, &onward()),
        sending,
        |runtime, pickup, gate| {
            dispatching(runtime, |told| {
                let carried = carry(runtime, pickup, gate, order(1));
                let id = carried.journeys[0].journey_id();
                told.wait_for(id, "completed");
                assert_eq!(tries.load(Ordering::Relaxed), 3, "once, and again twice");
                assert_eq!(took(&taken), ["order 1"]);
                let sent = journey(storage.as_ref(), id);
                assert_eq!(sent.state, JourneyState::Completed);
                let tried: Vec<&str> = sent.entries().iter().map(|e| e.action.as_str()).collect();
                assert_eq!(tried, ["send", "send", "send"], "each try recorded");
            });
        },
    );
}

/// `count` orders carried through a Sequential `Out`, the one numbered
/// `refused` refused for good by its far end; what the far end took once
/// every other has ended or a few scans have passed.
fn in_sequence(on_failure: OnFailure, count: u32, refused: u32) -> Vec<String> {
    let storage = memory();
    let refusing = format!("order {refused}");
    let (far, taken) = FarEnd::answering(Box::new(move |bytes| {
        if bytes == refusing.as_bytes() {
            return Err(TransportError {
                message: "refused for good".to_string(),
                retryable: false,
            });
        }
        Ok(())
    }));
    let sequential = out(|port| {
        port.execution_style = Some(ExecutionStyle::Sequential);
        port.on_failure = Some(on_failure);
    });
    let sending = sender(node(), far, sequential);
    on_node(
        &storage,
        (CHUNK, &onward()),
        sending,
        |runtime, pickup, gate| {
            dispatching(runtime, |told| {
                let ids: Vec<JourneyId> = (1..=count)
                    .map(|number| {
                        carry(runtime, pickup, gate, order(number)).journeys[0].journey_id()
                    })
                    .collect();
                let failing = (refused as usize)
                    .checked_sub(1)
                    .filter(|place| *place < ids.len());
                if let Some(blocked) = failing {
                    told.wait_for(ids[blocked], "failed");
                }
                if let (OnFailure::Block, Some(blocked)) = (on_failure, failing) {
                    // Several scans: nothing after the one that failed moves.
                    let scans = Instant::now() + Duration::from_millis(200);
                    until(|| Instant::now() >= scans, "a few scans");
                    assert_eq!(waiting(runtime), ids[blocked..], "blocked behind it");
                    let failed = journey(storage.as_ref(), ids[blocked]);
                    assert_eq!(failed.state, JourneyState::Failed);
                } else {
                    for (place, id) in ids.iter().enumerate() {
                        if Some(place) != failing {
                            told.wait_for(*id, "completed");
                        }
                    }
                }
            });
        },
    );
    took(&taken)
}

#[test]
fn a_sequential_send_port_keeps_its_order() {
    let all: Vec<String> = (1..=20).map(|n| format!("order {n}")).collect();
    let sent = in_sequence(OnFailure::Skip, 20, 21);
    assert_eq!(sent, all);
}

#[test]
fn a_sequential_send_port_blocks_behind_a_failure_or_sets_it_aside_as_it_says() {
    let blocked = in_sequence(OnFailure::Block, 6, 3);
    assert_eq!(blocked, ["order 1", "order 2"]);
    let skipped = in_sequence(OnFailure::Skip, 6, 3);
    assert_eq!(
        skipped,
        ["order 1", "order 2", "order 4", "order 5", "order 6"]
    );
}
