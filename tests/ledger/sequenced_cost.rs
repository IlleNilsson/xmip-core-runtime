//! What exclusiveness costs a hop (the owner, 2026-10-27: *Measure a turn
//! check per hop against the millisecond rule*): before a Journey moves on
//! at a point, it asks whether its Stream heads its end-to-end sequences
//! and whether it heads each sequence of the point. A place seen at the
//! head is remembered, so the check that lets work go costs no Ledger read;
//! one waiting behind another asks the Ledger once each time it is looked
//! at. Both are measured here, over places of an in-order Send Port.

use std::time::{Duration, Instant};

use configure::OnFailure;
use journey::Journey;
use xmip_core_runtime::fixture::FarEnd;
use xmip_core_runtime::ledger::CHUNK;
use xmip_core_runtime::message_path::{ReceiveCycle, carry};
use xmip_core_runtime::sequence::{heads, stream_heads};

use super::receive_cycle::{node, on_node};
use super::say;
use super::sending::{in_order, memory, onward, order, out, sender};

/// Every place `journey` holds, checked as a hop checks them.
fn checked(storage: &dyn persist::storage::XmipStorage, journey: &Journey) -> bool {
    let member = journey.journey_id().value();
    stream_heads(storage, journey).expect("asked")
        && journey
            .sequences
            .iter()
            .all(|sequenced| heads(storage, sequenced.queue, member).expect("asked"))
}

fn median(mut spent: Vec<Duration>) -> (Duration, Duration) {
    spent.sort();
    (spent[spent.len() / 2], spent[spent.len() - 1])
}

#[test]
fn a_hops_check_of_its_sequences_costs_far_under_a_millisecond() {
    let storage = memory();
    let (far, _) = FarEnd::answering(Box::new(|_| Ok(())));
    let sending = sender(node(), far, out(in_order(OnFailure::Block)));
    on_node(
        &storage,
        (CHUNK, &onward()),
        sending,
        |runtime, pickup, gate| {
            let journeys: Vec<Journey> = (0..200)
                .map(|number| {
                    let carried = carry(runtime, pickup, gate, order(number));
                    assert_eq!(carried.cycle(), ReceiveCycle::Completed);
                    carried.journeys[0].clone()
                })
                .collect();
            let (head, behind) = journeys.split_first().expect("two hundred");
            assert!(checked(storage.as_ref(), head), "the first heads its key");
            let mut ahead = Vec::new();
            for _ in 0..200 {
                let began = Instant::now();
                assert!(checked(storage.as_ref(), head));
                ahead.push(began.elapsed());
            }
            let mut waiting = Vec::new();
            for journey in behind {
                let began = Instant::now();
                assert!(!checked(storage.as_ref(), journey), "behind the first");
                waiting.push(began.elapsed());
            }
            let (ahead, ahead_most) = median(ahead);
            let (waiting, waiting_most) = median(waiting);
            say(&format!(
                "a hop's sequence check: at the head median {ahead:?} (slowest {ahead_most:?}), \
             behind another median {waiting:?} (slowest {waiting_most:?})"
            ));
            // The millisecond rule is a release build's: a debug build's figures
            // are said and not held to it, as the estate's other figures are.
            if !cfg!(debug_assertions) {
                assert!(ahead < Duration::from_millis(1), "at the head: {ahead:?}");
                assert!(waiting < Duration::from_millis(1), "behind: {waiting:?}");
            }
        },
    );
}
