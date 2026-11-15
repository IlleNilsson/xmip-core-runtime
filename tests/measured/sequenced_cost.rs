//! What exclusiveness costs a hop (the owner, 2026-10-27: *Measure a turn
//! check per hop against the millisecond rule*): before a Message moves on
//! at a point, it asks whether its Stream heads its end-to-end sequences
//! and whether it heads each sequence of the point. A place seen at the
//! head is remembered, so the check that lets work go costs no Ledger read;
//! one waiting behind another asks the Ledger once each time it is looked
//! at. Both are measured here, over places of an in-order Send Port. A
//! check waits on no wake, the Ledger read in process, so each is held by
//! the fastest of five under the millisecond (`xcore::latency::spread`).
//! Until 2026-11-15 their medians were held in a release build only, which
//! the estate never builds, so the hold never ran.

use std::time::{Duration, Instant};

use configure::OnFailure;
use journey::Journey;
use xcore::latency::spread;
use xmip_core_runtime::fixture::FarEnd;
use xmip_core_runtime::ledger::CHUNK;
use xmip_core_runtime::message_path::{ReceiveCycle, carry};
use xmip_core_runtime::sequence::{heads, stream_heads};

use super::receive_cycle::{node, on_node};
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
            let ahead = spread("a hop's sequence check at the head", ahead).fastest_of_five;
            let waiting = spread("a hop's sequence check behind another", waiting);
            let millisecond = Duration::from_millis(1);
            assert!(
                ahead < millisecond,
                "at the head: {ahead:?}, the fastest of five"
            );
            assert!(waiting.fastest_of_five < millisecond, "behind: {waiting:?}");
        },
    );
}
