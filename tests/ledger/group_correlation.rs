//! A Send Port Group naming a Correlation (the owner, 2026-10-27: *The
//! result is a set of ports that succeeded or failed … one has to
//! accumulate the results*; ADR-0024 and ADR-0066, amendments 2026-10-27):
//!
//! - a delivery's members go side by side, and the next delivery of the
//!   same key waits until every member of the one before has succeeded or
//!   failed;
//! - where that set holds a failure and the Correlation blocks, its key
//!   stays held until an operator retries or dismisses the failed member;
//!   where it skips, the next delivery goes on.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use configure::{OnFailure, SendPortGroup};
use journey::JourneyState;
use observe::Act;
use xcore::JourneyId;
use xmip_core_runtime::fixture::FarEnd;
use xmip_core_runtime::ledger::CHUNK;
use xmip_core_runtime::message_path::{Runtime, carry};
use xmip_core_runtime::pickup::Pickup;
use xmip_core_runtime::receiving::ReceiveGate;
use xmip_core_runtime::sequence::{Point, PointKind};
use xmip_core_runtime::work_step::{KeyWord, ResolvedSet};

use super::message_act::broken_for;
use super::receive_cycle::{node, on_node, on_working_node};
use super::send_group::to_both;
use super::sending::{
    dispatching, journey, memory, order, out, port, senders, taking, took, until,
};

/// Three orders carried to the Group `Both` of `Bad` and `Out`, keyed by
/// the Group alone and failing as `on_failure` says, `Bad` refusing `order
/// 1` until fixed: what `Bad` and `Out` took while the first delivery's
/// failure stood, and once its member was retried.
fn delivered(on_failure: OnFailure, late: bool) -> (Vec<String>, Vec<String>) {
    let storage = memory();
    let fixed = Arc::new(AtomicBool::new(false));
    let (bad, bad_took) = FarEnd::answering(broken_for(1, &fixed));
    let (out_end, out_took) = FarEnd::answering(taking());
    let group = SendPortGroup {
        name: "Both".to_string(),
        send_ports: vec!["Bad".to_string(), "Out".to_string()],
        correlation: Some("PerGroup".to_string()),
    };
    let mut sending = senders(
        node(),
        vec![(bad, port("Bad", |_| {})), (out_end, out(|_| {}))],
        vec![group],
    );
    sending.sends.points.push(Point {
        kind: PointKind::SendPortGroup,
        name: "Both".to_string(),
        set: ResolvedSet {
            name: "PerGroup".to_string(),
            keys: vec![KeyWord::SendPortGroup],
        },
        on_failure,
    });
    let mut standing = (Vec::new(), Vec::new());
    let run = |runtime: &Runtime<'_>, pickup: &Pickup, gate: &ReceiveGate| {
        dispatching(runtime, |told| {
            let deliveries: Vec<Vec<JourneyId>> = (1..=3)
                .map(|n| {
                    let carried = carry(runtime, pickup, gate, order(n));
                    carried.journeys.iter().map(|j| j.journey_id()).collect()
                })
                .collect();
            let member = |delivery: usize, port: &str| {
                deliveries[delivery]
                    .iter()
                    .copied()
                    .find(|id| journey(storage.as_ref(), *id).send_port.as_deref() == Some(port))
                    .expect("a member at the Port")
            };
            let failed = member(0, "Bad");
            told.wait_for(failed, "failed");
            told.wait_for(member(0, "Out"), "completed");
            let later = || {
                for delivery in 1..3 {
                    for at in ["Bad", "Out"] {
                        told.wait_for(member(delivery, at), "completed");
                    }
                }
            };
            if on_failure == OnFailure::Block {
                // Several scans: no member of a later delivery moves.
                let scans = Instant::now() + Duration::from_millis(200);
                until(|| Instant::now() >= scans, "a few scans");
            } else {
                later();
            }
            standing = (sorted(took(&bad_took)), sorted(took(&out_took)));
            fixed.store(true, std::sync::atomic::Ordering::Release);
            runtime
                .send
                .act(&failed.to_string(), Act::Retry, "ilian")
                .expect("retried");
            told.wait_for(failed, "completed");
            later();
            let retried = journey(storage.as_ref(), failed);
            assert_eq!(retried.state, JourneyState::Completed);
        });
    };
    if late {
        // The Location keeps its own sequence: each Stream heads it in
        // turn, and its Journeys take their places once it does.
        on_working_node(&storage, (CHUNK, &to_both()), (sending, Vec::new()), run);
    } else {
        on_node(&storage, (CHUNK, &to_both()), sending, run);
    }
    let every = ["order 1", "order 2", "order 3"];
    assert_eq!(sorted(took(&bad_took)), every, "Bad took every one");
    assert_eq!(sorted(took(&out_took)), every, "Out took every one");
    standing
}

fn sorted(mut taken: Vec<String>) -> Vec<String> {
    taken.sort();
    taken
}

#[test]
fn a_groups_key_is_held_until_every_member_of_its_delivery_has_ended_and_blocks_on_a_failure() {
    let (bad, out) = delivered(OnFailure::Block, false);
    assert_eq!(bad, [] as [String; 0], "Bad took nothing while it failed");
    assert_eq!(out, ["order 1"], "Out waited for the failed set's key");
}

#[test]
fn a_groups_key_that_skips_lets_the_next_delivery_go_past_a_failed_member() {
    let (bad, out) = delivered(OnFailure::Skip, false);
    assert_eq!(bad, ["order 2", "order 3"], "the next deliveries went on");
    assert_eq!(out, ["order 1", "order 2", "order 3"]);
}

#[test]
fn a_groups_place_taken_late_once_its_stream_heads_holds_the_same() {
    let (bad, out) = delivered(OnFailure::Block, true);
    assert_eq!(bad, [] as [String; 0], "Bad took nothing while it failed");
    assert_eq!(out, ["order 1"], "Out waited for the failed set's key");
}
