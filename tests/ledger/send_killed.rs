//! The send step killed at each of its steps (`runtime-model.md` section 3,
//! *What proves it*: *a kill at each step: nothing lost, and a repeat only
//! where at-least-once allows one*; *node failover by a lapsed claim*):
//!
//! - a node killed after its Publications and before it sent any: another
//!   node takes up every Journey it acknowledged once its claims lapse, and
//!   sends each;
//! - a node killed mid-send: the node restarted sends again every Journey
//!   it acknowledged, those it was sending among them — at least once,
//!   never lost.

use std::sync::{Arc, Mutex, PoisonError};

use persist::storage::XmipStorage;
use xcore::JourneyId;
use xmip_core_runtime::fixture::FarEnd;
use xmip_core_runtime::ledger::CHUNK;
use xmip_core_runtime::message_path::{ReceiveCycle, carry};
use xmip_core_runtime::send_step::{Departure, Ended, dispatch};

use super::receive_cycle::{node, on_node};
use super::sending::{dispatching, onward, order, out, sender};
use super::{STARTED, directory, heard, killed, say, spawn, test_node};

/// Carry orders one after the other through `runtime`, saying each whose
/// receive cycle completed — what its sender is acknowledged for — with
/// its Journey.
fn receive_saying(
    runtime: &xmip_core_runtime::message_path::Runtime<'_>,
    pickup: &xmip_core_runtime::pickup::Pickup,
    gate: &xmip_core_runtime::receiving::ReceiveGate,
) {
    for number in 0..1_000_000u32 {
        let carried = carry(runtime, pickup, gate, order(number));
        assert_eq!(carried.cycle(), ReceiveCycle::Completed);
        let journey = carried.journeys[0].journey_id().value();
        say(&format!("received {number} {journey}"));
    }
}

/// The child that publishes, claiming each Journey for its own send, and
/// is killed before it sends any: it never dispatches.
pub fn publish_until_killed(storage: &Arc<dyn XmipStorage>) {
    let (far, _) = FarEnd::answering(Box::new(|_| Ok(())));
    let sending = sender(node(), far, out(|_| {}));
    on_node(storage, (CHUNK, &onward()), sending, receive_saying);
}

/// The child that sends, its far end taking each Stream and never
/// answering, killed mid-send.
pub fn send_until_killed(storage: &Arc<dyn XmipStorage>) {
    let (far, _) = FarEnd::answering(Box::new(|bytes| {
        say(&format!("sending {}", String::from_utf8_lossy(bytes)));
        loop {
            std::thread::park();
        }
    }));
    let sending = sender(node(), far, out(|_| {}));
    on_node(
        storage,
        (CHUNK, &onward()),
        sending,
        |runtime, pickup, gate| {
            let ignored = |_: &Departure, _: &Ended| {};
            let ignored = &ignored;
            std::thread::scope(|scope| {
                scope.spawn(move || dispatch(scope, runtime, ignored));
                receive_saying(runtime, pickup, gate);
            });
        },
    );
}

/// One acknowledged receive as a child said it: its number and Journey.
fn acknowledged(said: &str) -> (u32, JourneyId) {
    let mut words = said.split_whitespace();
    let number = words.next().expect("a number").parse().expect("a number");
    let journey = words.next().expect("a Journey").parse().expect("a Journey");
    (number, JourneyId::new(journey))
}

/// Every receive the child said was acknowledged, before and as it died.
fn every_acknowledged(first: Vec<(u32, JourneyId)>, said: &[String]) -> Vec<(u32, JourneyId)> {
    let mut all = first;
    all.extend(
        said.iter()
            .filter_map(|line| line.find("received ").map(|at| &line[at + 9..]))
            .map(acknowledged),
    );
    all
}

/// Every one of `acknowledged` sent from the Ledger at `place` by the node
/// at `node`, once the dead node's claims lapsed: what its far end took.
fn sent_by(
    node: String,
    place: &std::path::Path,
    acknowledged: &[(u32, JourneyId)],
) -> Vec<String> {
    let storage = test_node(place);
    let (far, taken) = FarEnd::answering(Box::new(|_| Ok(())));
    on_node(
        &storage,
        (CHUNK, &onward()),
        sender(node, far, out(|_| {})),
        |runtime, _, _| {
            dispatching(runtime, |told| {
                for (_, journey) in acknowledged {
                    told.wait_for(*journey, "completed");
                }
            });
        },
    );
    drop(storage);
    let taken: &Mutex<Vec<Vec<u8>>> = &taken;
    taken
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
        .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
        .collect()
}

#[test]
fn a_node_killed_after_publication_and_before_send_leaves_every_journey_to_another_node() {
    let place = directory("unsent");
    let (child, lines) = spawn("publish", &place);
    let mut first = Vec::new();
    while first.len() < 20 {
        first.push(acknowledged(&heard(&lines, "received ", STARTED)));
    }
    let acknowledged = every_acknowledged(first, &killed(child, &lines));

    let other = configure::fixture::test_cluster().node_scope(1);
    let taken = sent_by(other, &place, &acknowledged);
    for (number, _) in &acknowledged {
        let expected = format!("order {number}");
        assert!(taken.contains(&expected), "{expected} lost");
    }
    let _ = std::fs::remove_dir_all(&place);
}

#[test]
fn a_node_killed_mid_send_sends_again_once_restarted_at_least_once_never_lost() {
    let place = directory("mid-send");
    let (child, lines) = spawn("sending", &place);
    let sending = heard(&lines, "sending ", STARTED);
    let mut first = Vec::new();
    while first.len() < 10 {
        first.push(acknowledged(&heard(&lines, "received ", STARTED)));
    }
    let said = killed(child, &lines);
    let acknowledged = every_acknowledged(first, &said);

    let taken = sent_by(node(), &place, &acknowledged);
    assert!(taken.contains(&sending), "{sending}, cut short, sent again");
    for (number, _) in &acknowledged {
        let expected = format!("order {number}");
        assert!(taken.contains(&expected), "{expected} lost");
    }
    let _ = std::fs::remove_dir_all(&place);
}
