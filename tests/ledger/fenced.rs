//! A node killed holding a key (the owner, 2026-10-27: *A node dies holding
//! a key. Its claim through Xmip Storage expires and passes on with a
//! fencing token*): the Message heading its Send Port's sequence is cut
//! short mid-send, its claim lapses, another node takes it over under a
//! larger fence and sends it first, and every Message behind it follows in
//! the order the Ledger wrote them — the key passed on with the Message,
//! never lost and never overtaken.

use std::sync::{Arc, Mutex, PoisonError};

use configure::OnFailure;
use persist::storage::XmipStorage;
use xmip_core_runtime::fixture::FarEnd;
use xmip_core_runtime::ledger::CHUNK;
use xmip_core_runtime::send_step::{Departure, Ended, dispatch};

use super::child_process::ChildProcess;
use super::receive_cycle::{node, on_node};
use super::send_killed::{acknowledged, every_acknowledged, receive_saying, sent_through};
use super::sending::{in_order, onward, out, sender};
use super::{STARTED, directory, say};

/// The child that sends `Out` one at a time, its far end saying the first
/// Stream it is handed and the fence it came under and never answering,
/// killed mid-send holding the key.
pub fn send_in_order_until_killed(storage: &Arc<dyn XmipStorage>) {
    let fences: Arc<Mutex<Vec<u64>>> = Arc::default();
    let seen = Arc::clone(&fences);
    let (far, _) = FarEnd::answering(Box::new(move |bytes| {
        let fence = seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .last()
            .copied()
            .unwrap_or_default();
        say(&format!(
            "sending {} fence {fence}",
            String::from_utf8_lossy(bytes)
        ));
        loop {
            std::thread::park();
        }
    }));
    let sending = sender(node(), far.fencing(fences), out(in_order(OnFailure::Block)));
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

#[test]
fn a_node_killed_holding_a_key_passes_it_on_under_a_larger_fence_and_order_is_kept() {
    let place = directory("fenced");
    let child = ChildProcess::start("fenced", &place);
    let sending = child.heard("sending ", STARTED);
    let (cut_short, old_fence) = sending
        .split_once(" fence ")
        .map(|(body, fence)| {
            (
                body.to_string(),
                fence.trim().parse::<u64>().expect("a fence"),
            )
        })
        .expect("a body and its fence");
    let mut first = Vec::new();
    while first.len() < 10 {
        first.push(acknowledged(&child.heard("received ", STARTED)));
    }
    let acknowledged = every_acknowledged(first, &child.killed());

    let other = configure::fixture::test_cluster().node_scope(1);
    let (taken, fences) = sent_through(
        other,
        &place,
        &acknowledged,
        out(in_order(OnFailure::Block)),
    );
    assert_eq!(taken.first(), Some(&cut_short), "the key's head goes first");
    let mut numbers: Vec<u32> = acknowledged.iter().map(|(n, _)| *n).collect();
    numbers.sort_unstable();
    let expected: Vec<String> = numbers.iter().map(|n| format!("order {n}")).collect();
    let sent: Vec<String> = taken
        .iter()
        .filter(|t| expected.contains(t))
        .cloned()
        .collect();
    assert_eq!(
        sent, expected,
        "one at a time, in the Ledger's order, none lost"
    );
    assert!(
        fences[0] > old_fence,
        "taken over under fence {} after {old_fence}",
        fences[0]
    );
    let _ = std::fs::remove_dir_all(&place);
}
