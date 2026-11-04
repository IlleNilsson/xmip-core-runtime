//! A Work Process run from the Ledger (`runtime-model.md` section 22;
//! ADR-0066, amendment 2026-10-22): a BPMN 2.0 design compiled to its
//! program, opened as a flow, and Messages carried through a node's
//! receive path into it — correlated by a cluster's Correlation to one
//! Instance, collected in a Batch in the order they were received, the
//! batch published back through routing to a Send Port — its state in the
//! Ledger between turns, never in a thread (the design and its node,
//! `work_design.rs`):
//!
//! - one client's Messages make one Instance, its Batch holding them in the
//!   order received;
//! - two clients' Messages carried at once, from two threads, with the work
//!   step dispatching on its pool meanwhile, make two Instances, neither
//!   Message of a client overtaking another;
//! - a node killed mid-process, its Instance waiting for the rest of its
//!   Batch: the node started again over the same Ledger finishes it, from
//!   the Instance the Ledger keeps.
//!
//! What a turn costs beside its Ledger writes is the module's timing
//! program's (`tests/measured`).

use std::sync::Arc;
use std::time::{Duration, Instant};

use persist::storage::XmipStorage;
use xmip_core_runtime::work_step::{Turned, dispatch, turn_due};

use super::child_process::ChildProcess;
use super::sending::memory;
use super::work_design::{carried, published, working};
use super::{STARTED, directory, say, test_node};

#[test]
fn a_clients_messages_make_one_instance_and_its_batch_holds_them_in_the_order_received() {
    let storage = memory();
    working(&storage, |runtime, pickup, gate| {
        for number in 0..4 {
            carried(runtime, pickup, gate, "A", number);
            let turned = turn_due(runtime, pickup);
            assert!(
                turned.iter().all(|turned| matches!(turned, Turned::Done)),
                "{turned:?}"
            );
        }
    });
    assert_eq!(published(&storage), vec![vec!["A 1", "A 2", "A 3"]]);
}

#[test]
fn a_scan_reads_its_queue_to_the_end_not_only_its_first_page() {
    let storage = memory();
    working(&storage, |runtime, pickup, gate| {
        // One more client than a page of the queue holds: the last one's
        // Message waits behind a page that may all have to wait.
        let clients: Vec<String> = (0..65).map(|n| format!("C{n}")).collect();
        for who in &clients {
            carried(runtime, pickup, gate, who, 0);
        }
        let turned = turn_due(runtime, pickup);
        assert_eq!(turned.len(), clients.len(), "{turned:?}");
        assert!(
            turned.iter().all(|turned| matches!(turned, Turned::Done)),
            "{turned:?}"
        );
        assert!(turn_due(runtime, pickup).is_empty(), "nothing is left");
    });
}

#[test]
fn two_clients_carried_at_once_never_see_one_of_their_messages_overtake_another() {
    let storage = memory();
    working(&storage, |runtime, pickup, gate| {
        std::thread::scope(|scope| {
            scope.spawn(|| dispatch(scope, runtime, pickup));
            std::thread::scope(|carrying| {
                for who in ["A", "B"] {
                    carrying.spawn(move || {
                        for number in 0..4 {
                            carried(runtime, pickup, gate, who, number);
                        }
                    });
                }
            });
            let until = Instant::now() + Duration::from_secs(10);
            while published(&storage).len() < 2 && Instant::now() < until {
                runtime.work.ask_every();
                std::thread::yield_now();
            }
            runtime.work.close();
        });
    });
    let mut batches = published(&storage);
    batches.sort();
    assert_eq!(
        batches,
        vec![vec!["A 1", "A 2", "A 3"], vec!["B 1", "B 2", "B 3"]]
    );
}

/// The child that carries a client's first two Messages, takes their
/// turns, says so, and waits to be killed with its Instance mid-Batch.
pub fn work_until_killed(storage: &Arc<dyn XmipStorage>) {
    working(storage, |runtime, pickup, gate| {
        for number in 0..2 {
            carried(runtime, pickup, gate, "A", number);
            let turned = turn_due(runtime, pickup);
            assert!(
                turned.iter().all(|t| matches!(t, Turned::Done)),
                "{turned:?}"
            );
        }
        say("waiting");
        loop {
            std::thread::park();
        }
    });
}

#[test]
fn a_node_killed_mid_process_is_started_again_and_finishes_its_instance_from_the_ledger() {
    let place = directory("work-killed");
    let child = ChildProcess::start("working", &place);
    child.heard("waiting", STARTED);
    let _ = child.killed();
    let storage = test_node(&place);
    assert!(
        published(&storage).is_empty(),
        "nothing is published mid-Batch"
    );
    working(&storage, |runtime, pickup, gate| {
        for number in 2..4 {
            carried(runtime, pickup, gate, "A", number);
            let turned = turn_due(runtime, pickup);
            assert!(
                turned.iter().all(|t| matches!(t, Turned::Done)),
                "{turned:?}"
            );
        }
    });
    assert_eq!(published(&storage), vec![vec!["A 1", "A 2", "A 3"]]);
}
