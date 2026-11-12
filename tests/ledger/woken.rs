//! A Journey one node publishes, taken up by another at once (open problem
//! 46; ADR-0018, amendment 2026-11-12): the node that takes it waits on its
//! queues in Xmip Storage, so neither its send step nor its Work Process
//! step waits for its scan, here an hour, the scan only the bound on one
//! wait:
//!
//! - a Message published on a node that sends nothing is sent by the node
//!   that sends its Send Port, which started first;
//! - a client's Messages published on a node that runs no Work Process are
//!   taken their turns by the node that runs it, and its batch published;
//! - and a node's own Publications into a queue it sends, claimed in them,
//!   wake no read of that queue.
//!
//! Each publishes only once the taking node's first scan of every queue has
//! read them, finding nothing, and holds that no second scan came before it
//! was taken up: so only the wait on its queues can have taken it up
//! (corrected 2026-11-12: the first scan could run after the Publication,
//! and the test pass with no wait at all).

use std::sync::Arc;
use std::time::Duration;

use persist::storage::XmipStorage;
use route::Subscriber;
use xmip_core_runtime::fixture::{Failing, FarEnd, Operation};
use xmip_core_runtime::ledger::CHUNK;
use xmip_core_runtime::message_path::{ReceiveCycle, carry};
use xmip_core_runtime::tuning::Tuning;
use xmip_core_runtime::work_step::{WorkStep, dispatch};

use super::receive_cycle::{Sender, on_node, on_runtime};
use super::sending::{
    dispatching, memory, memory_node, onward, order, out, sender, taking, took, until,
};
use super::work_design::{carried, published, routing, sending_nothing};

/// An hour: no scan comes while a test runs.
const HOUR: Duration = Duration::from_secs(3600);

/// The test cluster's second node: the one that takes up what the first
/// published.
fn other() -> String {
    configure::fixture::test_cluster().node_scope(1)
}

#[test]
fn a_message_another_node_publishes_is_sent_at_once_by_the_node_sending_its_port() {
    let storage = memory();
    // The sending node's Xmip Storage, counting what it is asked.
    let failing = Failing::over(Arc::clone(&storage));
    let counted: Arc<dyn XmipStorage> = Arc::clone(&failing) as _;
    let (far, taken) = FarEnd::answering(taking());
    let mut sending = sender(other(), far, out(|_| {}));
    sending.tuning.send_scan = HOUR;
    on_node(&counted, (CHUNK, &onward()), sending, |sends, _, _| {
        dispatching(sends, |told| {
            // Its first scan found nothing; the next is an hour away.
            until(|| sends.send.scans() == 1, "the first scan made");
            let failed = failing.asked_times(Operation::ReadFailed);
            let id = on_runtime(&storage, CHUNK, |runtime, pickup, gate| {
                let carried = carry(runtime, pickup, gate, order(1));
                assert_eq!(carried.cycle(), ReceiveCycle::Completed);
                carried.journeys[0].journey_id()
            });
            told.wait_for(id, "completed");
            assert_eq!(sends.send.scans(), 1, "sent before any scan came");
            // A wake reads what is due, never the failed Messages.
            assert_eq!(failing.asked_times(Operation::ReadFailed), failed);
        });
    });
    assert_eq!(took(&taken), ["order 1"]);
}

#[test]
fn a_nodes_own_publications_into_a_queue_it_sends_wake_no_read_of_it() {
    let node = memory_node();
    let failing = Failing::over(Arc::clone(&node) as _);
    let storage: Arc<dyn XmipStorage> = Arc::clone(&failing) as _;
    let (far, taken) = FarEnd::answering(taking());
    let mut sending = sender(other(), far, out(|_| {}));
    sending.tuning.send_scan = HOUR;
    on_node(
        &storage,
        (CHUNK, &onward()),
        sending,
        |sends, pickup, gate| {
            let queue = sends.send.queue(&Subscriber::SendPort("Out".to_string()));
            dispatching(sends, |told| {
                until(|| sends.send.scans() == 1, "the first scan made");
                // Its watch waits on the queue before anything is published: a
                // write before that is found moved, and read, as the wait begins.
                until(|| node.waiting_on(queue) == 1, "the watch waiting");
                let read = failing.asked_times(Operation::ReadDue);
                for number in 0..3 {
                    let carried = carry(sends, pickup, gate, order(number));
                    assert_eq!(carried.cycle(), ReceiveCycle::Completed);
                    told.wait_for(carried.journeys[0].journey_id(), "completed");
                }
                // Each claimed in its own Publication and handed on in memory:
                // the write that moves its queue tells the watch quietly.
                assert_eq!(failing.asked_times(Operation::ReadDue), read, "never read");
            });
        },
    );
    assert_eq!(took(&taken), ["order 0", "order 1", "order 2"]);
}

#[test]
fn a_clients_messages_another_node_publishes_take_their_turns_at_once_where_it_runs() {
    let storage = memory();
    let runner = Sender {
        tuning: Tuning {
            work_scan: HOUR,
            ..Tuning::default()
        },
        node: other(),
        ..sending_nothing()
    };
    routing(&storage, (true, runner), |runs, pickup, _| {
        std::thread::scope(|scope| {
            scope.spawn(|| dispatch(scope, runs, pickup));
            let _closing = Closing(runs.work);
            // Its first scan found nothing; the next is an hour away.
            until(|| runs.work.scans() == 1, "the first scan made");
            routing(
                &storage,
                (false, sending_nothing()),
                |routes, pickup, gate| {
                    for number in 0..4 {
                        carried(routes, pickup, gate, "A", number);
                    }
                },
            );
            until(|| !published(&storage).is_empty(), "the batch published");
            assert_eq!(runs.work.scans(), 1, "turned before any scan came");
        });
    });
    assert_eq!(published(&storage), vec![vec!["A 1", "A 2", "A 3"]]);
}

/// A Work Process step closed when this is dropped, however the test got
/// there, so a failing test fails rather than waits.
struct Closing<'a>(&'a WorkStep);

impl Drop for Closing<'_> {
    fn drop(&mut self) {
        self.0.close();
    }
}
