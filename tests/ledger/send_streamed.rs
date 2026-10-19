//! A send that streams, and what a send holds (`runtime-model.md` section
//! 10, *How a send runs*; open problem 38):
//!
//! - a Message far larger than a chunk, routed to every Port of a Send Port
//!   Group, is sent to each in bounded memory, read from Xmip Storage a
//!   chunk at a time and never whole — what this process allocated is
//!   counted;
//! - departures kept to their far ends' pace take each chunk from one read
//!   of it, lent, rather than each reading it again;
//! - a send whose transport gathers the whole body holds it within the
//!   node's byte budget for sends: two that do not fit together are sent
//!   one after the other.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use configure::SendPortGroup;
use path::expression::Expression;
use persist::storage::XmipStorage;
use receive::ReceivedStream;
use route::{Subscriber, Subscription};
use xmip_core_runtime::budget::{CARRY_CHUNKS, STREAM_CHUNKS};
use xmip_core_runtime::fixture::{Drain, Failing, FarEnd, Operation};
use xmip_core_runtime::ledger::CHUNK;
use xmip_core_runtime::message_path::{Carried, ReceiveCycle, carry};
use xmip_core_runtime::pool::hardware_threads;
use xmip_core_runtime::sending::Sends;

use super::bounded::{Made, measured};
use super::receive_cycle::{Sender, node, on_node};
use super::sending::{dispatching, interleaving, onward, order, out, port, quick, sender};
use super::{directory, test_node};

/// The Send Ports of the fan-out.
const PORTS: [&str; 4] = ["North", "South", "East", "West"];

/// The Subscription `all`, matching everything to the Group `All`.
fn to_all() -> [Subscription; 1] {
    [Subscription::new(
        "all",
        Subscriber::SendGroup("All".to_string()),
        Expression::parse("xmip.transport.mechanism = 'circumstance'").expect("compiles"),
    )]
}

/// What a fan-out of a Message of `length` bytes to [`PORTS`], each to its
/// far end in `drains`, came to once every Journey completed: the most this
/// process held at once while they were sent, and the chunks read from Xmip
/// Storage for them.
fn fan_out(test: &str, length: u64, drains: &[Drain]) -> (usize, u64) {
    // On disk, as a node's runtime database is: a Storage node in this
    // process's memory would hold every chunk where the count looks.
    let place = directory(test);
    let failing = Failing::over(test_node(&place));
    let storage: Arc<dyn XmipStorage> = failing.clone();
    let sending = Sender {
        sends: Sends {
            locations: drains
                .iter()
                .zip(PORTS)
                .map(|(drain, name)| drain.clone().at(name))
                .collect(),
            ports: PORTS.iter().map(|name| port(name, |_| {})).collect(),
            groups: vec![SendPortGroup {
                name: "All".to_string(),
                send_ports: PORTS.iter().map(ToString::to_string).collect(),
            }],
        },
        tuning: quick(),
        node: node(),
        audit: None,
    };
    let measured_and_read = on_node(
        &storage,
        (CHUNK, &to_all()),
        sending,
        |runtime, pickup, gate| {
            let fan_out = |received| {
                let carried = carry(runtime, pickup, gate, received);
                assert_eq!(
                    carried.cycle(),
                    ReceiveCycle::Completed,
                    "{:?}",
                    carried.arrived
                );
                assert_eq!(carried.journeys.len(), PORTS.len(), "one Journey per Port");
                carried
            };
            let ((carried, most, read), _) = dispatching(runtime, |told| {
                let sent = |carried: &Carried| {
                    for journey in &carried.journeys {
                        told.wait_for(journey.journey_id(), "completed");
                    }
                };
                // A small one first, so the Send pool's threads are started
                // and wait for work, as a node's that has been sending do.
                sent(&fan_out(order(0)));
                let read_before = failing.asked_times(Operation::ReadChunk);
                let (carried, most) = measured(|| {
                    let made = ReceivedStream::new(Made::of(length), "tcp://127.0.0.1:1");
                    let carried = fan_out(made);
                    sent(&carried);
                    carried
                });
                let read = failing.asked_times(Operation::ReadChunk) - read_before;
                (carried, most, read)
            });
            for (drain, journey) in drains.iter().zip(&carried.journeys) {
                let key = journey.journey_id().to_string();
                let last = drain.taken().pop();
                assert_eq!(last, Some((length, key)), "whole, under its key");
            }
            (most, read)
        },
    );
    let _ = std::fs::remove_dir_all(&place);
    measured_and_read
}

#[test]
fn a_fan_out_of_a_large_message_is_sent_in_bounded_memory() {
    const LENGTH: u64 = 64 * 1024 * 1024;
    let drains: Vec<Drain> = PORTS.iter().map(|_| Drain::default()).collect();
    let (most, read) = fan_out("send-streamed-large", LENGTH, &drains);
    let chunks = LENGTH.div_ceil(CHUNK as u64);
    eprintln!(
        "STREAMED {} sends of {LENGTH} bytes held {most} bytes at most; {read} chunk reads \
         for {chunks} chunks",
        PORTS.len()
    );
    // What each send is counted as holding, what its carry into the Ledger
    // is, and a mebibyte for what the steps hold of their own: against four
    // Messages of a thousand chunks each, whole.
    let sends = PORTS.len() * STREAM_CHUNKS as usize * CHUNK;
    let room = sends + CARRY_CHUNKS as usize * CHUNK + 1024 * 1024;
    assert!(most < room, "{most} bytes held at once, {room} allowed");
}

#[test]
fn departures_at_their_far_ends_pace_share_one_read_of_each_chunk() {
    // Eight MiB, at a tenth of a millisecond a piece: what a far end across a
    // network makes of a send, the read never the slower.
    const LENGTH: u64 = 8 * 1024 * 1024;
    let drains: Vec<Drain> = PORTS
        .iter()
        .map(|_| Drain::paced(Duration::from_micros(100)))
        .collect();
    let (_, read) = fan_out("send-streamed-paced", LENGTH, &drains);
    let chunks = LENGTH.div_ceil(CHUNK as u64) + 1;
    eprintln!(
        "SHARED {} sends at a far end's pace: {read} chunk reads for {chunks}",
        PORTS.len()
    );
    // Each on its own reads every chunk: four reads of each. Shared, each is
    // read once, and a send begun two chunks late reads on by itself.
    assert!(read < 2 * chunks, "{read} chunk reads for {chunks} chunks");
}
#[test]
fn sends_that_gather_more_than_the_byte_budget_holds_go_one_at_a_time() {
    let (_, storage) = interleaving();
    // A Message as large as the whole budget: one chunk for each of the
    // Send pool's threads, at one chunk each.
    let length = (hardware_threads() * CHUNK) as u64;
    let (inside, most_inside) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let (counting, counted) = (Arc::clone(&inside), Arc::clone(&most_inside));
    let (far, taken) = FarEnd::answering(Box::new(move |_| {
        let now = counting.fetch_add(1, Ordering::AcqRel) + 1;
        counted.fetch_max(now, Ordering::AcqRel);
        // Long enough for another send to come in beside it, were it let.
        let until = Instant::now() + Duration::from_millis(50);
        while Instant::now() < until && counting.load(Ordering::Acquire) < 2 {
            std::thread::yield_now();
        }
        counting.fetch_sub(1, Ordering::AcqRel);
        Ok(())
    }));
    let mut sending = sender(node(), far, out(|_| {}));
    sending.tuning.send_threads_per_hardware_thread = 1;
    sending.tuning.send_chunks_per_thread = 1;
    on_node(
        &storage,
        (CHUNK, &onward()),
        sending,
        |runtime, pickup, gate| {
            let ids: Vec<_> = (0..2)
                .map(|_| {
                    let received = ReceivedStream::new(Made::of(length), "tcp://127.0.0.1:1");
                    carry(runtime, pickup, gate, received).journeys[0].journey_id()
                })
                .collect();
            dispatching(runtime, |told| {
                for id in &ids {
                    told.wait_for(*id, "completed");
                }
            });
            assert_eq!(
                runtime.budget.sent.most(),
                length,
                "the budget, the tuning's"
            );
            assert_eq!(
                runtime.budget.sent.held(),
                0,
                "every send let go of what it held"
            );
        },
    );
    assert_eq!(most_inside.load(Ordering::Acquire), 1, "one at a time");
    assert_eq!(taken.lock().expect("lock").len(), 2, "both sent");
}
