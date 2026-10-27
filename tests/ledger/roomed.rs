//! What a node's Receive Locations take and hold (`runtime-model.md`
//! section 3, *Threads, pools and chunks*; open problem 38):
//!
//! - a receive takes no more arrivals than its Location's pool and the
//!   node's carry budget have room for, and what it does not take stays at
//!   its far end until there is room — across two Locations, the node's
//!   carries at once never pass its budget, whatever each pool allows;
//! - what the carries hold is held within the node's byte budget: large
//!   Streams on two Locations, what this process allocated counted.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use transport::{Acknowledgement, Arrivals, Arrived, Directions, Transport, Verdict, Waiting};
use xmip_core_runtime::budget::NodeBudget;
use xmip_core_runtime::ledger::CHUNK;
use xmip_core_runtime::message_path::Runtime;
use xmip_core_runtime::pickup::Pickup;
use xmip_core_runtime::pool::{Limits, hardware_threads};
use xmip_core_runtime::receiving::{Pace, ReceiveGate, Receiving};
use xmip_core_runtime::sending::Sends;
use xmip_core_runtime::stopping::Stopping;
use xmip_core_runtime::tuning::Tuning;

use super::bounded::{Made, alone, measured};
use super::receive_cycle::{Sender, node, on_node};
use super::sending::{onward, until};
use super::{directory, test_node};

/// What every Location's far end shares: how many arrivals were taken and
/// not yet told, the most at once, and the room each receive asked for.
#[derive(Default)]
struct Counts {
    untold: AtomicUsize,
    most_untold: AtomicUsize,
    asked: Mutex<Vec<usize>>,
}

/// A far end holding a backlog of Streams of `length` bytes each, which
/// hands over at most what each receive asks for and keeps the rest; one
/// not accepted goes back to the backlog.
struct Backlog {
    left: Arc<Mutex<VecDeque<u64>>>,
    length: u64,
    counts: Arc<Counts>,
}

impl Backlog {
    fn of(items: usize, length: u64, counts: &Arc<Counts>) -> Self {
        Self {
            left: Arc::new(Mutex::new((0..items as u64).collect())),
            length,
            counts: Arc::clone(counts),
        }
    }

    fn left(&self) -> Arc<Mutex<VecDeque<u64>>> {
        Arc::clone(&self.left)
    }
}

impl Transport for Backlog {
    fn name(&self) -> &'static str {
        "backlog"
    }

    fn directions(&self) -> Directions {
        Directions::RECEIVE
    }

    fn arrivals(&self) -> Arrivals {
        Arrivals::Unordered("each item is its own, kept until it is told")
    }

    fn waiting(&self) -> Waiting {
        Waiting::Polled("the backlog is looked at and the receive returns")
    }

    fn receive_up_to(&self, most: usize) -> transport::Result<Vec<Arrived>> {
        self.counts
            .asked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(most);
        let mut left = self.left.lock().unwrap_or_else(PoisonError::into_inner);
        let taken: Vec<u64> = (0..most).map_while(|_| left.pop_front()).collect();
        drop(left);
        Ok(taken
            .into_iter()
            .map(|item| {
                let now = self.counts.untold.fetch_add(1, Ordering::AcqRel) + 1;
                self.counts.most_untold.fetch_max(now, Ordering::AcqRel);
                let (counts, left) = (Arc::clone(&self.counts), Arc::clone(&self.left));
                let told = Acknowledgement::deferred(move |verdict| {
                    if verdict != Verdict::Accepted {
                        left.lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .push_back(item);
                    }
                    counts.untold.fetch_sub(1, Ordering::AcqRel);
                    Ok(())
                });
                Arrived::new(format!("backlog://{item}"), Made::of(self.length), told).detected()
            })
            .collect())
    }

    fn sending(&self) -> transport::Sending {
        transport::Sending::Streamed("it sends nothing")
    }

    fn send_from(&self, _: &str, _: transport::Outgoing<'_>) -> transport::Result<()> {
        Ok(())
    }
}

/// The Receive Location `name` over `backlog`, its pool `most` threads.
fn location(name: &str, backlog: Backlog, gate: &ReceiveGate, most: usize) -> Receiving {
    Receiving {
        configured: configure::ConfiguredLocation {
            name: name.to_string(),
            start: true,
            transport: "backlog".to_string(),
            address: format!("backlog://{name}"),
            credentials: None,
            contract: None,
            settings: configure::LocationSettings::default(),
            contract_settings: configure::LocationSettings::default(),
            accept: configure::Accept::default(),
            prepare: Vec::new(),
            transform: None,
            promote: None,
            demote: None,
            debatch: None,
            correlation: None,
        },
        gate: gate.clone(),
        transport: Box::new(backlog),
        limits: Limits {
            most,
            idle: Duration::from_secs(60),
        },
        pace: Pace {
            poll: Duration::from_millis(1),
            ..Pace::default()
        },
        audit: None,
    }
}

/// Two Locations, `items` Streams of `length` bytes behind each, served on
/// a node run by `tuning` until both backlogs are taken and told.
fn serve_two(test: &str, tuning: Tuning, (items, length): (usize, u64), most: usize) -> Counts {
    let at = directory(test);
    let storage = test_node(&at.join("node"));
    let counts = Arc::new(Counts::default());
    let sender = Sender {
        sends: Sends::default(),
        tuning,
        node: node(),
        audit: None,
    };
    on_node(
        &storage,
        (CHUNK, &onward()),
        sender,
        |runtime, pickup, gate| {
            let (east, west) = (
                Backlog::of(items, length, &counts),
                Backlog::of(items, length, &counts),
            );
            let lefts = [east.left(), west.left()];
            let locations = [
                location("East", east, gate, most),
                location("West", west, gate, most),
            ];
            served(runtime, pickup, &locations, || {
                lefts.iter().all(|left| {
                    left.lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .is_empty()
                }) && counts.untold.load(Ordering::Acquire) == 0
            });
        },
    );
    let _ = std::fs::remove_dir_all(&at);
    Arc::try_unwrap(counts).unwrap_or_else(|_| panic!("every far end let go"))
}

/// Every one of `locations` served on `runtime` until `done`, then stopped.
fn served(
    runtime: &Runtime<'_>,
    pickup: &Pickup,
    locations: &[Receiving],
    done: impl Fn() -> bool,
) {
    let stopping = Stopping::default();
    std::thread::scope(|scope| {
        let serving: Vec<_> = locations
            .iter()
            .map(|location| {
                let stopping = &stopping;
                scope.spawn(move || {
                    std::thread::scope(|pool| {
                        location.serve(pool, runtime, pickup, stopping, |_| {})
                    })
                })
            })
            .collect();
        until(done, "every backlog taken and told");
        stopping.raise();
        for one in serving {
            one.join().expect("served").expect("stopped when asked");
        }
    });
}

#[test]
fn receives_take_no_more_than_their_pool_and_the_node_have_room_for() {
    let node_most = hardware_threads();
    let tuning = Tuning {
        node_receive_threads_per_hardware_thread: 1,
        ..Tuning::default()
    };
    let pool_most = 2 * node_most;
    let counts = serve_two("roomed-places", tuning, (4 * node_most, 16), pool_most);
    let asked = counts.asked.lock().unwrap_or_else(PoisonError::into_inner);
    assert!(
        asked.iter().all(|most| (1..=pool_most).contains(most)),
        "each receive asked within its pool: {asked:?}"
    );
    let most_untold = counts.most_untold.load(Ordering::Acquire);
    eprintln!("ROOMED two pools of {pool_most}, a node of {node_most}: {most_untold} at once");
    assert!(
        most_untold <= node_most,
        "{most_untold} taken at once, the node has room for {node_most}"
    );
}

#[test]
fn what_the_carries_hold_is_held_within_the_node_byte_budget() {
    alone(
        "roomed::what_the_carries_hold_is_held_within_the_node_byte_budget",
        held_within_the_node_byte_budget,
    );
}

fn held_within_the_node_byte_budget() {
    // A carry is counted as holding eight chunks, and the node lets its
    // carries hold one chunk each: an eighth of them carry at once.
    let tuning = Tuning {
        receive_chunks_per_thread: 1,
        ..Tuning::default()
    };
    let budget = NodeBudget::of(&tuning).received.most() as usize;
    const LENGTH: u64 = 4 * 1024 * 1024;
    let items = hardware_threads();
    let (counts, most) = measured(|| {
        serve_two(
            "roomed-bytes",
            tuning,
            (items, LENGTH),
            2 * hardware_threads(),
        )
    });
    let whole = 2 * items * LENGTH as usize;
    eprintln!(
        "ROOMED {} Streams of {LENGTH} bytes, {whole} in all, held {most} bytes at most, the \
         node's budget {budget}",
        2 * items
    );
    assert_eq!(counts.untold.load(Ordering::Acquire), 0);
    // The budget, and what the carries waiting for room hold beside it: of
    // the Streams, all of them whole, it is a few hundredths.
    let room = budget + 2 * 1024 * 1024;
    assert!(most < room, "{most} bytes held at once, {room} allowed");
}
