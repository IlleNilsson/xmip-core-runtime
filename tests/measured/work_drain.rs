//! A backlog drained through a Work Process, measured (open problem 93;
//! ADR-0066, amendment 2026-11-22): 2,000 Messages queued for it over Xmip
//! Storage served on loopback, then taken their turns — each client a
//! sequence of its own, as the problem's probe had it, and four clients of
//! 500 each, a backlog behind a few Receive Locations' sequences as on the
//! Hyper-V environment. Each is held to the millisecond rule per Message:
//! the drain over its Messages where each is its own sequence, and over the
//! Messages of one sequence where there are four — what each sequence's next
//! takes once the one ahead of it is done — the fastest of five drains under
//! a millisecond. Until 2026-11-22 each Message of a sequence waited for a
//! pass of the whole queue, every entry in it claimed and given back.

use std::time::{Duration, Instant};

use journey::JourneyState;
use xcore::JourneyId;
use xcore::latency::spread;
use xmip_core_runtime::ledger::CHUNK;

use super::loopback::over_the_wire;
use super::receive_cycle::on_working_node;
use super::sending::{PATIENCE, journey, memory};
use super::work_design::{ABSORB, carried_through, opened, routes_to, running};
use super::work_turning::{counted_node, turning};

/// The Messages of a backlog.
const COUNT: u32 = 2_000;

/// The drains each figure is the fastest of.
const DRAINS: usize = 5;

/// [`COUNT`] Messages of `clients` clients, each client's Streams one at a
/// time end to end, carried into `Absorb` over Xmip Storage on loopback, and
/// then drained: how long the drain took, from its dispatching's start to
/// its last Message's turn written.
fn drained(clients: u32) -> Duration {
    let beneath = memory();
    let (_served, storage) = over_the_wire(&beneath, PATIENCE);
    let routes = routes_to(&["Absorb"]);
    let runs = (counted_node(), vec![running("Absorb", ABSORB)]);
    on_working_node(&storage, (CHUNK, &routes), runs, |works, pickup, gate| {
        let gate = opened(gate);
        let ids: Vec<JourneyId> = (0..COUNT)
            .map(|number| {
                let who = format!("C{}", number % clients);
                let text = format!("{who} {number}");
                carried_through((works, pickup), &gate, "Absorb", (&who, &text))
            })
            .collect();
        let completed =
            |id: JourneyId| journey(beneath.as_ref(), id).state == JourneyState::Completed;
        let began = Instant::now();
        turning(works, pickup, || {
            let deadline = began + PATIENCE;
            for id in &ids {
                while !completed(*id) {
                    assert!(Instant::now() < deadline, "the backlog never drained");
                    std::thread::yield_now();
                }
            }
        });
        began.elapsed()
    })
}

#[test]
fn two_thousand_each_its_own_sequence_drain_under_a_millisecond_a_message() {
    let each: Vec<Duration> = (0..DRAINS).map(|_| drained(COUNT) / COUNT).collect();
    let held = spread("a Message of 2,000, each its own sequence", each).fastest_of_five;
    assert!(held < Duration::from_millis(1), "{held:?} a Message");
}

#[test]
fn two_thousand_behind_four_sequences_drain_each_next_under_a_millisecond() {
    const SEQUENCES: u32 = 4;
    let next: Vec<Duration> = (0..DRAINS)
        .map(|_| drained(SEQUENCES) / (COUNT / SEQUENCES))
        .collect();
    let held = spread("a sequence's next of 2,000 behind four", next).fastest_of_five;
    assert!(
        held < Duration::from_millis(1),
        "{held:?} a sequence's next"
    );
}
