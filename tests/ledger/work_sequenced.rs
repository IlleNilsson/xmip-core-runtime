//! A Work Process naming a Correlation whose turn fails (ADR-0066, third
//! amendment 2026-11-12): its Message written Failed and kept in its
//! queue's failed index for an operator, and its place in the Work
//! Process's sequence let go of where the Correlation's `on_failure` is
//! `skip`, so the next Message of its key is taken its turn and completes,
//! or kept where it is `block`, so the next waits — however the turn
//! failed:
//!
//! - its flow ending on an error a unit threw and no scope caught;
//! - a turn its flow refused;
//! - a turn that panicked.
//!
//! As the amendment was first built, only the first let its place go: a
//! refused or panicked turn under `skip` held its key's sequence until an
//! operator acted.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use journey::JourneyState;
use process::Refused;
use xmip_core_runtime::ledger::CHUNK;
use xmip_core_runtime::sequence::OnFailure;
use xmip_core_runtime::work_step::{NoUnits, Running, turn_due};

use super::receive_cycle::on_working_node;
use super::sending::{journey, memory};
use super::work_design::{ABSORB, CALLS, carried_to, compiled, routes_to, running_as};
use super::work_turning::{Before, Hooked, ThrowingOnce, counted_node, sequenced};

/// The Work Process the tests turn.
const ORDERED: &str = "Ordered";

/// How the first turn fails.
#[derive(Clone, Copy, Debug)]
enum Failing {
    /// A unit's error its flow catches nowhere.
    Thrown,
    /// The flow refuses the turn.
    Refused,
    /// The flow panics.
    Panicked,
}

const EVERY: [Failing; 3] = [Failing::Thrown, Failing::Refused, Failing::Panicked];

/// What runs before each advance of `ORDERED`'s flow: its first turn
/// refused or panicking as `how` says, every later one taken.
fn first(how: Failing) -> Before {
    let done = AtomicBool::new(false);
    Box::new(move || {
        if done.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        match how {
            Failing::Refused => Err(Refused::Unfit("a flow that refuses".to_string())),
            Failing::Panicked => panic!("a flow that panics"),
            Failing::Thrown => Ok(()),
        }
    })
}

/// `ORDERED`, its first turn failing as `how` says.
fn failing(how: Failing) -> Running {
    match how {
        Failing::Thrown => running_as(
            ORDERED,
            Box::new(compiled(CALLS)),
            Arc::new(ThrowingOnce::default()),
        ),
        _ => running_as(ORDERED, Hooked::of(ABSORB, first(how)), Arc::new(NoUnits)),
    }
}

/// Two Messages of one client carried into `ORDERED`, its Correlation by
/// client failing as `on_failure` says and its first turn as `how` says,
/// and its queue turned: the first written Failed and kept in the failed
/// index, and the second's state.
fn after_a_failed_turn(how: Failing, on_failure: OnFailure) -> JourneyState {
    let storage = memory();
    let routes = routes_to(&[ORDERED]);
    let node = sequenced(counted_node(), ORDERED, on_failure);
    let runs = (node, vec![failing(how)]);
    on_working_node(&storage, (CHUNK, &routes), runs, |works, pickup, gate| {
        let failed = carried_to((works, pickup), gate, ORDERED, "A");
        let next = carried_to((works, pickup), gate, ORDERED, "A");
        let turned = turn_due(works, pickup);
        let state = journey(storage.as_ref(), failed).state;
        assert_eq!(state, JourneyState::Failed, "{how:?}: {turned:?}");
        let queue = works.work.running()[0].queue;
        let kept = storage.read_failed(queue, 0, 10).expect("read").failed;
        let kept: Vec<_> = kept.iter().map(|entry| entry.journey).collect();
        assert_eq!(kept, [failed], "{how:?}: kept in its queue's failed index");
        journey(storage.as_ref(), next).state
    })
}

#[test]
fn a_failed_turn_under_skip_lets_the_next_of_its_key_complete() {
    for how in EVERY {
        let next = after_a_failed_turn(how, OnFailure::Skip);
        assert_eq!(next, JourneyState::Completed, "{how:?}");
    }
}

#[test]
fn a_failed_turn_under_block_keeps_the_next_of_its_key_waiting() {
    for how in EVERY {
        let next = after_a_failed_turn(how, OnFailure::Block);
        assert_eq!(next, JourneyState::Active, "{how:?}");
    }
}
