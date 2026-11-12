//! A turn of a Work Process that panics strands nothing (ADR-0066,
//! amendment 2026-11-12): caught under its claim, it is written Failed with
//! what the panic said, kept in its queue's failed index for an operator,
//! and its place and its ownership on the node are given back however it
//! ends; one that unwinds before its claim is let go of and taken up again:
//!
//! - a turn whose unit panics is written Failed with what it said, its
//!   claim ended;
//! - a turn that panics leaves the other Work Processes, and its own, going
//!   on, with no restart and nothing held;
//! - a turn on the dispatching thread — its Work Process naming a
//!   Correlation — whose flow panics keeps the dispatching going;
//! - a turn that unwinds before its claim is let go of and, asked again,
//!   taken up, on the pool and on the dispatching thread.
//!
//! Until 2026-11-12 a turn that panicked stayed owned on its node and every
//! read passed it over until the node restarted, and one on the dispatching
//! thread ended the dispatching of every Work Process on the node.

use std::sync::Arc;

use journey::JourneyState;
use persist::storage::XmipStorage;
use xmip_core_runtime::fixture::{Failing, Operation};
use xmip_core_runtime::ledger::CHUNK;
use xmip_core_runtime::work_step::{NoUnits, Running, Turned, turn_due};

use super::receive_cycle::{Sender, on_working_node};
use super::sending::{free, journey, memory, until};
use super::work_design::{ABSORB, CALLS, carried_to, compiled, routes_to, running, running_as};
use super::work_turning::{Hooked, Panicking, counted_node, sequenced, turning};

/// `Calls`, each of its unit's calls panicking.
fn panicking_calls() -> Running {
    running_as("Calls", Box::new(compiled(CALLS)), Arc::new(Panicking))
}

/// Whether the Journey `id` is as the Ledger keeps it `state` now.
fn is(storage: &dyn XmipStorage, id: xcore::JourneyId, state: JourneyState) -> bool {
    journey(storage, id).state == state
}

#[test]
fn a_turn_whose_unit_panics_is_written_failed_with_what_it_said() {
    let storage = memory();
    let routes = routes_to(&["Calls"]);
    let runs = (counted_node(), vec![panicking_calls()]);
    on_working_node(&storage, (CHUNK, &routes), runs, |works, pickup, gate| {
        let id = carried_to((works, pickup), gate, "Calls", "A");
        let turned = turn_due(works, pickup);
        let [Turned::Failed(why)] = turned.as_slice() else {
            panic!("{turned:?}");
        };
        assert!(why.contains("panicked: a unit that panics"), "{why}");
        assert!(is(storage.as_ref(), id, JourneyState::Failed));
        let queue = works.work.running()[0].queue;
        let failed = storage.read_failed(queue, 0, 10).expect("read").failed;
        assert_eq!(failed.len(), 1, "kept in its queue's failed index");
        assert_eq!(failed[0].journey, id);
        assert!(
            failed[0].reason.contains("a unit that panics"),
            "{}",
            failed[0].reason
        );
        assert!(free(storage.as_ref(), id), "its claim ended");
        assert!(
            turn_due(works, pickup).is_empty(),
            "nothing is left to turn"
        );
    });
}

#[test]
fn a_turn_that_panics_leaves_unrelated_work_going_on_without_a_restart() {
    let storage = memory();
    let routes = routes_to(&["Calls", "Absorb"]);
    let runs = (
        counted_node(),
        vec![panicking_calls(), running("Absorb", ABSORB)],
    );
    on_working_node(&storage, (CHUNK, &routes), runs, |works, pickup, gate| {
        turning(works, pickup, || {
            let on = (works, pickup);
            let calls = carried_to(on, gate, "Calls", "A");
            let absorbed = carried_to(on, gate, "Absorb", "B");
            let failed = || is(storage.as_ref(), calls, JourneyState::Failed);
            until(failed, "the turn that panicked written Failed");
            let completed = || is(storage.as_ref(), absorbed, JourneyState::Completed);
            until(completed, "the other Work Process's turn taken");
            // Its own Work Process's work is still taken: nothing is held.
            let again = carried_to(on, gate, "Calls", "C");
            let failed = || is(storage.as_ref(), again, JourneyState::Failed);
            until(failed, "its next turn taken, and written Failed");
            until(|| works.work.held() == 0, "every place given back");
            assert_eq!(works.work.unwound(), 0, "each caught under its claim");
        });
    });
}

#[test]
fn a_sequenced_turn_whose_flow_panics_keeps_the_dispatching_going() {
    let storage = memory();
    let routes = routes_to(&["Calls", "Absorb"]);
    let panics = Hooked::of(CALLS, Box::new(|| panic!("a flow that panics")));
    let calls = running_as("Calls", panics, Arc::new(NoUnits));
    let runs = (
        sequenced(counted_node(), "Calls"),
        vec![calls, running("Absorb", ABSORB)],
    );
    on_working_node(&storage, (CHUNK, &routes), runs, |works, pickup, gate| {
        turning(works, pickup, || {
            let on = (works, pickup);
            let calls = carried_to(on, gate, "Calls", "A");
            let failed = || is(storage.as_ref(), calls, JourneyState::Failed);
            until(failed, "the turn that panicked written Failed");
            let queue = works.work.running()[0].queue;
            let kept = storage.read_failed(queue, 0, 10).expect("read").failed;
            let reason = &kept[0].reason;
            assert!(reason.contains("panicked: a flow that panics"), "{reason}");
            // The dispatching still goes on: another Work Process's turn.
            let absorbed = carried_to(on, gate, "Absorb", "B");
            let completed = || is(storage.as_ref(), absorbed, JourneyState::Completed);
            until(completed, "a turn taken after it");
            until(|| works.work.held() == 0, "every place given back");
        });
    });
}

/// A node over Xmip Storage whose next claim panics before it is taken,
/// running `Absorb` — on the dispatching thread where `in_order` — taking
/// a Message for it: its turn unwinds, is let go of, and is taken up again
/// once asked.
fn a_claim_that_panics_is_let_go_of_and_taken_up_again(in_order: bool) {
    let failing = Failing::over(memory());
    let storage: Arc<dyn XmipStorage> = Arc::clone(&failing) as _;
    failing.before(Operation::Claim, Box::new(|| panic!("a claim that panics")));
    let routes = routes_to(&["Absorb"]);
    let node: Sender = if in_order {
        sequenced(counted_node(), "Absorb")
    } else {
        counted_node()
    };
    let runs = (node, vec![running("Absorb", ABSORB)]);
    on_working_node(&storage, (CHUNK, &routes), runs, |works, pickup, gate| {
        turning(works, pickup, || {
            let id = carried_to((works, pickup), gate, "Absorb", "A");
            until(|| works.work.unwound() == 1, "its turn unwound");
            until(|| works.work.held() == 0, "its place given back");
            assert!(!is(storage.as_ref(), id, JourneyState::Completed));
            works.work.ask_every();
            let completed = || is(storage.as_ref(), id, JourneyState::Completed);
            until(completed, "taken up again");
            assert_eq!(works.work.unwound(), 1, "once");
        });
    });
}

#[test]
fn a_turn_that_unwinds_before_its_claim_is_let_go_of_and_taken_up_again() {
    a_claim_that_panics_is_let_go_of_and_taken_up_again(false);
    a_claim_that_panics_is_let_go_of_and_taken_up_again(true);
}
