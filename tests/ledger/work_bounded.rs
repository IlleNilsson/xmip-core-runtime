//! The Work Process step held to what its pool can run (ADR-0066,
//! amendment 2026-11-12), as the send step is (`send_bounded.rs`): a turn is
//! taken only under a place in the Work pool, each Work Process with work
//! holds no more than its share of it, and a queue is read a page a round
//! from where its pass stands:
//!
//! - a scan takes no more turns than the Work pool can run, the rest left
//!   durable and unclaimed in the Ledger;
//! - turns another node holds keep no place from the one behind them;
//! - a backlog in one Work Process holds back no turn of another;
//! - the dispatching reads one page before its first turn, however long the
//!   backlog;
//! - and holds a backlog in the memory a page takes, however long, run
//!   alone (`bounded.rs`).
//!
//! Until 2026-11-12 every page of a queue was read into memory before its
//! first turn, every entry handed to the pool, and the first configured
//! Work Process's backlog was turned before another's first Message.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use xcore::lock::Locked;

use journey::JourneyState;
use persist::storage::XmipStorage;
use xcore::JourneyId;
use xmip_core_runtime::fixture::{Failing, Operation};
use xmip_core_runtime::ledger::CHUNK;
use xmip_core_runtime::message_path::Runtime;
use xmip_core_runtime::pickup::Pickup;
use xmip_core_runtime::pool::hardware_threads;
use xmip_core_runtime::receiving::ReceiveGate;
use xmip_core_runtime::work_step::NoUnits;

use super::bounded::alone;
use super::receive_cycle::on_working_node;
use super::sending::{Gate, free, journey, memory, until};
use super::work_design::{ABSORB, CALLS, carried_to, compiled, routes_to, running, running_as};
use super::work_turning::{Gated, HOUR, Hooked, counted_node, turning};

/// A page of a queue: as many as a wake brings, and as a read takes.
const PAGE: usize = 64;

/// Whether the Journey `id` is Completed in the Ledger now.
fn completed(storage: &dyn XmipStorage, id: JourneyId) -> bool {
    journey(storage, id).state == JourneyState::Completed
}

/// `count` Messages, each of a client of its own, carried into the Work
/// Process `name` on the node `on`: their Journeys, oldest first.
fn backlog(
    on: (&Runtime<'_>, &Pickup),
    gate: &ReceiveGate,
    (name, count): (&str, usize),
) -> Vec<JourneyId> {
    (0..count)
        .map(|n| carried_to(on, gate, name, &format!("{name}{n}")))
        .collect()
}

/// A gate opened when this is dropped, however the test got there, so a
/// failing test fails rather than waits on turns held at it.
struct Opened<'a>(&'a Gate);

impl Drop for Opened<'_> {
    fn drop(&mut self) {
        self.0.open();
    }
}

#[test]
fn a_scan_takes_no_more_turns_than_the_work_pool_can_run() {
    let storage = memory();
    let most = hardware_threads();
    let (gate, entered) = (Arc::new(Gate::default()), Arc::new(AtomicUsize::new(0)));
    let units = Gated {
        gate: Arc::clone(&gate),
        entered: Arc::clone(&entered),
    };
    let calls = running_as("Calls", Box::new(compiled(CALLS)), Arc::new(units));
    let routes = routes_to(&["Calls"]);
    let runs = (counted_node(), vec![calls]);
    on_working_node(
        &storage,
        (CHUNK, &routes),
        runs,
        |works, pickup, carrying| {
            let ids = backlog((works, pickup), carrying, ("Calls", most + 8));
            turning(works, pickup, || {
                let opened = Opened(&gate);
                until(|| entered.load(Ordering::Acquire) == most, "the pool full");
                assert_eq!(works.work.held(), most, "no more turns than the pool runs");
                let unclaimed = ids.iter().filter(|id| free(storage.as_ref(), **id)).count();
                assert_eq!(unclaimed, 8, "the rest left durable and unclaimed");
                drop(opened);
                for id in &ids {
                    until(|| completed(storage.as_ref(), *id), "every one taken");
                }
            });
        },
    );
}

#[test]
fn turns_another_node_holds_keep_no_place_from_those_behind_them() {
    let storage = memory();
    let routes = routes_to(&["Absorb"]);
    let runs = (counted_node(), vec![running("Absorb", ABSORB)]);
    on_working_node(&storage, (CHUNK, &routes), runs, |works, pickup, gate| {
        let held = backlog((works, pickup), gate, ("Absorb", PAGE));
        // A page of them, each held by a live node for an hour.
        let other = configure::fixture::test_cluster().node_scope(1);
        for id in &held {
            let claim = storage.claim(*id, &other, id.value() ^ 0x07e5, HOUR);
            assert!(claim.expect("asked").is_some(), "held by another node");
        }
        let last = carried_to((works, pickup), gate, "Absorb", "behind");
        turning(works, pickup, || {
            until(|| completed(storage.as_ref(), last), "the one behind them");
        });
        let ours = held.iter().filter(|id| completed(storage.as_ref(), **id));
        assert_eq!(
            ours.count(),
            0,
            "those another node holds are still its own"
        );
    });
}

#[test]
fn a_backlog_in_one_work_process_holds_back_no_turn_of_another() {
    let storage = memory();
    let most = hardware_threads();
    let record: Arc<Mutex<Vec<&'static str>>> = Arc::default();
    let recorded = |name: &'static str| {
        let record = Arc::clone(&record);
        let flow = Hooked::of(ABSORB, Box::new(move || record.locked().push(name)));
        running_as(name, flow, Arc::new(NoUnits))
    };
    let routes = routes_to(&["First", "Second"]);
    let runs = (counted_node(), vec![recorded("First"), recorded("Second")]);
    on_working_node(&storage, (CHUNK, &routes), runs, |works, pickup, gate| {
        let mut ids = backlog((works, pickup), gate, ("First", 16 * most));
        ids.extend(backlog((works, pickup), gate, ("Second", 1)));
        turning(works, pickup, || {
            for id in &ids {
                until(|| completed(storage.as_ref(), *id), "every one taken");
            }
        });
    });
    let record = record.locked();
    let at = record.iter().position(|name| *name == "Second");
    let at = at.expect("Second took its turn");
    assert!(at <= most, "Second's turn came {at}th of {}", record.len());
}

#[test]
fn the_dispatching_reads_one_page_before_its_first_turn_however_long_the_backlog() {
    let failing = Failing::over(memory());
    let storage: Arc<dyn XmipStorage> = Arc::clone(&failing) as _;
    let routes = routes_to(&["Absorb"]);
    let runs = (counted_node(), vec![running("Absorb", ABSORB)]);
    on_working_node(&storage, (CHUNK, &routes), runs, |works, pickup, gate| {
        let _ = backlog((works, pickup), gate, ("Absorb", 1000));
        let before = failing.asked_times(Operation::ReadDue);
        let read: Arc<Mutex<Option<u64>>> = Arc::default();
        let (at_claim, counted) = (Arc::clone(&read), Arc::clone(&failing));
        let first_claim = move || {
            *at_claim.locked() = Some(counted.asked_times(Operation::ReadDue));
        };
        failing.before(Operation::Claim, Box::new(first_claim));
        turning(works, pickup, || {
            until(|| read.locked().is_some(), "the first claim");
        });
        let pages = read.locked().map(|read| read - before);
        assert_eq!(pages, Some(1), "one page read before its first turn, of 16");
    });
}

/// What the dispatching held above what was held as it began, at the most,
/// until its first claim, over a queue of `count` Messages.
fn held_before_its_first_turn(count: usize) -> usize {
    let failing = Failing::over(memory());
    let storage: Arc<dyn XmipStorage> = Arc::clone(&failing) as _;
    let routes = routes_to(&["Absorb"]);
    let runs = (counted_node(), vec![running("Absorb", ABSORB)]);
    on_working_node(&storage, (CHUNK, &routes), runs, |works, pickup, gate| {
        let _ = backlog((works, pickup), gate, ("Absorb", count));
        let most = Arc::new(AtomicUsize::new(usize::MAX));
        let at_claim = Arc::clone(&most);
        let first_claim = move || at_claim.store(xcore::held::most(), Ordering::SeqCst);
        failing.before(Operation::Claim, Box::new(first_claim));
        xcore::held::reset();
        let began = xcore::held::now();
        turning(works, pickup, || {
            until(
                || most.load(Ordering::SeqCst) != usize::MAX,
                "the first claim",
            );
        });
        most.load(Ordering::SeqCst).saturating_sub(began)
    })
}

#[test]
fn a_backlog_is_dispatched_in_memory_a_page_bounds() {
    alone(
        "work_bounded::a_backlog_is_dispatched_in_memory_a_page_bounds",
        || {
            let short = held_before_its_first_turn(256);
            let long = held_before_its_first_turn(4096);
            assert!(
                long <= short + 64 * 1024,
                "{long} bytes held before the first turn of 4,096, {short} of 256"
            );
        },
    );
}
