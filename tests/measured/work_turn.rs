//! What a Work Process's turn costs beside its Ledger writes (ADR-0066,
//! amendment 2026-10-22), over the Ledger tests' Work Process
//! (`tests/ledger/work_design.rs`).

use std::time::{Duration, Instant};

use xmip_core_runtime::work_step::{Turned, turn_due};

use super::say;
use super::sending::memory;
use super::work_design::{carried, working};

#[test]
fn a_turn_costs_far_under_a_millisecond_beside_its_ledger_writes() {
    let storage = memory();
    working(&storage, |runtime, pickup, gate| {
        let mut spent = Vec::new();
        for (number, who) in (0..200u32).map(|n| (n % 4, format!("C{}", n / 4))) {
            carried(runtime, pickup, gate, &who, number);
            let began = Instant::now();
            let turned = turn_due(runtime, pickup);
            spent.push(began.elapsed());
            assert!(
                turned.iter().all(|t| matches!(t, Turned::Done)),
                "{turned:?}"
            );
        }
        spent.sort();
        let median = spent[spent.len() / 2];
        say(&format!(
            "a turn, its Ledger reads and its write in memory: median {median:?}, \
             slowest {:?}",
            spent[spent.len() - 1]
        ));
        // The millisecond rule is a release build's: a debug build's turn is
        // said and not held to it, as the estate's other figures are.
        if !cfg!(debug_assertions) {
            assert!(median < Duration::from_millis(1), "a turn took {median:?}");
        }
    });
}
