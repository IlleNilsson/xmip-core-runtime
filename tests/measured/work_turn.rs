//! What a Work Process's turn costs beside its Ledger writes (ADR-0066,
//! amendment 2026-10-22), over the Ledger tests' Work Process
//! (`tests/ledger/work_design.rs`). A turn waits on Xmip Storage's one
//! writer twice, for its claim and for its write, so it is a wait that
//! works as it wakes, held as every one is: each turn one round beside a
//! plain wake (`xcore::latency::Rounds`), its wall clock under the
//! millisecond plus a plain wake for each thread it wakes, and the
//! process's processor time across it under the millisecond plus a plain
//! wake's, each the fastest of five. Until 2026-11-15 its median was held
//! in a release build only, which the estate never builds, so the hold
//! never ran.

use xcore::latency::Rounds;
use xmip_core_runtime::work_step::{Turned, turn_due};

use super::sending::memory;
use super::work_design::{carried, working};

/// What a turn wakes where a plain wake wakes one: for its claim and for
/// its write each, Xmip Storage's writer, its sync thread and the turn
/// again (`persist::storage::commit`).
const WAKES: u32 = 6;

#[test]
fn a_turn_costs_far_under_a_millisecond_beside_its_ledger_writes() {
    let storage = memory();
    working(&storage, |runtime, pickup, gate| {
        let mut rounds = Rounds::crossing(WAKES);
        for (number, who) in (0..200u32).map(|n| (n % 4, format!("C{}", n / 4))) {
            carried(runtime, pickup, gate, &who, number);
            let turned = rounds.round(|| turn_due(runtime, pickup));
            assert!(
                turned.iter().all(|t| matches!(t, Turned::Done)),
                "{turned:?}"
            );
        }
        rounds.hold("a turn, its Ledger reads and its writes in memory");
    });
}
