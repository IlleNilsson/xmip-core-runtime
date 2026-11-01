//! When a queue's earliest retry is due (`send_step`, open problem 43),
//! measured: the send step wakes for it within a millisecond.

use std::time::{Duration, Instant};

use xmip_core_runtime::fixture::send_step;

use super::sending::memory;

/// A queue's retry is woken for within a millisecond of its due time,
/// apart from load: held to `std::thread::sleep` measured beside it.
/// Until 2026-10-17 the wait ended on Windows' system tick, 9-14 ms late
/// (`xcore::wake`).
#[test]
fn a_due_time_is_woken_for_within_a_millisecond() {
    const DUE: Duration = Duration::from_millis(2);
    const ROUNDS: usize = 200;
    let step = send_step(&memory());
    let (mut late, mut control) = (Vec::new(), Vec::new());
    for _ in 0..ROUNDS {
        late.push(step.woken_late(DUE));
        let slept = Instant::now();
        std::thread::sleep(DUE);
        control.push(slept.elapsed().saturating_sub(DUE));
    }
    // The fastest of five: a sleep's tail moves by milliseconds either way
    // on a busy machine. The tail is held in `xcore::wake`'s tests.
    let late = xcore::latency::spread("a retry woken after its due time", late);
    let usual = xcore::latency::spread("a sleep beside it", control).fastest_of_five;
    assert!(
        late.fastest_of_five < Duration::from_millis(1) + usual,
        "the fastest of five {:?} late, the machine's own {usual:?}",
        late.fastest_of_five
    );
}
