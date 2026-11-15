//! How long a local call may wait (`plane::deadline`), measured: a node
//! that does not answer within the wait is unreachable at once after.

use std::time::{Duration, Instant};

use xcore::fastest::FIVE;
use xcore::latency::spread;
use xmip_core_runtime::plane::Remote;
use xmip_core_runtime::plane::deadline::{Hung, not_answered};

/// Decided by the owner, 2026-10-13: *a local call waits at most a set
/// time, then says the node did not answer and shows it so.* An endpoint
/// that takes the connection and never answers stands for a hung node.
#[test]
fn a_node_that_does_not_answer_within_the_wait_is_unreachable_at_once_after() {
    let within = Duration::from_millis(150);
    // A give-up at its wait, five times, each at a hung node of its own,
    // which takes one connection: a give-up that outlives its wait does so
    // in all five, one a busy machine preempted in some only. It is a
    // timeout, not a wake, so no plain wake is measured beside it; the
    // fastest of five (`xcore::latency::spread`). Until 2026-11-15 one
    // give-up was timed once.
    let (mut gave_up, mut last) = (Vec::with_capacity(FIVE), None);
    for round in 0..FIVE {
        let name = format!("xmip-deadline-test-{}-{round}", std::process::id());
        let hung = Hung::at(&name);
        let surface = Remote::local_retrying(&name, within, vec![Duration::from_secs(60)])
            .expect("a surface");
        let asked = Instant::now();
        let said = surface.publication().expect_err("no answer");
        gave_up.push(asked.elapsed());
        assert!(said.ends_with(&not_answered(within)), "{said}");
        assert!(!surface.state().reachable);
        // The one before let go of, the surface first.
        last = Some((surface, hung));
    }
    let gave_up = spread("a hung node given up at its wait", gave_up).fastest_of_five;
    assert!(
        gave_up < within * 4,
        "gave up after {gave_up:?}, the fastest of five, which is not its wait"
    );
    let (surface, hung) = last.expect("five asked");
    // Said at once from now on, while the follow recovers it: the fastest
    // of five under the millisecond, and no more than that of the caller's
    // processor time in any (xcore::latency::at_once).
    let (again, fastest, spent) =
        xcore::latency::at_once("a hung node, asked again", || surface.publication());
    assert!(again.is_err());
    assert!(fastest < Duration::from_millis(1), "said in {fastest:?}");
    assert!(
        spent < Duration::from_millis(1),
        "{spent:?} of processor time"
    );
    drop(surface);
    drop(hung);
}
