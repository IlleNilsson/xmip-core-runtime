//! How long a local call may wait (`plane::deadline`), measured: a node
//! that does not answer within the wait is unreachable at once after.

use std::time::{Duration, Instant};

use xmip_core_runtime::plane::Remote;
use xmip_core_runtime::plane::deadline::{Hung, not_answered};

/// Decided by the owner, 2026-10-13: *a local call waits at most a set
/// time, then says the node did not answer and shows it so.* An endpoint
/// that takes the connection and never answers stands for a hung node.
#[test]
fn a_node_that_does_not_answer_within_the_wait_is_unreachable_at_once_after() {
    let name = format!("xmip-deadline-test-{}", std::process::id());
    let hung = Hung::at(&name);
    let within = Duration::from_millis(150);
    let surface =
        Remote::local_retrying(&name, within, vec![Duration::from_secs(60)]).expect("a surface");

    let asked = Instant::now();
    let said = surface.publication().expect_err("no answer");
    assert!(asked.elapsed() < within * 4, "{:?}", asked.elapsed());
    assert!(said.ends_with(&not_answered(within)), "{said}");
    assert!(!surface.state().reachable);
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
