//! The follow of a remote surface: a connection of its own to the node,
//! held in a wait the node answers when its publication advances, every
//! follower told at once — and, when the node cannot be reached, the
//! recovery loop of ADR-0052's note of 2026-10-05, on its own thread.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use xcore::lock::Locked;

use serde_json::json;

use crate::plane::call::LONGEST_WAIT;
use crate::plane::deadline;
use crate::plane::line::Line;
use crate::plane::remote::{Follows, Waited};
use crate::plane::shared::Shared;

/// Follow until the surface ends: reach the node, hold its wait while it
/// answers, and when it is lost or never reached, tell every follower why
/// and try again on the retry schedule. Each try — the connect, the
/// handshake and the node's first answer — waits at most what every call on
/// the surface waits, its patience: on a line that keeps time by its
/// silence, and on one that keeps none by the process's deadline thread
/// (`plane::deadline`); a try that ran out says so in the one sentence,
/// *the node did not answer within …* (until 2026-11-13 the first try of a
/// hung node waited out the follow's long silence).
pub(crate) fn run(shared: &Arc<Shared>) {
    let mut attempt = 0usize;
    while !shared.ending() {
        let began = Instant::now();
        shared.trying.arm(shared.patience);
        shared.connecting.store(true, Ordering::SeqCst);
        let opened = Line::open(
            &shared.reach,
            shared.patience,
            shared.patience,
            shared.ended(),
            &shared.following,
        );
        shared.connecting.store(false, Ordering::SeqCst);
        let (why, answered) = match opened {
            Ok(line) => held(shared, line),
            Err(why) => (why, false),
        };
        let ran_out = shared.trying.disarm();
        if shared.ending() {
            return;
        }
        // The schedule starts again only once the node answered a wait: a
        // node that takes the connection and refuses the wait — a caller
        // holding no role, the cluster's at a node gathering none — is
        // tried again on the schedule, never at once over and over.
        if answered {
            attempt = 0;
        }
        let why = if !answered && (ran_out || began.elapsed() >= shared.patience) {
            deadline::not_answered(shared.patience)
        } else {
            why
        };
        // Told once a node is lost or a try fails anew, not at every try.
        let anew = {
            let state = shared.state.locked();
            state.told == 0 || state.reachable || state.reason != why
        };
        // A node lost is asked again which it answers, where its answer
        // decides: until then the state says nothing has.
        if anew {
            shared.tell(|state| {
                state.reachable = false;
                state.reason = why;
                state.follows = shared.follows();
            });
        }
        pause(shared, shared.retry[attempt.min(shared.retry.len() - 1)]);
        attempt += 1;
    }
}

/// Hold the node's wait on `line` while it answers — on the publication the
/// surface follows, the node's own or the cluster's it gathered
/// (`remote::cluster`), asked afresh where a wait has named another since,
/// and where the surface left it to the node's answer, the cluster's unless
/// the node says it gathers none, then its own — every follower told the
/// node is reached and which it follows, then each revision as it
/// advances; once the node first answered, its try is over and each wait
/// may be held as long as the node holds it. Why it ended, and whether the
/// node answered a wait first.
fn held(shared: &Shared, mut line: Line) -> (String, bool) {
    let mut revision = 0;
    let mut reached = false;
    let mut answered = false;
    let mut asked_for = shared.follows();
    let mut follows = asked_for;
    let within = u64::try_from(LONGEST_WAIT.as_millis()).unwrap_or(u64::MAX);
    loop {
        if shared.ending() {
            return (String::new(), answered);
        }
        if shared.follows() != asked_for {
            asked_for = shared.follows();
            (follows, revision, reached) = (asked_for, 0, false);
        }
        let asked = json!({ "after": revision, "within_ms": if reached { within } else { 0 } });
        match follows.waited(line.call(follows.method(), &asked, None)) {
            Waited::Revision(now) => {
                let now = now.unwrap_or(revision);
                // A call that waited too long said the node unreachable;
                // its next answer here says it is back.
                let said_lost = !shared.state.locked().reachable;
                if !reached || now != revision || said_lost {
                    revision = now;
                    let decided = if follows == Follows::Answered {
                        Follows::Cluster
                    } else {
                        follows
                    };
                    shared.tell(|state| {
                        state.reachable = true;
                        state.reason.clear();
                        state.revision = now;
                        state.follows = decided;
                    });
                }
                if !answered {
                    let _ = shared.trying.disarm();
                    line.hold(LONGEST_WAIT + shared.patience);
                }
                (reached, answered) = (true, true);
            }
            Waited::Instead(instead) => (follows, revision, reached) = (instead, 0, false),
            Waited::Lost(why) => return (why, answered),
        }
    }
}

/// Wait `delay`, or less where the surface ends meanwhile.
fn pause(shared: &Shared, delay: Duration) {
    if delay.is_zero() {
        return;
    }
    let state = shared.state.locked();
    let _ = shared
        .told
        .wait_timeout_while(&shared.state, state, delay, |_| !shared.ending());
}

#[cfg(all(test, feature = "node"))]
mod tests {
    use std::time::{Duration, Instant};

    use crate::plane::deadline::{Hung, not_answered};
    use crate::plane::remote::{Follows, Remote};

    /// A hung node, a local endpoint that takes the connection and never
    /// answers, is told unreachable by the follow's first try within the
    /// surface's own wait, in the one sentence every call says it in,
    /// whichever publication the surface follows — where until 2026-11-13
    /// the try waited out the follow's long silence.
    #[test]
    fn a_follows_first_try_of_a_hung_node_is_told_within_the_surfaces_wait() {
        let within = Duration::from_millis(200);
        for (round, follows) in [Follows::Answered, Follows::Node].into_iter().enumerate() {
            let name = format!("xmip-follow-hung-{}-{round}", std::process::id());
            let _hung = Hung::at(&name);
            let retry = vec![Duration::from_secs(30)];
            let surface = Remote::local_retrying(&name, within, retry).expect("a surface");
            let began = Instant::now();
            let state = surface
                .follow(follows, 0, Duration::from_secs(10))
                .expect("it follows");
            let took = began.elapsed();
            assert!(
                took < Duration::from_secs(2),
                "{follows:?} told in {took:?}"
            );
            assert!(!state.reachable, "{follows:?}");
            assert_eq!(state.reason, not_answered(within), "{follows:?}");
            assert_eq!(state.follows, follows);
        }
    }
}
