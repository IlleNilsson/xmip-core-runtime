//! The follow of a remote surface: a connection of its own to the node,
//! held in a wait the node answers when its publication advances, every
//! follower told at once — and, when the node cannot be reached, the
//! recovery loop of ADR-0052's note of 2026-10-05, on its own thread.

use std::sync::atomic::Ordering;
use std::sync::{Arc, PoisonError};
use std::time::Duration;

use serde_json::json;

use crate::plane::call::{LONGEST_WAIT, WAIT};
use crate::plane::line::Line;
use crate::plane::shared::Shared;

/// Follow until the surface ends: reach the node, hold its wait while it
/// answers, and when it is lost or never reached, tell every follower why
/// and try again on the retry schedule.
pub(crate) fn run(shared: &Arc<Shared>) {
    let mut attempt = 0usize;
    while !shared.ending() {
        shared.connecting.store(true, Ordering::SeqCst);
        let opened = Line::open(
            &shared.reach,
            shared.patience,
            LONGEST_WAIT + shared.patience,
            shared.ended(),
            &shared.following,
        );
        shared.connecting.store(false, Ordering::SeqCst);
        let why = match opened {
            Ok(line) => {
                attempt = 0;
                held(shared, line)
            }
            Err(why) => why,
        };
        if shared.ending() {
            return;
        }
        // Told once a node is lost or a try fails anew, not at every try.
        let anew = {
            let state = shared.state.lock().unwrap_or_else(PoisonError::into_inner);
            state.told == 0 || state.reachable || state.reason != why
        };
        if anew {
            shared.tell(|state| {
                state.reachable = false;
                state.reason = why;
            });
        }
        pause(shared, shared.retry[attempt.min(shared.retry.len() - 1)]);
        attempt += 1;
    }
}

/// Hold the node's wait on `line` while it answers: every follower told
/// the node is reached, then each revision as it advances. Why it ended.
fn held(shared: &Shared, mut line: Line) -> String {
    let mut revision = 0;
    let mut reached = false;
    let within = u64::try_from(LONGEST_WAIT.as_millis()).unwrap_or(u64::MAX);
    loop {
        if shared.ending() {
            return String::new();
        }
        let asked = json!({ "after": revision, "within_ms": if reached { within } else { 0 } });
        match line.call(WAIT, &asked) {
            Ok(answer) => {
                let now = answer["revision"].as_u64().unwrap_or(revision);
                // A call that waited too long said the node unreachable;
                // its next answer here says it is back.
                let said_lost = !shared
                    .state
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .reachable;
                if !reached || now != revision || said_lost {
                    revision = now;
                    shared.tell(|state| {
                        state.reachable = true;
                        state.reason.clear();
                        state.revision = now;
                    });
                }
                reached = true;
            }
            Err(why) => return format!("lost: {why}"),
        }
    }
}

/// Wait `delay`, or less where the surface ends meanwhile.
fn pause(shared: &Shared, delay: Duration) {
    if delay.is_zero() {
        return;
    }
    let state = shared.state.lock().unwrap_or_else(PoisonError::into_inner);
    let _ = shared
        .told
        .wait_timeout_while(&shared.state, state, delay, |_| !shared.ending());
}
