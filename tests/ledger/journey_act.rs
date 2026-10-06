//! An operator's acts on a Journey that failed (`runtime-model.md` section
//! 13: Retry and Dismiss):
//!
//! - Retry sends it again from its Send Port's queue, once its fault is
//!   fixed, and audits who acted;
//! - on a Sequential Send Port that blocks behind it, Retry keeps its place,
//!   so its sequence goes on in order from it, and Dismiss ends it
//!   Dismissed and lets the next of its sequence go;
//! - an act on a Journey that has not failed, or on none, is refused in
//!   words, and so is a word that is no act on a Journey;
//! - the Port's figures say it is blocked while the failed Journey waits,
//!   and neither failing nor blocked once it is acted on, its last failure
//!   kept apart as history.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use configure::{ExecutionStyle, OnFailure};
use journey::JourneyState;
use observe::Act;
use transport::TransportError;
use xaudit::program_audit::ProgramAudit;
use xcore::JourneyId;
use xmip_core_runtime::fixture::{Answer, FarEnd};
use xmip_core_runtime::ledger::CHUNK;
use xmip_core_runtime::message_path::carry;

use super::receive_cycle::{node, on_node};
use super::sending::{
    dispatching, journey, memory, onward, order, out, sender, took, until, waiting,
};

/// A far end refusing `order <refused>` for good until `fixed`.
fn broken_for(refused: u32, fixed: &Arc<AtomicBool>) -> Answer {
    let fixed = Arc::clone(fixed);
    let refusing = format!("order {refused}");
    Box::new(move |bytes| {
        if !fixed.load(Ordering::Acquire) && bytes == refusing.as_bytes() {
            return Err(TransportError {
                message: "the far end is broken".to_string(),
                retryable: false,
            });
        }
        Ok(())
    })
}

#[test]
fn a_retry_sends_a_failed_journey_again_once_its_fault_is_fixed_and_is_audited() {
    let at = std::env::temp_dir().join(format!("xmip-journey-act-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&at);
    let storage = memory();
    let fixed = Arc::new(AtomicBool::new(false));
    let (far, taken) = FarEnd::answering(broken_for(1, &fixed));
    let mut sending = sender(node(), far, out(|_| {}));
    sending.audit = Some(ProgramAudit::new(
        "xmip-runtime journey act tests",
        Some(&at),
    ));
    on_node(
        &storage,
        (CHUNK, &onward()),
        sending,
        |runtime, pickup, gate| {
            dispatching(runtime, |told| {
                let id = carry(runtime, pickup, gate, order(1)).journeys[0].journey_id();
                told.wait_for(id, "failed");
                let refused = runtime.send.act(&id.to_string(), Act::Replay, "ilian");
                assert!(refused.is_err_and(|said| said.contains("retry, dismiss")));

                fixed.store(true, Ordering::Release);
                let said = runtime
                    .send
                    .act(&id.to_string(), Act::Retry, "ilian")
                    .expect("retried");
                assert!(said.contains("retried by ilian"), "{said}");
                told.wait_for(id, "completed");
                let sent = journey(storage.as_ref(), id);
                assert_eq!(sent.state, JourneyState::Completed);
                let acts: Vec<&str> = sent.entries().iter().map(|e| e.action.as_str()).collect();
                assert_eq!(acts, ["send", "retry", "send"], "its history kept");
                assert_eq!(took(&taken), ["order 1"]);
                assert!(waiting(runtime).is_empty());

                let again = runtime.send.act(&id.to_string(), Act::Retry, "ilian");
                assert!(
                    again.is_err_and(|said| said.starts_with("REFUSED") && said.contains("Failed")),
                    "a Completed Journey is not retried"
                );
                let none = JourneyId::new(7).to_string();
                let unknown = runtime.send.act(&none, Act::Dismiss, "ilian");
                assert!(unknown.is_err_and(|said| said.contains("no Journey")));
            });
        },
    );
    xaudit::keeper::settle();
    let text = std::fs::read_to_string(at.join(xaudit::file_sink::FILE_NAME)).expect("kept");
    assert!(text.contains("action = \"journey.retry\""), "{text}");
    assert!(text.contains("\"by\" = \"ilian\""), "{text}");
    let _ = std::fs::remove_dir_all(&at);
}

/// Six orders through a Sequential `Out` that blocks, the third refused
/// until `act` is taken on it: what the far end took, and the Journey.
fn blocked_then(act: Act) -> (Vec<String>, JourneyState, Vec<JourneyId>) {
    let storage = memory();
    let fixed = Arc::new(AtomicBool::new(false));
    let (far, taken) = FarEnd::answering(broken_for(3, &fixed));
    let sequential = out(|port| {
        port.execution_style = Some(ExecutionStyle::Sequential);
        port.on_failure = Some(OnFailure::Block);
    });
    let mut state = JourneyState::Active;
    let mut left = Vec::new();
    on_node(
        &storage,
        (CHUNK, &onward()),
        sender(node(), far, sequential),
        |runtime, pickup, gate| {
            dispatching(runtime, |told| {
                let ids: Vec<JourneyId> = (1..=6)
                    .map(|n| carry(runtime, pickup, gate, order(n)).journeys[0].journey_id())
                    .collect();
                told.wait_for(ids[2], "failed");
                assert_eq!(waiting(runtime), ids[2..], "blocked behind it");
                let now = || {
                    let figures = &runtime.send.figures()["Out"];
                    (figures.failing, figures.blocked)
                };
                until(|| now() == (1, true), "said blocked");
                fixed.store(true, Ordering::Release);
                runtime
                    .send
                    .act(&ids[2].to_string(), act, "ilian")
                    .expect("acted");
                // A scan that read it Failed just before the act may say so
                // once more; the next reads it as the act left it.
                until(|| now() == (0, false), "acted on: none failing now");
                let last = runtime.send.figures()["Out"].last_failure.clone();
                assert_eq!(last.map(|(id, _)| id), Some(ids[2].to_string()), "history");
                for (place, id) in ids.iter().enumerate() {
                    if place != 2 {
                        told.wait_for(*id, "completed");
                    }
                }
                if act == Act::Retry {
                    told.wait_for(ids[2], "completed");
                }
                state = journey(storage.as_ref(), ids[2]).state;
                left = waiting(runtime);
            });
        },
    );
    (took(&taken), state, left)
}

#[test]
fn a_retry_of_a_journey_a_sequential_port_blocks_behind_keeps_its_order() {
    let (took, state, left) = blocked_then(Act::Retry);
    let all: Vec<String> = (1..=6).map(|n| format!("order {n}")).collect();
    assert_eq!(took, all, "in order, from it");
    assert_eq!(state, JourneyState::Completed);
    assert!(left.is_empty());
}

#[test]
fn a_dismiss_ends_a_failed_journey_dismissed_and_lets_its_sequence_go() {
    let (took, state, left) = blocked_then(Act::Dismiss);
    assert_eq!(
        took,
        ["order 1", "order 2", "order 4", "order 5", "order 6"]
    );
    assert_eq!(state, JourneyState::Dismissed, "a decision, not a failure");
    assert!(left.is_empty(), "out of its queue");
}
