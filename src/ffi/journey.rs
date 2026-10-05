//! `xmip_operate.h` section 16, an operator's act on a Journey that failed:
//! Retry or Dismiss on the send step of a node in this process, forwarded.
//!
//! The act, its write and its audit are `crate::send_step`'s; the act's word
//! is `observe`'s.
#![allow(unsafe_code)]

use abi::ffi::{Str, status};
use observe::Act;

use crate::ffi::operate::scope_text;
use crate::ffi::rule::refuse;
use crate::send_step::SendStep;

/// `crate::send_step::SendStep::act` on the node at `node` in this process,
/// forwarded: `act` on the Journey `journey`, by `who`.
///
/// # Safety
/// Every `Str` points at its stated length of readable bytes; `said` has room
/// for `said_cap` bytes; `said_len` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_journey_act_v1(
    node: Str,
    journey: Str,
    act: Str,
    who: Str,
    said: *mut u8,
    said_cap: usize,
    said_len: *mut usize,
) -> i32 {
    // SAFETY: the caller upholds the header's contract on every string.
    let texts = unsafe {
        [
            scope_text(node),
            scope_text(journey),
            scope_text(act),
            scope_text(who),
        ]
    };
    let [Some(node), Some(journey), Some(act), Some(who)] = texts else {
        return status::MALFORMED;
    };
    let (code, sentence) = acted(node, journey, act, who);

    // SAFETY: `said` and `said_len` per the contract.
    unsafe { refuse(&sentence, said, said_cap, said_len) };
    code
}

/// What came of `act` on `journey` at `node`, and its status.
fn acted(node: &str, journey: &str, act: &str, who: &str) -> (i32, String) {
    let Some(act) = Act::named(act).filter(|act| matches!(act, Act::Retry | Act::Dismiss)) else {
        let refused = observe::Noun::Journey.act(act).err().unwrap_or_default();
        return (status::INVALID, refused);
    };
    let step = SendStep::registered()
        .into_iter()
        .find(|step| step.node() == node);
    match step {
        None => (
            status::NOT_FOUND,
            format!("REFUSED: no node at {node} runs in this process"),
        ),
        Some(step) => match step.act(journey, act, who) {
            Ok(done) => (status::OK, done),
            Err(failed) if failed.starts_with("FAILED") => (status::IO, failed),
            Err(refused) => (status::NOT_FOUND, refused),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::operate::borrow;

    #[test]
    fn the_export_has_the_shape_the_binding_declares() {
        let _: abi::operate::journey::JourneyActFn = xmip_journey_act_v1;
    }

    fn act(node: &str, word: &str) -> (i32, String) {
        let mut buffer = vec![0u8; 1024];
        let mut length = 0usize;
        // SAFETY: every pointer is this test's own string or buffer, alive for the call.
        let code = unsafe {
            xmip_journey_act_v1(
                borrow(node),
                borrow("0199a000-0000-7000-8000-000000000001"),
                borrow(word),
                borrow("an operator"),
                buffer.as_mut_ptr(),
                buffer.len(),
                &raw mut length,
            )
        };
        (
            code,
            String::from_utf8_lossy(&buffer[..length]).into_owned(),
        )
    }

    #[test]
    fn an_act_on_a_node_not_here_or_no_act_on_a_journey_is_refused_in_words() {
        let node = format!(
            "{}-ffi-journey",
            configure::fixture::test_cluster().node_scope(0)
        );
        let (code, said) = act(&node, "retry");
        assert_eq!(code, status::NOT_FOUND);
        assert!(said.starts_with("REFUSED: no node at"), "{said}");
        let (code, said) = act(&node, "replay");
        assert_eq!(code, status::INVALID);
        assert!(said.contains("the acts are retry, dismiss"), "{said}");
    }
}
