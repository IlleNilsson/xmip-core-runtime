//! `xmip_operate.h` section 15, a node's Dead Message Queue: what the
//! queues of this process's nodes keep, Replay on one of them, and what a
//! read publication carries of them (ADR-0052, amendment 2026-10-01),
//! forwarded.
//!
//! The queue, the Replay and its audit are `crate::pickup`'s; the act's word
//! is `observe`'s. This writes one list's JSON, once, for this process's
//! nodes and for a read publication alike.
#![allow(unsafe_code)]

use abi::ffi::{Str, status};
use abi::operate::publication::Publication as Handle;
use observe::{DeadMessage, Scope};
use serde_json::{Value, json};

use crate::ffi::operate::scope_text;
use crate::ffi::publication::held;
use crate::ffi::rule::refuse;
use crate::pickup::{PUBLISHED, Pickup};

/// A list of Dead Message Queue entries as the header writes it.
fn listed<'a>(orders: &str, dead: impl Iterator<Item = &'a DeadMessage>) -> String {
    let dead: Vec<Value> = dead
        .map(|entry| {
            json!({
                "node": entry.node,
                "message": entry.message,
                "sequence": entry.sequence,
                "location": entry.location,
                "received_unix_nanos": entry.received_unix_nanos,
                "validation": entry.validation,
                "promoted": entry.promoted,
                "declines": entry.declines,
            })
        })
        .collect();
    json!({ "orders": orders, "dead_messages": dead }).to_string()
}

/// The Dead Message Queue of every node in this process at or beneath
/// `node` (empty: all), the oldest of each, as
/// `crate::pickup::Pickup::dead_messages` reads it.
///
/// # Safety
/// `node` points at its stated length of readable bytes; `out` has room for
/// `cap` bytes; `out_len` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_dead_messages_v1(
    node: Str,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: the caller upholds the header's contract on `node`.
    let Some(node) = (unsafe { scope_text(node) }) else {
        return status::MALFORMED;
    };
    let within = Scope::new(node);
    let dead: Vec<DeadMessage> = Pickup::registered()
        .iter()
        .filter(|pickup| within.contains(Scope::new(pickup.node())))
        .filter_map(|pickup| pickup.dead_messages(PUBLISHED).ok())
        .flat_map(|(_, dead)| dead)
        .collect();

    // SAFETY: `out` and `out_len` per the contract.
    unsafe { refuse(&listed("", dead.iter()), out, cap, out_len) };
    status::OK
}

/// `crate::pickup::Pickup::replay` on the node at `node` in this process,
/// forwarded: replay the Message `message`, by `who`.
///
/// # Safety
/// Every `Str` points at its stated length of readable bytes; `said` has room
/// for `said_cap` bytes; `said_len` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_dead_message_replay_v1(
    node: Str,
    message: Str,
    who: Str,
    said: *mut u8,
    said_cap: usize,
    said_len: *mut usize,
) -> i32 {
    // SAFETY: the caller upholds the header's contract on every string.
    let texts = unsafe { (scope_text(node), scope_text(message), scope_text(who)) };
    let (Some(node), Some(message), Some(who)) = texts else {
        return status::MALFORMED;
    };
    let pickup = Pickup::registered()
        .into_iter()
        .find(|pickup| pickup.node() == node);
    let (code, sentence) = match pickup {
        None => (
            status::NOT_FOUND,
            format!("REFUSED: no node at {node} runs in this process"),
        ),
        Some(pickup) => match pickup.replay(message, who) {
            Ok(done) => (status::OK, done),
            Err(failed) if failed.starts_with("FAILED") => (status::IO, failed),
            Err(refused) => (status::NOT_FOUND, refused),
        },
    };

    // SAFETY: `said` and `said_len` per the contract.
    unsafe { refuse(&sentence, said, said_cap, said_len) };
    code
}

/// What a read publication carries of Dead Message Queues, and where its
/// publisher takes orders.
///
/// # Safety
/// `publication` is a live handle; `out` has room for `cap` bytes;
/// `out_len` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_publication_dead_messages_v1(
    publication: *const Handle,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: per the contract above.
    let Some(read) = (unsafe { held(publication) }) else {
        return status::INVALID;
    };
    let publication = &read.publication;
    let text = listed(&publication.orders, publication.dead_messages.iter());

    // SAFETY: `out` and `out_len` per the contract.
    unsafe { refuse(&text, out, cap, out_len) };
    status::OK
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::operate::borrow;

    #[test]
    fn the_exports_have_the_shapes_the_binding_declares() {
        let _: abi::operate::dead_message::DeadMessagesFn = xmip_dead_messages_v1;
        let _: abi::operate::dead_message::DeadMessageReplayFn = xmip_dead_message_replay_v1;
        let _: abi::operate::dead_message::PublicationDeadMessagesFn =
            xmip_publication_dead_messages_v1;
    }

    #[test]
    fn a_replay_on_a_node_not_here_is_refused_in_words() {
        let mut buffer = vec![0u8; 1024];
        let mut length = 0usize;
        let node = format!(
            "{}-ffi-dead-messages",
            configure::fixture::test_cluster().node_scope(0)
        );
        // SAFETY: every pointer is this test's own string or buffer, alive for the call.
        let code = unsafe {
            xmip_dead_message_replay_v1(
                borrow(&node),
                borrow("0199a000-0000-7000-8000-000000000001"),
                borrow("an operator"),
                buffer.as_mut_ptr(),
                buffer.len(),
                &raw mut length,
            )
        };
        let said = String::from_utf8_lossy(&buffer[..length]).into_owned();
        assert_eq!(code, status::NOT_FOUND);
        assert!(said.starts_with("REFUSED: no node at"), "{said}");
    }
}
