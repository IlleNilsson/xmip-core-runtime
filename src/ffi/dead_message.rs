//! `xmip_operate.h` section 15, a node's Dead Message Queue: what the
//! queues of this process's nodes keep, and what a read publication carries
//! of them (ADR-0052, amendment 2026-10-01), forwarded. A Replay reaches a
//! node through its operate listener's door and Xmip Storage, never here
//! (ADR-0014, amendment 2026-11-13).
//!
//! The queue is `crate::pickup`'s. This writes one list's JSON, once, for
//! this process's nodes and for a read publication alike.
#![allow(unsafe_code)]

#[cfg(feature = "node")]
use abi::ffi::Str;
use abi::ffi::status;
use abi::operate::publication::Publication as Handle;
#[cfg(feature = "node")]
use node::Scope;
use observe::DeadMessage;
use serde_json::{Value, json};

use crate::ffi::publication::held;
use crate::ffi::rule::refuse;
#[cfg(feature = "node")]
use crate::ffi::text::scope_text;
#[cfg(feature = "node")]
use crate::pickup::{PUBLISHED, Pickup};

/// A list of Dead Message Queue entries as the header writes it.
fn listed<'a>(dead: impl Iterator<Item = &'a DeadMessage>) -> String {
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
    json!({ "dead_messages": dead }).to_string()
}

/// The Dead Message Queue of every node in this process at or beneath
/// `node` (empty: all), the oldest of each, as
/// `crate::pickup::Pickup::dead_messages` reads it.
///
/// # Safety
/// `node` points at its stated length of readable bytes; `out` has room for
/// `cap` bytes; `out_len` is writable.
#[unsafe(no_mangle)]
#[cfg(feature = "node")]
pub unsafe extern "C" fn xmip_dead_messages_v1(
    node: Str,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: the caller's contract is this export's, passed on whole.
    abi::guarded(status::PANIC, || unsafe {
        dead_listed(node, out, cap, out_len)
    })
}

/// [`xmip_dead_messages_v1`] within its guard.
#[cfg(feature = "node")]
unsafe fn dead_listed(node: Str, out: *mut u8, cap: usize, out_len: *mut usize) -> i32 {
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
    unsafe { refuse(&listed(dead.iter()), out, cap, out_len) };
    status::OK
}

/// What a read publication carries of Dead Message Queues.
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
    // SAFETY: the caller's contract is this export's, passed on whole.
    abi::guarded(status::PANIC, || unsafe {
        publication_dead_messages(publication, out, cap, out_len)
    })
}

/// [`xmip_publication_dead_messages_v1`] within its guard.
unsafe fn publication_dead_messages(
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
    let text = listed(publication.dead_messages.iter());

    // SAFETY: `out` and `out_len` per the contract.
    unsafe { refuse(&text, out, cap, out_len) };
    status::OK
}

#[cfg(all(test, feature = "node"))]
mod tests {
    use super::*;

    #[test]
    fn the_exports_have_the_shapes_the_binding_declares() {
        let _: abi::operate::dead_message::DeadMessagesFn = xmip_dead_messages_v1;
        let _: abi::operate::dead_message::PublicationDeadMessagesFn =
            xmip_publication_dead_messages_v1;
    }

    #[test]
    fn a_list_says_no_place_to_leave_an_act() {
        let read: Value = serde_json::from_str(&listed(std::iter::empty())).expect("JSON");
        assert_eq!(read["dead_messages"], json!([]));
        assert_eq!(
            read.get("orders"),
            None,
            "a snapshot is read, never acted on"
        );
    }
}
