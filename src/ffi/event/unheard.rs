//! `xmip_operate.h` section 11, who is not heard: the members of the
//! cluster the process's hub does not hear now — carried with every drained
//! batch and asked of the hub — forwarded (ADR-0065, amendment 2026-10-02).
//! The members not heard are the event crate's; their words are `observe::Unheard`'s; this
//! writes them in the header's JSON once, for a batch, the hub and the
//! subscriptions list alike.
#![allow(unsafe_code)]

use abi::ffi::status;
use abi::operate::event::EventBatch;
use observe::Unheard;
use serde_json::{Value, json};
use xevent::hub::Hub;

use super::Batch;
use crate::ffi::rule::refuse;

/// The members not heard, as the header writes them.
pub(super) fn listed(unheard: &[Unheard]) -> Value {
    unheard
        .iter()
        .map(|unheard| {
            json!({
                "by": unheard.by,
                "node": unheard.node,
                "since_unix_nanos": unheard.since_unix_nanos,
                "why": unheard.why,
                "said": unheard.said(),
            })
        })
        .collect()
}

/// Who was not heard when `batch` was drained, and whether that changed.
///
/// # Safety
/// `batch` is null or a batch next returned and nobody freed; `out` has
/// room for `cap` bytes; `out_len` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_event_batch_unheard_v1(
    batch: *const EventBatch,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: per the contract, a live batch or null.
    let Some(batch) = (unsafe { batch.cast::<Batch>().as_ref() }) else {
        return status::INVALID;
    };
    let text = json!({
        "changed": batch.unheard_changed,
        "unheard": listed(&batch.unheard),
    })
    .to_string();
    // SAFETY: `out` and `out_len` per the contract.
    unsafe { refuse(&text, out, cap, out_len) };
    status::OK
}

/// `xevent::hub::Hub::unheard` on the process's hub, forwarded.
///
/// # Safety
/// `out` has room for `cap` bytes; `out_len` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_event_unheard_v1(
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    let text = json!({ "unheard": listed(&Hub::process().unheard()) }).to_string();
    // SAFETY: `out` and `out_len` per the contract.
    unsafe { refuse(&text, out, cap, out_len) };
    status::OK
}
