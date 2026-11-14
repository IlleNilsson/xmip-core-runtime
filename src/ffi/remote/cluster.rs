//! `xmip_operate.h` section 17's `xmip_remote_cluster_v1`: the cluster's
//! publication a monitoring node gathered, read over a handle of the
//! section as the node's own is (`crate::plane::Remote::cluster`), with
//! the status a surface decides by — a node that gathers none told apart
//! from one that does not answer (ADR-0027 decision 8, amendment
//! 2026-11-13).
#![allow(unsafe_code)]

use abi::ffi::status;
use abi::operate::remote::Remote as RemoteHandle;

use super::{handed_text, held};
use crate::plane::remote::Clustered;

/// The cluster's publication the node gathered, as the text its file
/// would hold, and its revision: `UNSUPPORTED` with the node's refusal
/// where it declares no monitoring role, `UNAVAILABLE` with why where it
/// did not answer or refused the call. A text that did not fit is kept and
/// handed whole at the next call.
///
/// # Safety
/// `remote` is a live handle; `out` has room for `cap` bytes; `out_len`
/// and `out_revision` are writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_remote_cluster_v1(
    remote: *const RemoteHandle,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
    out_revision: *mut u64,
) -> i32 {
    // SAFETY: the caller's contract is this export's, passed on whole.
    abi::guarded(status::PANIC, || unsafe {
        remote_cluster(remote, out, cap, out_len, out_revision)
    })
}

/// [`xmip_remote_cluster_v1`] within its guard.
unsafe fn remote_cluster(
    remote: *const RemoteHandle,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
    out_revision: *mut u64,
) -> i32 {
    // SAFETY: per the contract above.
    let Some(held) = (unsafe { held(remote) }) else {
        return status::INVALID;
    };
    let read = || match held.remote.cluster() {
        Ok(Clustered::Gathered(revision, text)) => Ok((revision, text)),
        Ok(Clustered::GathersNone(said)) => Err((status::UNSUPPORTED, said)),
        Err(why) => Err((status::UNAVAILABLE, why)),
    };
    // SAFETY: per the contract above.
    unsafe { handed_text(&held.clustered, read, (out, cap, out_len), out_revision) }
}
