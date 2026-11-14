//! `xmip_operate.h` section 17: a node reached at its operate address, or
//! at its local endpoint on this machine, the surface `crate::plane::Remote`
//! is, forwarded.
//!
//! A handle owns its remote, or its listener, and one call frees it. The
//! follow, its recovery loop and every word are the plane's; this lays
//! them out as the header's values and decides nothing. An act asked
//! through a handle, on a noun or on the node's secrets, is [`act`]'s.
#![allow(unsafe_code)]

mod act;
mod cluster;

use std::sync::Mutex;
use std::time::Duration;
use xcore::lock::Locked;

use abi::ffi::{Str, status};
use abi::operate::remote::Remote as RemoteHandle;

pub use act::{xmip_remote_act_v1, xmip_secret_v1, xmip_secrets_v1};
pub use cluster::xmip_remote_cluster_v1;

use crate::ffi::rule::refuse;
use crate::ffi::text::scope_text;
use crate::plane::Remote;
use crate::plane::remote::Follows;

/// A remote, and the node's publication and the cluster's it gathered,
/// each read whole but not yet handed over whole.
struct Held {
    remote: Remote,
    pending: Mutex<Option<(u64, String)>>,
    clustered: Mutex<Option<(u64, String)>>,
}

/// A text read whole and its revision — `read` asked only where nothing
/// is `pending` — written into `out`, its true length into `out_len`; one
/// that did not fit kept in `pending` and handed whole at the next call
/// without asking the node again. Where `read` fails, its status and its
/// words in `out`.
///
/// # Safety
/// `out` has room for `cap` bytes; `out_len` and `out_revision` are
/// writable.
unsafe fn handed_text(
    pending: &Mutex<Option<(u64, String)>>,
    read: impl FnOnce() -> Result<(u64, String), (i32, String)>,
    (out, cap, out_len): (*mut u8, usize, *mut usize),
    out_revision: *mut u64,
) -> i32 {
    let mut pending = pending.locked();
    let (revision, text) = match pending.take() {
        Some(kept) => kept,
        None => match read() {
            Ok(read) => read,
            Err((failed, said)) => {
                // SAFETY: `out` and `out_len` per the contract.
                unsafe { refuse(&said, out, cap, out_len) };
                return failed;
            }
        },
    };
    // SAFETY: `out`, `out_len` and `out_revision` per the contract.
    unsafe {
        refuse(&text, out, cap, out_len);
        *out_revision = revision;
    }
    if text.len() > cap {
        *pending = Some((revision, text));
        return status::TRUNCATED;
    }
    status::OK
}

/// The identity three PEM texts make, or why not.
pub(crate) fn identity(
    certificate: &str,
    key: &str,
    anchors: &str,
) -> Result<tls::Identity, String> {
    tls::Identity::from_pem(certificate.as_bytes(), key.as_bytes(), anchors.as_bytes())
        .map_err(|failed| failed.message)
}

/// Four strings, each as `&str`, or `None` where one is not UTF-8.
///
/// # Safety
/// Each points at its stated length of readable bytes.
pub(crate) unsafe fn texts<'a>(strings: [Str; 4]) -> Option<[&'a str; 4]> {
    // SAFETY: the caller upholds the header's contract on every string.
    let [a, b, c, d] = strings.map(|text| unsafe { scope_text(text) });
    Some([a?, b?, c?, d?])
}

/// `crate::plane::Remote::open` over the node at `address`, presenting
/// `certificate` with `key` and trusting `anchors`, each PEM.
///
/// # Safety
/// The strings point at their stated lengths; `out` is writable; `report`
/// has room for `cap` bytes and `out_len` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_remote_open_v1(
    address: Str,
    certificate: Str,
    key: Str,
    anchors: Str,
    out: *mut *mut RemoteHandle,
    report: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: the caller's contract is this export's, passed on whole.
    abi::guarded(status::PANIC, || unsafe {
        remote_open(
            address,
            certificate,
            key,
            anchors,
            out,
            report,
            cap,
            out_len,
        )
    })
}

/// [`xmip_remote_open_v1`] within its guard.
#[expect(clippy::too_many_arguments, reason = "the export's own parameters")]
unsafe fn remote_open(
    address: Str,
    certificate: Str,
    key: Str,
    anchors: Str,
    out: *mut *mut RemoteHandle,
    report: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: per the contract above.
    let Some([address, certificate, key, anchors]) =
        (unsafe { texts([address, certificate, key, anchors]) })
    else {
        return status::MALFORMED;
    };
    let opened =
        identity(certificate, key, anchors).and_then(|identity| Remote::open(address, &identity));
    // SAFETY: per the contract above.
    unsafe { handed(opened, out, report, cap, out_len) }
}

/// `crate::plane::Remote::local` over the node on this machine whose local
/// endpoint is called `endpoint` — a named pipe on Windows, a Unix domain
/// socket elsewhere (ADR-0014, amendment 2026-10-13) — each call waiting
/// at most `within_ms`, or where it is 0 what the node declared from its
/// `[tuning] local_timeout`.
///
/// # Safety
/// `endpoint` points at its stated length; `out` is writable; `report` has
/// room for `cap` bytes and `out_len` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_remote_open_local_v1(
    endpoint: Str,
    within_ms: u32,
    out: *mut *mut RemoteHandle,
    report: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: the caller's contract is this export's, passed on whole.
    abi::guarded(status::PANIC, || unsafe {
        remote_open_local(endpoint, within_ms, out, report, cap, out_len)
    })
}

/// [`xmip_remote_open_local_v1`] within its guard.
unsafe fn remote_open_local(
    endpoint: Str,
    within_ms: u32,
    out: *mut *mut RemoteHandle,
    report: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: per the contract above.
    let Some(endpoint) = (unsafe { scope_text(endpoint) }) else {
        return status::MALFORMED;
    };
    let within = std::time::Duration::from_millis(u64::from(within_ms));
    // SAFETY: per the contract above.
    unsafe { handed(Remote::local(endpoint, within), out, report, cap, out_len) }
}

/// A remote opened, as a handle in `out`, or why not in `report`.
///
/// # Safety
/// `out` is writable; `report` has room for `cap` bytes; `out_len` is
/// writable.
pub(crate) unsafe fn handed(
    opened: Result<Remote, String>,
    out: *mut *mut RemoteHandle,
    report: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    match opened {
        Ok(remote) => {
            let held = Box::new(Held {
                remote,
                pending: Mutex::new(None),
                clustered: Mutex::new(None),
            });
            // SAFETY: `out` and `out_len` are writable per the contract.
            unsafe {
                *out = Box::into_raw(held).cast::<RemoteHandle>();
                *out_len = 0;
            }
            status::OK
        }
        Err(said) => {
            // SAFETY: per the contract above.
            unsafe {
                *out = core::ptr::null_mut();
                refuse(&said, report, cap, out_len);
            }
            status::INVALID
        }
    }
}

/// The remote behind a handle.
///
/// # Safety
/// `remote` is null or a live handle `xmip_remote_open_v1` or
/// `xmip_remote_open_local_v1` returned.
unsafe fn held<'a>(remote: *const RemoteHandle) -> Option<&'a Held> {
    // SAFETY: per the contract above.
    unsafe { remote.cast::<Held>().as_ref() }
}

/// The node's publication as the text its file holds, and its revision. A
/// text that did not fit is kept and handed whole at the next call.
///
/// # Safety
/// `remote` is a live handle; `out` has room for `cap` bytes; `out_len`
/// and `out_revision` are writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_remote_publication_v1(
    remote: *const RemoteHandle,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
    out_revision: *mut u64,
) -> i32 {
    // SAFETY: the caller's contract is this export's, passed on whole.
    abi::guarded(status::PANIC, || unsafe {
        remote_publication(remote, out, cap, out_len, out_revision)
    })
}

/// [`xmip_remote_publication_v1`] within its guard.
unsafe fn remote_publication(
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
    let read = || {
        held.remote
            .publication()
            .map_err(|said| (status::UNAVAILABLE, said))
    };
    // SAFETY: per the contract above.
    unsafe { handed_text(&held.pending, read, (out, cap, out_len), out_revision) }
}

/// Wait until a follower has been told more than `seen` times, or for
/// `timeout_ms`, following the publication `follows` names — the node's
/// own (0), the cluster's it gathered (1), or the cluster's where the node
/// answers one and else its own (2), the first wait naming which the handle
/// follows: how many times, the revision, whether the node is reached,
/// which it follows (2 until the node's answer decided) and, where it is
/// not reached, why.
///
/// # Safety
/// `remote` is a live handle; every `out_` is writable; `reason` has room
/// for `cap` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_remote_wait_v1(
    remote: *const RemoteHandle,
    follows: u32,
    seen: u64,
    timeout_ms: u32,
    out_told: *mut u64,
    out_revision: *mut u64,
    out_reachable: *mut u8,
    out_follows: *mut u32,
    reason: *mut u8,
    cap: usize,
    reason_len: *mut usize,
) -> i32 {
    // SAFETY: the caller's contract is this export's, passed on whole.
    abi::guarded(status::PANIC, || unsafe {
        remote_wait(
            remote,
            (follows, seen, timeout_ms),
            (out_told, out_revision, out_reachable, out_follows),
            reason,
            cap,
            reason_len,
        )
    })
}

/// [`xmip_remote_wait_v1`] within its guard.
unsafe fn remote_wait(
    remote: *const RemoteHandle,
    (follows, seen, timeout_ms): (u32, u64, u32),
    (out_told, out_revision, out_reachable, out_follows): (*mut u64, *mut u64, *mut u8, *mut u32),
    reason: *mut u8,
    cap: usize,
    reason_len: *mut usize,
) -> i32 {
    // SAFETY: per the contract above.
    let (Some(held), Some(follows)) = (unsafe { held(remote) }, Follows::from_wire(follows)) else {
        return status::INVALID;
    };
    let within = Duration::from_millis(u64::from(timeout_ms));
    let state = match held.remote.follow(follows, seen, within) {
        Ok(state) => state,
        Err(said) => {
            // SAFETY: per the contract above.
            unsafe { refuse(&said, reason, cap, reason_len) };
            return status::STATE;
        }
    };
    // SAFETY: per the contract above.
    unsafe {
        *out_told = state.told;
        *out_revision = state.revision;
        *out_reachable = u8::from(state.reachable);
        *out_follows = state.follows as u32;
        refuse(&state.reason, reason, cap, reason_len);
    }
    status::OK
}

/// End a remote's follow and wake every wait on it, from any thread, while
/// a call may still be in flight on another: what a binding asks before it
/// frees the handle.
///
/// # Safety
/// `remote` is null or a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_remote_end_v1(remote: *const RemoteHandle) {
    abi::guarded((), || {
        // SAFETY: per the contract above.
        if let Some(held) = unsafe { held(remote) } {
            held.remote.end();
        }
    });
}

/// Release a remote: its follow ended, its connections closed. No call on
/// it may be in flight.
///
/// # Safety
/// `remote` is null or a handle `xmip_remote_open_v1` or
/// `xmip_remote_open_local_v1` returned and nobody freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_remote_free_v1(remote: *mut RemoteHandle) {
    if !remote.is_null() {
        // SAFETY: per the contract above, the box this handle was made from.
        let held = unsafe { Box::from_raw(remote.cast::<Held>()) };
        abi::guarded((), || drop(held));
    }
}
