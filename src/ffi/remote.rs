//! `xmip_operate.h` section 17: a node reached at its operate address, or
//! at its local endpoint on this machine, the surface `crate::plane::Remote`
//! is, forwarded.
//!
//! A handle owns its remote, or its listener, and one call frees it. The
//! follow, its recovery loop and every word are the plane's; this lays
//! them out as the header's values and decides nothing.
#![allow(unsafe_code)]

use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use abi::ffi::{Str, status};
use abi::operate::remote::Remote as RemoteHandle;

use crate::ffi::rule::refuse;
use crate::ffi::text::scope_text;
use crate::plane::{Outcome, Remote};

/// A remote, and a publication read whole but not yet handed over whole.
struct Held {
    remote: Remote,
    pending: Mutex<Option<(u64, String)>>,
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
    // SAFETY: per the contract above.
    let Some(held) = (unsafe { held(remote) }) else {
        return status::INVALID;
    };
    let mut pending = held.pending.lock().unwrap_or_else(PoisonError::into_inner);
    let (revision, text) = match pending.take() {
        Some(kept) => kept,
        None => match held.remote.publication() {
            Ok(read) => read,
            Err(said) => {
                // SAFETY: `out` and `out_len` per the contract.
                unsafe { refuse(&said, out, cap, out_len) };
                return status::UNAVAILABLE;
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

/// Wait until a follower has been told more than `seen` times, or for
/// `timeout_ms`: how many times, the revision, whether the node is
/// reached and, where it is not, why.
///
/// # Safety
/// `remote` is a live handle; every `out_` is writable; `reason` has room
/// for `cap` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_remote_wait_v1(
    remote: *const RemoteHandle,
    seen: u64,
    timeout_ms: u32,
    out_told: *mut u64,
    out_revision: *mut u64,
    out_reachable: *mut u8,
    reason: *mut u8,
    cap: usize,
    reason_len: *mut usize,
) -> i32 {
    // SAFETY: per the contract above.
    let Some(held) = (unsafe { held(remote) }) else {
        return status::INVALID;
    };
    let state = held
        .remote
        .wait(seen, Duration::from_millis(u64::from(timeout_ms)));
    // SAFETY: per the contract above.
    unsafe {
        *out_told = state.told;
        *out_revision = state.revision;
        *out_reachable = u8::from(state.reachable);
        refuse(&state.reason, reason, cap, reason_len);
    }
    status::OK
}

/// `act` on the `noun` called `target` of the node at `node`, as the
/// identity the certificate proves. `XMIP_OK` taken; `XMIP_E_AUTH` refused
/// by role; `XMIP_E_NOT_FOUND` refused by the node; `XMIP_E_INVALID` no
/// act the noun takes; `XMIP_E_IO` Xmip Storage did not answer;
/// `XMIP_E_UNAVAILABLE` the node did not. The sentence in `said`.
///
/// # Safety
/// `remote` is a live handle; the strings point at their stated lengths;
/// `said` has room for `cap` bytes and `said_len` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_remote_act_v1(
    remote: *const RemoteHandle,
    node: Str,
    noun: Str,
    target: Str,
    act: Str,
    said: *mut u8,
    cap: usize,
    said_len: *mut usize,
) -> i32 {
    // SAFETY: per the contract above.
    let Some(held) = (unsafe { held(remote) }) else {
        return status::INVALID;
    };
    // SAFETY: per the contract above.
    let Some([node, noun, target, act]) = (unsafe { texts([node, noun, target, act]) }) else {
        return status::MALFORMED;
    };
    let (code, sentence) = match held.remote.act(node, noun, target, act) {
        Ok((outcome, sentence)) => (status_of(outcome), sentence),
        Err(why) => (status::UNAVAILABLE, why),
    };
    // SAFETY: per the contract above.
    unsafe { refuse(&sentence, said, cap, said_len) };
    code
}

/// The status an outcome of the node's crosses as.
const fn status_of(outcome: Outcome) -> i32 {
    match outcome {
        Outcome::Taken => status::OK,
        Outcome::Denied => status::AUTH,
        Outcome::Refused => status::NOT_FOUND,
        Outcome::Invalid => status::INVALID,
        Outcome::Failed => status::IO,
    }
}

/// Set the secret `name` of `kind` to `value` through the node at `node`
/// (section 24; ADR-0019, amendment 2026-10-29), as the identity the
/// handle's connection proves; the node admits it by role and audits it
/// with the name, never the value. The sentence in `said`.
///
/// # Safety
/// `remote` is a live handle; the strings point at their stated lengths;
/// `said` has room for `cap` bytes and `said_len` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_secret_v1(
    remote: *const RemoteHandle,
    node: Str,
    name: Str,
    kind: Str,
    value: Str,
    said: *mut u8,
    cap: usize,
    said_len: *mut usize,
) -> i32 {
    // SAFETY: per the contract above.
    let Some(held) = (unsafe { held(remote) }) else {
        return status::INVALID;
    };
    // SAFETY: per the contract above.
    let Some([node, name, kind, value]) = (unsafe { texts([node, name, kind, value]) }) else {
        return status::MALFORMED;
    };
    let (code, sentence) = match held.remote.set_secret(node, (name, kind, value)) {
        Ok((outcome, sentence)) => (status_of(outcome), sentence),
        Err(why) => (status::UNAVAILABLE, why),
    };
    // SAFETY: per the contract above.
    unsafe { refuse(&sentence, said, cap, said_len) };
    code
}

/// The secrets the node at `node` keeps, JSON, never a value (section 24):
/// written into `out`, its true length in `out_len` whether or not it fit.
///
/// # Safety
/// `remote` is a live handle; `node` points at its stated length; `out`
/// has room for `cap` bytes and `out_len` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_secrets_v1(
    remote: *const RemoteHandle,
    node: Str,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: per the contract above.
    let Some(held) = (unsafe { held(remote) }) else {
        return status::INVALID;
    };
    // SAFETY: per the contract above.
    let Some(node) = (unsafe { scope_text(node) }) else {
        return status::MALFORMED;
    };
    let (code, text) = match held.remote.secrets(node) {
        Ok(listed) => {
            let text = listed.to_string();
            let code = if text.len() > cap {
                status::TRUNCATED
            } else {
                status::OK
            };
            (code, text)
        }
        Err(why) if why.starts_with("REFUSED") => (status::NOT_FOUND, why),
        Err(why) if why.starts_with("FAILED") => (status::IO, why),
        Err(why) => (status::UNAVAILABLE, why),
    };
    // SAFETY: per the contract above.
    unsafe { refuse(&text, out, cap, out_len) };
    code
}

/// End a remote's follow and wake every wait on it, from any thread, while
/// a call may still be in flight on another: what a binding asks before it
/// frees the handle.
///
/// # Safety
/// `remote` is null or a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_remote_end_v1(remote: *const RemoteHandle) {
    // SAFETY: per the contract above.
    if let Some(held) = unsafe { held(remote) } {
        held.remote.end();
    }
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
        drop(unsafe { Box::from_raw(remote.cast::<Held>()) });
    }
}
