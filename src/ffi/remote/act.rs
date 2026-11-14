//! `xmip_operate.h` sections 17 and 24: an act asked of the node a remote
//! handle reaches — on one of its nouns, or on its secrets — as the identity
//! the handle's connection proves, or as a caller this process holds, the
//! node vouching for it. The node admits each by role; this lays its
//! outcome out as the header's status and decides nothing (`super`).
#![allow(unsafe_code)]

use abi::ffi::{Str, status};
use abi::operate::remote::Remote as RemoteHandle;

use super::{held, texts};
use crate::ffi::rule::refuse;
use crate::ffi::text::scope_text;
use crate::plane::Outcome;

/// `act` on the `noun` called `target` of the node at `node`, as the
/// identity the certificate proves — or, for `caller` a handle this
/// process holds a caller by (section 18), as that caller, the node
/// vouching for it; 0 for this side itself. `XMIP_OK` taken; `XMIP_E_AUTH`
/// refused by role, or no one; `XMIP_E_NOT_FOUND` refused by the node;
/// `XMIP_E_INVALID` no act the noun takes; `XMIP_E_IO` Xmip Storage did not
/// answer; `XMIP_E_AGAIN` asked: written to Xmip Storage and not taken yet,
/// its node taking it as soon as it runs — not a failure; `XMIP_E_UNAVAILABLE`
/// the node did not answer. The sentence in `said`.
///
/// # Safety
/// `remote` is a live handle; the strings point at their stated lengths;
/// `said` has room for `cap` bytes and `said_len` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_remote_act_v1(
    remote: *const RemoteHandle,
    caller: u64,
    node: Str,
    noun: Str,
    target: Str,
    act: Str,
    said: *mut u8,
    cap: usize,
    said_len: *mut usize,
) -> i32 {
    // SAFETY: the caller's contract is this export's, passed on whole.
    abi::guarded(status::PANIC, || unsafe {
        remote_act(remote, caller, node, noun, target, act, said, cap, said_len)
    })
}

/// [`xmip_remote_act_v1`] within its guard.
#[expect(clippy::too_many_arguments, reason = "the export's own parameters")]
unsafe fn remote_act(
    remote: *const RemoteHandle,
    caller: u64,
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
    let (code, sentence) = match held.remote.act(caller, node, (noun, target, act)) {
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
        Outcome::Asked => status::AGAIN,
    }
}

/// Set the secret `name` of `kind` to `value` through the node at `node`
/// (section 24; ADR-0019, amendment 2026-10-29), as the identity the
/// handle's connection proves — or, for `caller` a handle this process
/// holds a caller by (section 18), as that caller, the node vouching for
/// it; 0 for this side itself; the node admits it by role and audits it
/// with the name, never the value. The sentence in `said`.
///
/// # Safety
/// `remote` is a live handle; the strings point at their stated lengths;
/// `said` has room for `cap` bytes and `said_len` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_secret_v1(
    remote: *const RemoteHandle,
    caller: u64,
    node: Str,
    name: Str,
    kind: Str,
    value: Str,
    said: *mut u8,
    cap: usize,
    said_len: *mut usize,
) -> i32 {
    // SAFETY: the caller's contract is this export's, passed on whole.
    abi::guarded(status::PANIC, || unsafe {
        secret_set(remote, caller, node, name, kind, value, said, cap, said_len)
    })
}

/// [`xmip_secret_v1`] within its guard.
#[expect(clippy::too_many_arguments, reason = "the export's own parameters")]
unsafe fn secret_set(
    remote: *const RemoteHandle,
    caller: u64,
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
    let (code, sentence) = match held.remote.set_secret(caller, node, (name, kind, value)) {
        Ok((outcome, sentence)) => (status_of(outcome), sentence),
        Err(why) => (status::UNAVAILABLE, why),
    };
    // SAFETY: per the contract above.
    unsafe { refuse(&sentence, said, cap, said_len) };
    code
}

/// The secrets the node at `node` keeps, JSON, never a value (section 24),
/// asked as `xmip_secret_v1` asks, `caller` alike:
/// written into `out`, its true length in `out_len` whether or not it fit.
///
/// # Safety
/// `remote` is a live handle; `node` points at its stated length; `out`
/// has room for `cap` bytes and `out_len` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_secrets_v1(
    remote: *const RemoteHandle,
    caller: u64,
    node: Str,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: the caller's contract is this export's, passed on whole.
    abi::guarded(status::PANIC, || unsafe {
        secrets_listed(remote, caller, node, out, cap, out_len)
    })
}

/// [`xmip_secrets_v1`] within its guard.
unsafe fn secrets_listed(
    remote: *const RemoteHandle,
    caller: u64,
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
    let (code, text) = match held.remote.secrets(caller, node) {
        Ok(listed) => {
            let text = listed.to_string();
            let code = if text.len() > cap {
                status::TRUNCATED
            } else {
                status::OK
            };
            (code, text)
        }
        // Refused by role, `REFUSED.`, or by the node, `REFUSED:`.
        Err(why) if why.starts_with("REFUSED.") => (status::AUTH, why),
        Err(why) if why.starts_with("REFUSED") => (status::NOT_FOUND, why),
        Err(why) if why.starts_with("FAILED") => (status::IO, why),
        Err(why) => (status::UNAVAILABLE, why),
    };
    // SAFETY: per the contract above.
    unsafe { refuse(&text, out, cap, out_len) };
    code
}
