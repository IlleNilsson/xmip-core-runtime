//! `xmip_operate.h` section 21, one connection a web host's listener
//! accepted (`super`): who its client is, where both ends are, and its
//! bytes read and written from two threads at once, until it is closed and
//! freed. Forwarders only: the rules are the TLS library's and the plane's.
#![allow(unsafe_code)]

use abi::ffi::{Slice, status};

use crate::ffi::rule::{hand, refuse};
use crate::ffi::text::slice_bytes;
use crate::plane::held;
use crate::secure_listener::SecureSession;

/// The leaf certificate the session's client presented, DER; empty where
/// it presented none.
///
/// # Safety
/// `session` is null or a live handle; `out` has room for `cap` bytes and
/// `out_len` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_session_peer_v1(
    session: *const SecureSession,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    abi::guarded(status::PANIC, || {
        // SAFETY: `session` is null or a live handle per the contract.
        let Some(session) = (unsafe { session.as_ref() }) else {
            return status::INVALID;
        };
        // SAFETY: `out` has room for `cap` bytes and `out_len` is writable.
        unsafe { hand(session.presented().unwrap_or_default(), out, cap, out_len) };
        status::OK
    })
}

/// Who the session's client is, proven: the certificate the handshake
/// verified against the anchors run through the authentication gate
/// (`plane::caller::certificate`), held behind a handle of its own in
/// `out_caller` (`plane::held`) — the one caller a host acts as — until its
/// holder releases it, the certificate ends or the listener stops; 0 for
/// no one, where the client presented none or the gate refused it. The
/// identity in `out`, a distinguished name, for display alone (ADR-0009,
/// amendment 2026-11-01).
///
/// # Safety
/// `session` is null or a live handle; `out_caller` is writable; `out` has
/// room for `cap` bytes and `out_len` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_caller_proven_v1(
    session: *const SecureSession,
    out_caller: *mut u64,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: the caller's contract is this export's, passed on whole.
    abi::guarded(status::PANIC, || unsafe {
        caller_proven(session, out_caller, out, cap, out_len)
    })
}

/// [`xmip_caller_proven_v1`] within its guard.
unsafe fn caller_proven(
    session: *const SecureSession,
    out_caller: *mut u64,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: `session` is null or a live handle per the contract.
    let Some(session) = (unsafe { session.as_ref() }) else {
        return status::INVALID;
    };
    // The session holds the caller its handshake proved (`secured`); each
    // call hands its caller a handle of its own.
    let handle = held::again(session.caller());
    let name = held::proven(handle)
        .map(|caller| caller.value)
        .unwrap_or_default();
    // SAFETY: `out_caller` is writable; `out` has room for `cap` bytes and
    // `out_len` is writable.
    unsafe {
        *out_caller = handle;
        refuse(&name, out, cap, out_len);
    }
    status::OK
}

/// Where the session was accepted and where its client is, `host:port`
/// each, one space between.
///
/// # Safety
/// `session` is null or a live handle; `out` has room for `cap` bytes and
/// `out_len` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_session_ends_v1(
    session: *const SecureSession,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: the caller's contract is this export's, passed on whole.
    abi::guarded(status::PANIC, || unsafe {
        session_ends(session, out, cap, out_len)
    })
}

/// [`xmip_session_ends_v1`] within its guard.
unsafe fn session_ends(
    session: *const SecureSession,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: `session` is null or a live handle per the contract.
    let Some(session) = (unsafe { session.as_ref() }) else {
        return status::INVALID;
    };
    let (local, remote) = session.ends();
    // SAFETY: `out` has room for `cap` bytes and `out_len` is writable.
    unsafe { refuse(&format!("{local} {remote}"), out, cap, out_len) };
    status::OK
}

/// What the client sent next, into `out`, at most `cap` bytes, their count
/// in `out_len`, waiting for it; 0 once the connection has ended.
/// `XMIP_E_IO` where a record could not be read.
///
/// # Safety
/// `session` is null or a live handle; `out` has room for `cap` bytes and
/// `out_len` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_session_read_v1(
    session: *const SecureSession,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: the caller's contract is this export's, passed on whole.
    abi::guarded(status::PANIC, || unsafe {
        session_read(session, out, cap, out_len)
    })
}

/// [`xmip_session_read_v1`] within its guard.
unsafe fn session_read(
    session: *const SecureSession,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: `session` is null or a live handle per the contract.
    let Some(session) = (unsafe { session.as_ref() }) else {
        return status::INVALID;
    };
    let buffer = if cap == 0 || out.is_null() {
        &mut [][..]
    } else {
        // SAFETY: `out` has room for `cap` bytes per the contract.
        unsafe { core::slice::from_raw_parts_mut(out, cap) }
    };
    let (code, read) = match session.read(buffer) {
        Ok(read) => (status::OK, read),
        Err(_) => (status::IO, 0),
    };
    // SAFETY: `out_len` is writable per the contract.
    unsafe { *out_len = read };
    code
}

/// `bytes` written whole and sent. `XMIP_E_IO` where the connection has
/// ended or the socket refused them.
///
/// # Safety
/// `session` is null or a live handle; `bytes` points at its stated length
/// of readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_session_write_v1(session: *const SecureSession, bytes: Slice) -> i32 {
    abi::guarded(status::PANIC, || {
        // SAFETY: `session` is null or a live handle per the contract.
        let Some(session) = (unsafe { session.as_ref() }) else {
            return status::INVALID;
        };
        // SAFETY: and `bytes` is readable.
        let bytes = unsafe { slice_bytes(bytes) };
        match session.write(bytes) {
            Ok(()) => status::OK,
            Err(_) => status::IO,
        }
    })
}

/// Close the session: its client told where no write holds it, the socket
/// shut both ways, a read waiting on another thread woken to its end. From
/// any thread; the handle stays until `xmip_session_free_v1`.
///
/// # Safety
/// `session` is null or a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_session_close_v1(session: *const SecureSession) {
    abi::guarded((), || {
        // SAFETY: `session` is null or a live handle per the contract.
        if let Some(session) = unsafe { session.as_ref() } {
            session.close();
        }
    });
}

/// Free `session` once every call on it has returned.
///
/// # Safety
/// `session` is null or a handle `xmip_listener_accept_v1` made, freed once,
/// with no call on it in flight.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_session_free_v1(session: *mut SecureSession) {
    if !session.is_null() {
        // SAFETY: made by `Box::into_raw` in `xmip_listener_accept_v1`, freed once.
        let session = unsafe { Box::from_raw(session) };
        abi::guarded((), || drop(session));
    }
}
