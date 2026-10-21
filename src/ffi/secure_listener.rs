//! `xmip_operate.h` section 21: a web host's HTTPS in Xmip's own TLS
//! (ADR-0009, amendment 2026-10-21). A web host hands its TLS to the
//! runtime and keeps HTTP: a listener presenting the host's certificate and
//! asking each browser for one (`crate::secure_listener`), each connection read
//! and written from two threads at once; and the host's certificate issued
//! under an authority kept in a folder (`provision::host::issue_into`).
//! Forwarders only: the rules are the TLS library's and the capability's.
#![allow(unsafe_code)]

use abi::ffi::{Slice, Str, status};
use serde_json::json;

use crate::ffi::remote::texts;
use crate::ffi::rule::{hand, refuse};
use crate::ffi::text::slice_bytes;
use crate::secure_listener::{Accepted, Protection, SecureListener, SecureSession};

/// The authority kept in the folder `authority` — made there, called
/// `name`, where none is kept — and a fresh key and certificate for `host`
/// under it, written into `folder` as private files,
/// `provision::host::issue_into`. The answer is JSON,
/// `{"certificate","key","anchor"}`, the three files' paths;
/// `XMIP_E_INVALID` with the refusal.
///
/// # Safety
/// The strings point at their stated lengths of readable bytes; `out` has
/// room for `cap` bytes and `out_len` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_host_issue_v1(
    authority: Str,
    name: Str,
    host: Str,
    folder: Str,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: the caller upholds the header's contract on every string.
    let Some([authority, name, host, folder]) = (unsafe { texts([authority, name, host, folder]) })
    else {
        return status::MALFORMED;
    };
    let issued = provision::host::issue_into(
        std::path::Path::new(authority),
        name,
        host,
        std::path::Path::new(folder),
        provision::now(),
    );
    let (code, text) = match issued {
        Ok(written) => (
            status::OK,
            json!({
                "certificate": written.certificate.display().to_string(),
                "key": written.key.display().to_string(),
                "anchor": written.anchor.display().to_string(),
            })
            .to_string(),
        ),
        Err(refused) => (status::INVALID, refused.message),
    };
    // SAFETY: `out` has room for `cap` bytes and `out_len` is writable.
    unsafe { refuse(&text, out, cap, out_len) };
    code
}

/// A listener on `listen`, `host:port`, protected by `protection`
/// (`XMIP_PROTECTION_TLS`, the one built): presenting `certificate` with
/// `key` and verifying a client's certificate against `anchors`, each PEM;
/// a client that presents none is let through. `XMIP_E_UNSUPPORTED` for a
/// protection not built, `XMIP_E_IO` with why in `report`.
///
/// # Safety
/// The strings point at their stated lengths; `out` is writable; `report`
/// has room for `cap` bytes and `out_len` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_listener_open_v1(
    protection: i32,
    listen: Str,
    certificate: Str,
    key: Str,
    anchors: Str,
    out: *mut *mut SecureListener,
    report: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: the caller upholds the header's contract on every string.
    let Some([listen, certificate, key, anchors]) =
        (unsafe { texts([listen, certificate, key, anchors]) })
    else {
        return status::MALFORMED;
    };
    let Some(protection) = Protection::of(protection) else {
        // SAFETY: per the contract above.
        unsafe {
            *out = core::ptr::null_mut();
            refuse(
                &format!("no protection {protection} is built; TLS is 1"),
                report,
                cap,
                out_len,
            );
        }
        return status::UNSUPPORTED;
    };
    match SecureListener::listen(protection, listen, certificate, key, anchors) {
        Ok(listener) => {
            // SAFETY: `out` and `out_len` are writable per the contract.
            unsafe {
                *out = Box::into_raw(Box::new(listener));
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
            status::IO
        }
    }
}

/// Where `listener` listens, `host:port`.
///
/// # Safety
/// `listener` is null or a live handle; `out` has room for `cap` bytes and
/// `out_len` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_listener_address_v1(
    listener: *const SecureListener,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: `listener` is null or a live handle per the contract.
    let Some(listener) = (unsafe { listener.as_ref() }) else {
        return status::INVALID;
    };
    // SAFETY: `out` has room for `cap` bytes and `out_len` is writable.
    unsafe { refuse(&listener.address().to_string(), out, cap, out_len) };
    status::OK
}

/// The next connection whose handshake finished, as a session in `out`,
/// waiting until there is one: `XMIP_E_AUTH` with why in `report` for a
/// client whose certificate the anchors refused, `XMIP_E_IO` for one that
/// did not finish for any other reason — neither ends the listener —
/// and `XMIP_E_CANCELLED` once it is stopped.
///
/// # Safety
/// `listener` is null or a live handle; `out` is writable; `report` has
/// room for `cap` bytes and `report_len` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_listener_accept_v1(
    listener: *const SecureListener,
    out: *mut *mut SecureSession,
    report: *mut u8,
    cap: usize,
    report_len: *mut usize,
) -> i32 {
    // SAFETY: `listener` is null or a live handle per the contract.
    let Some(listener) = (unsafe { listener.as_ref() }) else {
        return status::INVALID;
    };
    // bounded: a host accepts as long as it serves; xmip_listener_stop_v1 wakes it
    let (code, session, said) = match listener.accept() {
        Accepted::Session(session) => (status::OK, Box::into_raw(Box::new(session)), String::new()),
        Accepted::Refused(said) => (status::AUTH, core::ptr::null_mut(), said),
        Accepted::Failed(said) => (status::IO, core::ptr::null_mut(), said),
        Accepted::Stopped => (status::CANCELLED, core::ptr::null_mut(), String::new()),
    };
    // SAFETY: `out`, `report` and `report_len` are writable per the contract.
    unsafe {
        *out = session;
        refuse(&said, report, cap, report_len);
    }
    code
}

/// Stop `listener`: nothing accepted after, every accept waiting woken and
/// answered `XMIP_E_CANCELLED`. From any thread, while an accept may be in
/// flight on another; the handle stays until `xmip_listener_free_v1`.
///
/// # Safety
/// `listener` is null or a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_listener_stop_v1(listener: *const SecureListener) {
    // SAFETY: `listener` is null or a live handle per the contract.
    if let Some(listener) = unsafe { listener.as_ref() } {
        listener.stop();
    }
}

/// Free `listener`, stopping it where it was not, once every call on it
/// has returned. Sessions it handed over stay their holder's.
///
/// # Safety
/// `listener` is null or a handle `xmip_listener_open_v1` made, freed once,
/// with no call on it in flight.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_listener_free_v1(listener: *mut SecureListener) {
    if !listener.is_null() {
        // SAFETY: made by `Box::into_raw` in `xmip_listener_open_v1`, freed once.
        drop(unsafe { Box::from_raw(listener) });
    }
}

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
    // SAFETY: `session` is null or a live handle per the contract.
    let Some(session) = (unsafe { session.as_ref() }) else {
        return status::INVALID;
    };
    // SAFETY: `out` has room for `cap` bytes and `out_len` is writable.
    unsafe { hand(session.presented().unwrap_or_default(), out, cap, out_len) };
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
}

/// Close the session: its client told where no write holds it, the socket
/// shut both ways, a read waiting on another thread woken to its end. From
/// any thread; the handle stays until `xmip_session_free_v1`.
///
/// # Safety
/// `session` is null or a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_session_close_v1(session: *const SecureSession) {
    // SAFETY: `session` is null or a live handle per the contract.
    if let Some(session) = unsafe { session.as_ref() } {
        session.close();
    }
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
        drop(unsafe { Box::from_raw(session) });
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::sync::Arc;

    use super::*;
    use crate::ffi::text::borrow;

    fn answer(call: impl FnOnce(*mut u8, usize, *mut usize) -> i32) -> (i32, String) {
        let mut room = vec![0u8; 8192];
        let mut length = 0usize;
        let code = call(room.as_mut_ptr(), room.len(), &raw mut length);
        (
            code,
            String::from_utf8_lossy(&room[..length.min(8192)]).to_string(),
        )
    }

    #[test]
    fn a_host_certificate_under_a_kept_authority_serves_a_browser_reaching_127_0_0_1() {
        let base = std::env::temp_dir().join(format!("xmip-ffi-secure-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let authority = base.join("authority").display().to_string();
        let folder = base.display().to_string();
        // SAFETY: every pointer is to live, writable storage of its size.
        let (code, text) = answer(|out, cap, len| unsafe {
            xmip_host_issue_v1(
                borrow(&authority),
                borrow("test authority"),
                borrow("127.0.0.1"),
                borrow(&folder),
                out,
                cap,
                len,
            )
        });
        assert_eq!(code, status::OK, "{text}");
        let written: serde_json::Value = serde_json::from_str(&text).expect("json");
        let read = |name: &str| {
            std::fs::read_to_string(written[name].as_str().expect("a path")).expect("read")
        };
        let (certificate, key, anchor) = (read("certificate"), read("key"), read("anchor"));

        let mut listener = core::ptr::null_mut();
        // SAFETY: as above, `listener` writable.
        let (code, said) = answer(|report, cap, len| unsafe {
            xmip_listener_open_v1(
                Protection::TLS,
                borrow("127.0.0.1:0"),
                borrow(&certificate),
                borrow(&key),
                borrow(&anchor),
                &raw mut listener,
                report,
                cap,
                len,
            )
        });
        assert_eq!(code, status::OK, "{said}");
        // SAFETY: a live handle.
        let (_, address) =
            answer(|out, cap, len| unsafe { xmip_listener_address_v1(listener, out, cap, len) });

        // A browser presenting nothing, checking the host by its address.
        let trusting = Arc::new(tls::trusting(anchor.as_bytes()).expect("the anchor"));
        let browser = std::thread::spawn(move || {
            let tcp = std::net::TcpStream::connect(&address).expect("connected");
            let mut stream = tls::client_with("127.0.0.1", tcp, trusting).expect("tls");
            stream.write_all(b"GET").expect("asked");
            let mut back = [0u8; 2];
            stream.read_exact(&mut back).expect("answered");
            back
        });
        let mut session = core::ptr::null_mut();
        // SAFETY: a live handle, `session` writable.
        let (code, said) = answer(|report, cap, len| unsafe {
            xmip_listener_accept_v1(listener, &raw mut session, report, cap, len)
        });
        assert_eq!(code, status::OK, "{said}");
        // SAFETY: a live session.
        let (code, peer) =
            answer(|out, cap, len| unsafe { xmip_session_peer_v1(session, out, cap, len) });
        assert_eq!((code, peer.as_str()), (status::OK, ""), "it presented none");
        let mut asked = [0u8; 3];
        let mut length = 0usize;
        // SAFETY: a live session, `asked` writable.
        let code = unsafe { xmip_session_read_v1(session, asked.as_mut_ptr(), 3, &raw mut length) };
        assert_eq!((code, &asked[..length]), (status::OK, &b"GET"[..]));
        let ok = b"OK";
        let lent = Slice {
            ptr: ok.as_ptr(),
            len: ok.len(),
        };
        // SAFETY: a live session, `lent` readable.
        assert_eq!(unsafe { xmip_session_write_v1(session, lent) }, status::OK);
        assert_eq!(&browser.join().expect("the browser"), b"OK");

        // SAFETY: live handles, each freed once with nothing in flight.
        unsafe {
            xmip_session_close_v1(session);
            xmip_session_free_v1(session);
            xmip_listener_stop_v1(listener);
        }
        let mut none = core::ptr::null_mut();
        // SAFETY: a stopped, live handle.
        let (code, _) = answer(|report, cap, len| unsafe {
            xmip_listener_accept_v1(listener, &raw mut none, report, cap, len)
        });
        assert_eq!(code, status::CANCELLED);
        // SAFETY: freed once, nothing in flight.
        unsafe { xmip_listener_free_v1(listener) };
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_protection_not_built_is_refused_in_words_and_nothing_listens() {
        let mut listener = core::ptr::null_mut();
        // SAFETY: every pointer is to live, writable storage of its size.
        let (code, said) = answer(|report, cap, len| unsafe {
            xmip_listener_open_v1(
                7,
                borrow("127.0.0.1:0"),
                borrow(""),
                borrow(""),
                borrow(""),
                &raw mut listener,
                report,
                cap,
                len,
            )
        });
        assert_eq!(code, status::UNSUPPORTED);
        assert!(said.contains("no protection 7"), "{said}");
        assert!(listener.is_null());
    }
}
