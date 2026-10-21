//! `xmip_operate.h` section 17, the node's side, for a program that hosts a
//! node through the C ABI: what it posts as its publication, and the acts
//! on the nodes of its process, served on an operate listener of its own
//! (`crate::plane::Listener` over a `crate::plane::Board`) — on the
//! network inside mutual TLS, or on this machine's local endpoint.
//!
//! A handle owns its listener and its board, and one call stops and frees
//! them.
#![allow(unsafe_code)]

use std::sync::Arc;

use abi::ffi::{Str, status};
use abi::operate::remote::Served as ServedHandle;
use xaudit::program_audit::ProgramAudit;

use crate::ffi::remote::{identity, texts};
use crate::ffi::rule::refuse;
use crate::ffi::text::scope_text;
use crate::plane::{Board, Listener, Published, Role};

/// A listener and the board it answers from.
struct Serving {
    listener: Listener,
    board: Arc<Board>,
}

/// Serve what is posted to the handle (`xmip_operate_post_v1`) and the
/// acts on the nodes of this process on an operate listener at `listen`, presenting
/// `certificate` with `key` and taking a surface whose certificate reaches
/// `anchors`; every proven caller holds the role `role` names, Observer for
/// an empty or unknown word. Audited as `program`.
///
/// # Safety
/// The strings point at their stated lengths; `out` is writable; `report`
/// has room for `cap` bytes and `out_len` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_operate_serve_v1(
    listen: Str,
    certificate: Str,
    key: Str,
    anchors: Str,
    role: Str,
    program: Str,
    out: *mut *mut ServedHandle,
    report: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: per the contract above.
    let (Some([listen, certificate, key, anchors]), Some(role), Some(program)) = (
        unsafe { texts([listen, certificate, key, anchors]) },
        unsafe { scope_text(role) },
        unsafe { scope_text(program) },
    ) else {
        return status::MALFORMED;
    };
    let stated = (!role.trim().is_empty()).then(|| Role::named(role));
    let audit = ProgramAudit::new(program, None);
    let board = Arc::new(Board::default());
    let published: Arc<dyn Published> = Arc::clone(&board) as Arc<dyn Published>;
    let started = identity(certificate, key, anchors).and_then(|identity| {
        let bound = std::net::TcpListener::bind(listen).map_err(|error| error.to_string())?;
        Listener::start(bound, &identity, published, stated, &audit)
    });
    // SAFETY: per the contract above.
    unsafe { handed(started, board, out, report, cap, out_len) }
}

/// Serve the same on this machine's local endpoint called `local` — a
/// named pipe on Windows, a Unix domain socket elsewhere — every caller
/// the user its process runs as, holding the role `role` names (ADR-0014,
/// amendment 2026-10-13). Audited as `program`.
///
/// # Safety
/// The strings point at their stated lengths; `out` is writable; `report`
/// has room for `cap` bytes and `out_len` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_operate_serve_local_v1(
    local: Str,
    role: Str,
    program: Str,
    out: *mut *mut ServedHandle,
    report: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: per the contract above.
    let (Some(local), Some(role), Some(program)) = (
        unsafe { scope_text(local) },
        unsafe { scope_text(role) },
        unsafe { scope_text(program) },
    ) else {
        return status::MALFORMED;
    };
    let stated = (!role.trim().is_empty()).then(|| Role::named(role));
    let audit = ProgramAudit::new(program, None);
    let board = Arc::new(Board::default());
    let published: Arc<dyn Published> = Arc::clone(&board) as Arc<dyn Published>;
    let admitting = crate::plane::local::Admitting::default();
    let started = Listener::local(local, admitting, published, stated, &audit);
    // SAFETY: per the contract above.
    unsafe { handed(started, board, out, report, cap, out_len) }
}

/// A listener started, as a handle in `out`, or why not in `report`.
///
/// # Safety
/// `out` is writable; `report` has room for `cap` bytes; `out_len` is
/// writable.
unsafe fn handed(
    started: Result<Listener, String>,
    board: Arc<Board>,
    out: *mut *mut ServedHandle,
    report: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    match started {
        Ok(listener) => {
            let serving = Box::new(Serving { listener, board });
            // SAFETY: `out` and `out_len` are writable per the contract.
            unsafe {
                *out = Box::into_raw(serving).cast::<ServedHandle>();
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

/// Where a served listener listens: `host:port`, or the local endpoint's
/// path.
///
/// # Safety
/// `served` is a live handle; `out` has room for `cap` bytes; `out_len` is
/// writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_operate_served_address_v1(
    served: *const ServedHandle,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: per the contract above.
    let Some(serving) = (unsafe { served.cast::<Serving>().as_ref() }) else {
        return status::INVALID;
    };
    // SAFETY: per the contract above.
    unsafe { refuse(&serving.listener.address(), out, cap, out_len) };
    status::OK
}

/// Post `publication`, the text a publication file holds, as what the
/// listener answers: a new revision where it differs from the last, and
/// every surface following told.
///
/// # Safety
/// `served` is a live handle; `publication` points at its stated length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_operate_post_v1(
    served: *const ServedHandle,
    publication: Str,
) -> i32 {
    // SAFETY: per the contract above.
    let Some(serving) = (unsafe { served.cast::<Serving>().as_ref() }) else {
        return status::INVALID;
    };
    // SAFETY: per the contract above.
    let Some(text) = (unsafe { scope_text(publication) }) else {
        return status::MALFORMED;
    };
    serving.board.post(text.to_string());
    status::OK
}

/// Stop a served listener and release it.
///
/// # Safety
/// `served` is null or a handle `xmip_operate_serve_v1` or
/// `xmip_operate_serve_local_v1` returned and nobody freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_operate_serve_stop_v1(served: *mut ServedHandle) {
    if !served.is_null() {
        // SAFETY: per the contract above, the box this handle was made from.
        drop(unsafe { Box::from_raw(served.cast::<Serving>()) });
    }
}

#[cfg(test)]
mod tests {
    //! Sections 17 and 18 across the C boundary, as a surface in another
    //! language calls them: an operate listener this process serves, a
    //! publication posted to it, a remote opened on it, the publication
    //! read, the follow waited on, an act refused by role, the follow ended
    //! and every handle freed — and each export's signature held to the
    //! header's.

    use std::time::{Duration, Instant};

    use abi::ffi::{Str, status};
    use abi::operate::remote::{Remote, Served};

    use super::*;
    use crate::ffi::remote::{
        xmip_remote_act_v1, xmip_remote_end_v1, xmip_remote_free_v1, xmip_remote_open_v1,
        xmip_remote_publication_v1, xmip_remote_wait_v1,
    };
    use crate::ffi::security_role::{
        xmip_act_admitted_v1, xmip_security_role_named_v1, xmip_security_role_words_v1,
    };
    use crate::fixture::Authority;

    fn text(value: &str) -> Str {
        Str {
            ptr: value.as_ptr(),
            len: value.len(),
        }
    }

    #[test]
    fn every_export_has_the_headers_signature() {
        use abi::operate::remote as header;
        let _: header::OpenFn = xmip_remote_open_v1;
        let _: header::PublicationFn = xmip_remote_publication_v1;
        let _: header::WaitFn = xmip_remote_wait_v1;
        let _: header::ActFn = xmip_remote_act_v1;
        let _: header::EndFn = xmip_remote_end_v1;
        let _: header::FreeFn = xmip_remote_free_v1;
        let _: header::ServeFn = xmip_operate_serve_v1;
        let _: header::ServeLocalFn = xmip_operate_serve_local_v1;
        let _: header::OpenLocalFn = crate::ffi::remote::xmip_remote_open_local_v1;
        let _: header::ServedAddressFn = xmip_operate_served_address_v1;
        let _: header::PostFn = xmip_operate_post_v1;
        let _: header::ServeStopFn = xmip_operate_serve_stop_v1;
        let _: header::SecurityRoleNamedFn = xmip_security_role_named_v1;
        let _: header::SecurityRoleWordsFn = xmip_security_role_words_v1;
        let _: header::ActAdmittedFn = xmip_act_admitted_v1;
    }

    #[test]
    fn a_node_served_through_the_boundary_is_read_followed_and_refuses_an_observers_act() {
        let authority = Authority::new();
        let (certificate, key, anchors) = authority.pem("node");
        let mut report = vec![0u8; 4096];
        let mut length = 0usize;
        let mut served: *mut Served = std::ptr::null_mut();
        // SAFETY: every pointer is to live storage of its stated size.
        let code = unsafe {
            xmip_operate_serve_v1(
                text("127.0.0.1:0"),
                text(&certificate),
                text(&key),
                text(&anchors),
                text(""),
                text("plane-exports-test"),
                &raw mut served,
                report.as_mut_ptr(),
                report.len(),
                &raw mut length,
            )
        };
        assert_eq!(
            code,
            status::OK,
            "{}",
            String::from_utf8_lossy(&report[..length])
        );
        // SAFETY: `served` is live.
        assert_eq!(
            unsafe { xmip_operate_post_v1(served, text("source = \"one\"\n")) },
            status::OK
        );
        let mut address = vec![0u8; 256];
        // SAFETY: as above.
        let code = unsafe {
            xmip_operate_served_address_v1(
                served,
                address.as_mut_ptr(),
                address.len(),
                &raw mut length,
            )
        };
        assert_eq!(code, status::OK);
        let address = String::from_utf8_lossy(&address[..length]).to_string();

        let (certificate, key, anchors) = authority.pem("surface");
        let mut remote: *mut Remote = std::ptr::null_mut();
        // SAFETY: as above.
        let code = unsafe {
            xmip_remote_open_v1(
                text(&address),
                text(&certificate),
                text(&key),
                text(&anchors),
                &raw mut remote,
                report.as_mut_ptr(),
                report.len(),
                &raw mut length,
            )
        };
        assert_eq!(
            code,
            status::OK,
            "{}",
            String::from_utf8_lossy(&report[..length])
        );

        // A buffer too small keeps the text whole for the next call.
        let mut revision = 0u64;
        let mut small = vec![0u8; 4];
        // SAFETY: as above.
        let code = unsafe {
            xmip_remote_publication_v1(
                remote,
                small.as_mut_ptr(),
                small.len(),
                &raw mut length,
                &raw mut revision,
            )
        };
        assert_eq!((code, length, revision), (status::TRUNCATED, 15, 1));
        let mut whole = vec![0u8; length];
        // SAFETY: as above.
        let code = unsafe {
            xmip_remote_publication_v1(
                remote,
                whole.as_mut_ptr(),
                whole.len(),
                &raw mut length,
                &raw mut revision,
            )
        };
        assert_eq!(code, status::OK);
        assert_eq!(whole, b"source = \"one\"\n");

        let (mut told, mut reachable) = (0u64, 0u8);
        // SAFETY: as above.
        let code = unsafe {
            xmip_remote_wait_v1(
                remote,
                0,
                5000,
                &raw mut told,
                &raw mut revision,
                &raw mut reachable,
                report.as_mut_ptr(),
                report.len(),
                &raw mut length,
            )
        };
        assert_eq!((code, reachable, revision), (status::OK, 1, 1));
        let posted = Instant::now();
        // SAFETY: as above.
        unsafe { xmip_operate_post_v1(served, text("source = \"two\"\n")) };
        let seen = told;
        // SAFETY: as above.
        unsafe {
            xmip_remote_wait_v1(
                remote,
                seen,
                5000,
                &raw mut told,
                &raw mut revision,
                &raw mut reachable,
                report.as_mut_ptr(),
                report.len(),
                &raw mut length,
            )
        };
        assert_eq!(revision, 2);
        assert!(posted.elapsed() < Duration::from_secs(1));

        // SAFETY: as above.
        let code = unsafe {
            xmip_remote_act_v1(
                remote,
                text(&crate::fixture::absent_node()),
                text("subscription"),
                text("orders"),
                text("pause"),
                report.as_mut_ptr(),
                report.len(),
                &raw mut length,
            )
        };
        assert_eq!(code, status::AUTH);
        assert!(String::from_utf8_lossy(&report[..length]).starts_with("REFUSED. CN=surface"));

        let ended = Instant::now();
        // SAFETY: `remote` and `served` are live, and freed once each.
        unsafe {
            xmip_remote_end_v1(remote);
            xmip_remote_free_v1(remote);
            xmip_operate_serve_stop_v1(served);
        }
        assert!(
            ended.elapsed() < Duration::from_secs(1),
            "{:?}",
            ended.elapsed()
        );
    }
}
