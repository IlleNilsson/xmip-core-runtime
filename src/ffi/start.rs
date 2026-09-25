//! `xmip_operate.h` section 6: starting and validating a node, from a
//! surface. The exports only — what starting and validating are is
//! `crate::start`'s.
//!
//! In `ffi/`, the one folder of the runtime that may hold unsafe code
//! (ADR-0050, refined 2026-09-25): each reads text a surface handed over and
//! writes where it was told.
#![allow(unsafe_code)]

use abi::ffi::{Str, status};

use crate::ffi::operate::scope_text;
use crate::start::{start_published, validate};

/// `xmip_start_v1`: [`crate::start::start`] from a surface. Publishes whatever it found and
/// returns `XMIP_OK` when the node validated, `XMIP_E_INVALID` when it did
/// not, `XMIP_E_MALFORMED` when the path is not UTF-8. The snapshot says why
/// either way, so a surface reads the table rather than the status.
///
/// # Safety
/// `path` must point at `path.len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_start_v1(path: Str) -> i32 {
    let Some(text) = (unsafe { scope_text(path) }) else {
        return status::MALFORMED;
    };

    if start_published(text) {
        status::OK
    } else {
        status::INVALID
    }
}

/// `xmip_validate_v1`: [`crate::start::validate`] from a surface. The report is written into
/// `report` as UTF-8, one problem per line, and `out_len` is the true byte
/// length whether or not it fit — a surface that passed too small a buffer
/// asks again. `XMIP_OK` and `out_len` 0 means the configuration is good;
/// `XMIP_E_INVALID` with a report means it is not; `XMIP_E_MALFORMED` when the
/// configuration is not UTF-8.
///
/// # Safety
/// `configuration` points at its stated length of readable bytes; `report`
/// has room for `cap` bytes; `out_len` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_validate_v1(
    configuration: Str,
    report: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: the caller upholds the header's contract on `configuration`:
    // its bytes are the caller's, alive for the call, and not freed here.
    let Some(text) = (unsafe { scope_text(configuration) }) else {
        return status::MALFORMED;
    };

    let problems = validate(text);
    let joined = problems.join("\n");
    let bytes = joined.as_bytes();

    // SAFETY: `out_len` is writable per the contract.
    unsafe { *out_len = bytes.len() };

    if !bytes.is_empty() && cap > 0 {
        let n = bytes.len().min(cap);

        // SAFETY: `report` has room for `cap` >= `n` bytes.
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), report, n) };
    }

    if problems.is_empty() {
        status::OK
    } else {
        status::INVALID
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_exports_have_the_shape_the_binding_declares() {
        // A signature that drifted from xmip-core-abi's fails to compile here,
        // and the language server calls through that same declaration.
        let _: abi::operate::StartFn = xmip_start_v1;
        let _: abi::operate::ValidateFn = xmip_validate_v1;
    }
}
