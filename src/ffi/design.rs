//! `xmip_operate.h` section 10: an Xmip Application read and edited for a
//! designer (ADR-0064). The exports only — what each does is
//! `crate::design`'s, and the rules are `xmip-core-configure`'s.
//!
//! In `ffi/`, the one folder of the runtime that may hold unsafe code
//! (ADR-0050, refined 2026-09-25): each reads the text a surface handed over
//! and writes its answer where it was told.
#![allow(unsafe_code)]

use abi::ffi::{Str, status};

use crate::design;
use crate::ffi::operate::scope_text;
use crate::ffi::rule::refuse;

/// Read both texts, answer, and write the answer or the refusal in the
/// header's text shape: its true length in `out_len` whether or not it fit.
///
/// # Safety
/// `input` and `argument` point at their stated lengths of readable bytes;
/// `out` has room for `cap` bytes; `out_len` is writable.
unsafe fn answer(
    input: Str,
    argument: Str,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
    answering: impl FnOnce(&str, &str) -> Result<String, String>,
) -> i32 {
    // SAFETY: the caller upholds the header's contract on both texts: their
    // bytes are the caller's, alive for the call, and not freed here.
    let (Some(input), Some(argument)) = (unsafe { scope_text(input) }, unsafe {
        scope_text(argument)
    }) else {
        return status::MALFORMED;
    };

    let (code, text) = match answering(input, argument) {
        Ok(answer) => (status::OK, answer),
        Err(refusal) => (status::INVALID, refusal),
    };

    // SAFETY: `out` has room for `cap` bytes and `out_len` is writable, per
    // the contract; the text shape a refusal takes is the answer's too.
    unsafe { refuse(&text, out, cap, out_len) };
    code
}

/// `xmip_application_routes_v1`: [`design::routes`].
///
/// # Safety
/// As the header states: both texts readable, `out` room for `cap` bytes,
/// `out_len` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_application_routes_v1(
    input: Str,
    argument: Str,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: the caller upholds the header's contract, passed on whole.
    unsafe {
        answer(input, argument, out, cap, out_len, |text, _| {
            design::routes(text)
        })
    }
}

/// `xmip_filter_structure_v1`: [`design::filter_structure`].
///
/// # Safety
/// As [`xmip_application_routes_v1`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_filter_structure_v1(
    input: Str,
    argument: Str,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: the caller upholds the header's contract, passed on whole.
    unsafe {
        answer(input, argument, out, cap, out_len, |text, _| {
            design::filter_structure(text)
        })
    }
}

/// `xmip_filter_text_v1`: [`design::filter_text`].
///
/// # Safety
/// As [`xmip_application_routes_v1`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_filter_text_v1(
    input: Str,
    argument: Str,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: the caller upholds the header's contract, passed on whole.
    unsafe {
        answer(input, argument, out, cap, out_len, |text, _| {
            design::filter_text(text)
        })
    }
}

/// `xmip_application_edit_v1`: [`design::edit`].
///
/// # Safety
/// As [`xmip_application_routes_v1`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_application_edit_v1(
    input: Str,
    argument: Str,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: the caller upholds the header's contract, passed on whole.
    unsafe { answer(input, argument, out, cap, out_len, design::edit) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_export_has_the_shape_the_binding_declares() {
        // A signature that drifted from xmip-core-abi's fails to compile here,
        // and the language server calls through that same declaration.
        let _: abi::operate::design::DesignFn = xmip_application_routes_v1;
        let _: abi::operate::design::DesignFn = xmip_filter_structure_v1;
        let _: abi::operate::design::DesignFn = xmip_filter_text_v1;
        let _: abi::operate::design::DesignFn = xmip_application_edit_v1;
    }

    fn text(value: &str) -> Str {
        Str {
            ptr: value.as_ptr(),
            len: value.len(),
        }
    }

    #[test]
    fn an_answer_is_written_whole_and_a_refusal_says_why() {
        let filter = "exists Urgent";
        let mut needed = 0usize;

        // SAFETY: a null buffer of capacity 0 asks for the length only.
        let code = unsafe {
            xmip_filter_structure_v1(
                text(filter),
                text(""),
                std::ptr::null_mut(),
                0,
                &raw mut needed,
            )
        };
        assert_eq!(code, status::OK);

        let mut buffer = vec![0u8; needed];
        // SAFETY: `buffer` has room for `needed` bytes.
        let code = unsafe {
            xmip_filter_structure_v1(
                text(filter),
                text(""),
                buffer.as_mut_ptr(),
                buffer.len(),
                &raw mut needed,
            )
        };
        assert_eq!(code, status::OK);
        let said = String::from_utf8(buffer).expect("UTF-8");
        assert!(said.contains("\"operator\":\"exists\""), "{said}");

        let mut refusal = vec![0u8; 256];
        // SAFETY: `refusal` has room for 256 bytes.
        let code = unsafe {
            xmip_filter_structure_v1(
                text("not a filter"),
                text(""),
                refusal.as_mut_ptr(),
                refusal.len(),
                &raw mut needed,
            )
        };
        assert_eq!(code, status::INVALID);
        assert!(needed > 0);
    }
}
