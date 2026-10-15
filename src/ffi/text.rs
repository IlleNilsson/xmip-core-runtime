//! Text as it crosses the boundary, both ways: a `&str` lent to a surface
//! as the header's `xmip_str`, and a surface's `xmip_str` read as `&str`.
//! Every export of `xmip_operate.h` reads and lends text through these two,
//! a node's and a remote surface's alike.
#![allow(unsafe_code)]

use abi::ffi::Str;

/// `text` lent as the header's string: valid while `text` is.
pub(crate) fn borrow(text: &str) -> Str {
    Str {
        ptr: text.as_ptr(),
        len: text.len(),
    }
}

/// The scope a surface passed, as `&str`, or `None` if it is not UTF-8 —
/// which the header says to answer with `XMIP_E_MALFORMED`.
///
/// # Safety
/// `scope` must point at `scope.len` readable bytes, as the header requires.
pub(crate) unsafe fn scope_text<'a>(scope: Str) -> Option<&'a str> {
    if scope.ptr.is_null() {
        return Some("");
    }

    // SAFETY: the caller upholds the header's contract on `scope`.
    let bytes = unsafe { core::slice::from_raw_parts(scope.ptr, scope.len) };

    core::str::from_utf8(bytes).ok()
}

/// The bytes a surface lent as the header's `xmip_slice`; empty for null.
///
/// # Safety
/// `bytes` must point at `bytes.len` readable bytes, as the header requires.
pub(crate) unsafe fn slice_bytes<'a>(bytes: abi::ffi::Slice) -> &'a [u8] {
    if bytes.ptr.is_null() {
        return &[];
    }

    // SAFETY: the caller upholds the header's contract on `bytes`.
    unsafe { core::slice::from_raw_parts(bytes.ptr, bytes.len) }
}
