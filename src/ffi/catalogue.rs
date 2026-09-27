//! `xmip_operate.h` section 12: the technologies this runtime carries and the
//! settings each declares (ADR-0064, amendment 2026-09-26). The export only —
//! what it answers is `crate::catalogue`'s, and each declaration is its
//! technology's own.
//!
//! In `ffi/`, the one folder of the runtime that may hold unsafe code
//! (ADR-0050, refined 2026-09-25): it reads the name a surface handed over
//! and writes its answer where it was told.
#![allow(unsafe_code)]

use abi::ffi::{Str, status};

use crate::catalogue;
use crate::ffi::operate::scope_text;
use crate::ffi::rule::refuse;

/// `xmip_technology_catalogue_v1`: [`catalogue::catalogue`].
///
/// # Safety
/// As the header states: `technology` readable for its length, `out` room
/// for `cap` bytes, `out_len` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_technology_catalogue_v1(
    technology: Str,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: the caller upholds the header's contract on `technology`: its
    // bytes are the caller's, alive for the call, and not freed here.
    let Some(technology) = (unsafe { scope_text(technology) }) else {
        return status::MALFORMED;
    };

    let (code, text) = match catalogue::catalogue(technology) {
        Ok(answer) => (status::OK, answer),
        Err(refusal) => (status::INVALID, refusal),
    };

    // SAFETY: `out` has room for `cap` bytes and `out_len` is writable, per
    // the contract; the text shape a refusal takes is the answer's too.
    unsafe { refuse(&text, out, cap, out_len) };
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_export_has_the_shape_the_binding_declares() {
        // A signature that drifted from xmip-core-abi's fails to compile here,
        // and the language server calls through that same declaration.
        let _: abi::operate::catalogue::CatalogueFn = xmip_technology_catalogue_v1;
    }

    #[test]
    fn the_catalogue_is_written_whole_and_an_unknown_name_is_refused() {
        let mut needed = 0usize;
        let empty = Str {
            ptr: std::ptr::null(),
            len: 0,
        };
        // SAFETY: a null buffer of capacity 0 asks for the length only.
        let code = unsafe {
            xmip_technology_catalogue_v1(empty, std::ptr::null_mut(), 0, &raw mut needed)
        };
        assert_eq!(code, status::OK);

        let mut buffer = vec![0u8; needed];
        // SAFETY: `buffer` has room for `needed` bytes.
        let code = unsafe {
            xmip_technology_catalogue_v1(empty, buffer.as_mut_ptr(), buffer.len(), &raw mut needed)
        };
        assert_eq!(code, status::OK);
        let said = String::from_utf8(buffer).expect("UTF-8");
        assert!(said.starts_with("{\"technologies\":["), "{said}");

        let name = "xmip-core-transport-nowhere";
        let named = Str {
            ptr: name.as_ptr(),
            len: name.len(),
        };
        let mut refusal = vec![0u8; 256];
        // SAFETY: `refusal` has room for 256 bytes.
        let code = unsafe {
            xmip_technology_catalogue_v1(
                named,
                refusal.as_mut_ptr(),
                refusal.len(),
                &raw mut needed,
            )
        };
        assert_eq!(code, status::INVALID);
        assert!(String::from_utf8_lossy(&refusal[..needed]).contains(name));
    }
}
