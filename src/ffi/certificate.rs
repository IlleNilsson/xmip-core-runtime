//! `xmip_operate.h` section 19: a person's certificate (ADR-0034,
//! amendment 2026-10-15). An operator's request made — a fresh key and the
//! request naming the person, `provision::operator::request`, which the
//! phone's build carries too — and, on a node's build, one signed by the
//! authority `[provision.operator]` names (`crate::operator_certificate`).
//! Forwarders only: the rules are the capability's.
#![allow(unsafe_code)]

use abi::ffi::{Str, status};
use serde_json::json;

use crate::ffi::rule::refuse;
use crate::ffi::text::scope_text;

/// A fresh P-256 key and an operator's request for `person`, as one JSON
/// document `{"key","request"}`, each PEM; `XMIP_E_INVALID` with the
/// refusal where `person` is not a person's name.
///
/// # Safety
/// `person` points at its stated length of readable bytes; `out` has room
/// for `cap` bytes and `out_len` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_operator_request_v1(
    person: Str,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: the caller upholds the header's contract on `person`.
    let Some(person) = (unsafe { scope_text(person) }) else {
        return status::MALFORMED;
    };
    let (code, text) = match provision::operator::request(person) {
        Ok(made) => (
            status::OK,
            zeroize::Zeroizing::new(
                json!({ "key": made.key.as_str(), "request": made.request }).to_string(),
            ),
        ),
        Err(refused) => (status::INVALID, zeroize::Zeroizing::new(refused.message)),
    };
    // SAFETY: `out` has room for `cap` bytes and `out_len` is writable.
    unsafe { refuse(text.as_str(), out, cap, out_len) };
    code
}

/// The chain, PEM, for the operator's request `request`, PEM, signed by the
/// authority the node configuration at `configuration` names in
/// `[provision.operator]`; `XMIP_E_INVALID` with the refusal.
///
/// # Safety
/// Both strings point at their stated lengths of readable bytes; `out` has
/// room for `cap` bytes and `out_len` is writable.
#[cfg(feature = "node")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_operator_sign_v1(
    configuration: Str,
    request: Str,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: the caller upholds the header's contract on both strings.
    let (Some(configuration), Some(request)) = (unsafe { scope_text(configuration) }, unsafe {
        scope_text(request)
    }) else {
        return status::MALFORMED;
    };
    let path = std::path::Path::new(configuration);
    let (code, text) = match crate::operator_certificate::sign(path, request) {
        Ok(chain) => (status::OK, chain),
        Err(refused) => (status::INVALID, refused),
    };
    // SAFETY: `out` has room for `cap` bytes and `out_len` is writable.
    unsafe { refuse(&text, out, cap, out_len) };
    code
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::text::borrow;

    fn answer(call: impl Fn(*mut u8, usize, *mut usize) -> i32) -> (i32, String) {
        let mut room = vec![0u8; 8192];
        let mut length = 0usize;
        let code = call(room.as_mut_ptr(), room.len(), &raw mut length);
        (code, String::from_utf8_lossy(&room[..length]).to_string())
    }

    #[test]
    fn a_request_is_made_for_a_person_and_a_distinguished_name_is_refused() {
        // SAFETY: every pointer is to live, writable storage of its size.
        let (code, text) = answer(|out, cap, len| unsafe {
            xmip_operator_request_v1(borrow("alice@example.org"), out, cap, len)
        });
        assert_eq!(code, status::OK, "{text}");
        let made: serde_json::Value = serde_json::from_str(&text).expect("json");
        assert!(made["key"].as_str().expect("key").contains("PRIVATE KEY"));
        assert!(
            made["request"]
                .as_str()
                .expect("request")
                .contains("CERTIFICATE REQUEST")
        );

        // SAFETY: as above.
        let (code, text) = answer(|out, cap, len| unsafe {
            xmip_operator_request_v1(borrow("CN=alice"), out, cap, len)
        });
        assert_eq!(code, status::INVALID);
        assert!(text.contains("person"), "{text}");
    }

    #[cfg(feature = "node")]
    #[test]
    fn a_sign_against_a_configuration_without_an_authority_is_refused_in_words() {
        // SAFETY: as above.
        let (code, text) = answer(|out, cap, len| unsafe {
            xmip_operator_sign_v1(borrow("no-such-node.toml"), borrow(""), out, cap, len)
        });
        assert_eq!(code, status::INVALID);
        assert!(text.contains("no-such-node.toml"), "{text}");
    }
}
