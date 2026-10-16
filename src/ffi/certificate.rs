//! `xmip_operate.h` section 19: a person's certificate (ADR-0034,
//! amendment 2026-10-15). An operator's request made — a fresh key and the
//! request naming the person, written into a folder as private files,
//! `provision::operator::request_into`, which the phone's build carries
//! too — the chain and anchors a surface keeps, written whole
//! (`provision::operator::keep`), every build too — its two halves around a
//! keeper's signature
//! for a key that never leaves its platform's keeper
//! (`provision::operator::information` and `assemble`, every build too) —
//! and, on a node's build, one signed by the
//! authority `[provision.operator]` names (`crate::operator_certificate`).
//! Forwarders only: the rules are the capability's.
#![allow(unsafe_code)]

use abi::ffi::{Slice, Str, status};
use serde_json::json;

use crate::ffi::rule::{hand, refuse};
use crate::ffi::text::{scope_text, slice_bytes};

/// A fresh P-256 key and an operator's request for `person`, written into
/// the folder `folder` as private files, `provision::operator::request_into`:
/// the key never crosses this boundary. The answer is one JSON document
/// `{"key","request"}`, the two files' paths; `XMIP_E_INVALID` with the
/// refusal where `person` is not a person's name or a file is there already.
///
/// # Safety
/// `person` and `folder` point at their stated lengths of readable bytes;
/// `out` has room for `cap` bytes and `out_len` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_operator_request_v1(
    person: Str,
    folder: Str,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: the caller upholds the header's contract on both strings.
    let (Some(person), Some(folder)) =
        (unsafe { scope_text(person) }, unsafe { scope_text(folder) })
    else {
        return status::MALFORMED;
    };
    let folder = std::path::Path::new(folder);
    let (code, text) = match provision::operator::request_into(person, folder) {
        Ok(written) => (
            status::OK,
            json!({
                "key": written.key.display().to_string(),
                "request": written.request.display().to_string(),
            })
            .to_string(),
        ),
        Err(refused) => (status::INVALID, refused.message),
    };
    // SAFETY: `out` has room for `cap` bytes and `out_len` is writable.
    unsafe { refuse(&text, out, cap, out_len) };
    code
}

/// The text `text` — a chain the authority signed, or the anchors a surface
/// trusts, PEM — kept whole at the file `path`, `provision::operator::keep`:
/// written beside it and synced, then, where `replace` is non-zero, renamed
/// over what was there; where it is zero, never over a file already there.
/// An empty answer where kept; `XMIP_E_INVALID` with the refusal where not.
///
/// # Safety
/// Both strings point at their stated lengths of readable bytes; `out` has
/// room for `cap` bytes and `out_len` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_operator_keep_v1(
    path: Str,
    text: Str,
    replace: u8,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: the caller upholds the header's contract on both strings.
    let (Some(path), Some(text)) = (unsafe { scope_text(path) }, unsafe { scope_text(text) })
    else {
        return status::MALFORMED;
    };
    let path = std::path::Path::new(path);
    let (code, said) = match provision::operator::keep(path, text, replace != 0) {
        Ok(()) => (status::OK, String::new()),
        Err(refused) => (status::INVALID, refused.message),
    };
    // SAFETY: `out` has room for `cap` bytes and `out_len` is writable.
    unsafe { refuse(&said, out, cap, out_len) };
    code
}

/// What an operator's request for `person` signs over the P-256 key
/// `public_key` — `SubjectPublicKeyInfo` DER or the uncompressed point, as
/// a keeper hands it — DER, `provision::operator::information`; the keeper
/// signs these bytes and `xmip_operator_assemble_v1` makes the request.
/// `XMIP_E_INVALID` with the refusal.
///
/// # Safety
/// `person` and `public_key` point at their stated lengths of readable
/// bytes; `out` has room for `cap` bytes and `out_len` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_operator_information_v1(
    person: Str,
    public_key: Slice,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: the caller upholds the header's contract on `person`.
    let Some(person) = (unsafe { scope_text(person) }) else {
        return status::MALFORMED;
    };
    // SAFETY: and on `public_key`.
    let public_key = unsafe { slice_bytes(public_key) };
    let (code, bytes) = match provision::operator::information(person, public_key) {
        Ok(information) => (status::OK, information),
        Err(refused) => (status::INVALID, refused.message.into_bytes()),
    };
    // SAFETY: `out` has room for `cap` bytes and `out_len` is writable.
    unsafe { hand(&bytes, out, cap, out_len) };
    code
}

/// The request, `CERTIFICATE REQUEST` PEM, that `information` and the
/// keeper's `signature` over it make, its signature verified under the key
/// the information holds, `provision::operator::assemble`;
/// `XMIP_E_INVALID` with the refusal.
///
/// # Safety
/// Both slices point at their stated lengths of readable bytes; `out` has
/// room for `cap` bytes and `out_len` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_operator_assemble_v1(
    information: Slice,
    signature: Slice,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: the caller upholds the header's contract on both.
    let (information, signature) = unsafe { (slice_bytes(information), slice_bytes(signature)) };
    let (code, text) = match provision::operator::assemble(information, signature) {
        Ok(request) => (status::OK, request),
        Err(refused) => (status::INVALID, refused.message),
    };
    // SAFETY: `out` has room for `cap` bytes and `out_len` is writable.
    unsafe { refuse(&text, out, cap, out_len) };
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
    fn a_request_is_written_for_a_person_and_a_distinguished_name_is_refused() {
        let base = std::env::temp_dir().join(format!("xmip-ffi-request-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let folder = base.join("phone").display().to_string();
        // SAFETY: every pointer is to live, writable storage of its size.
        let (code, text) = answer(|out, cap, len| unsafe {
            xmip_operator_request_v1(borrow("alice@example.org"), borrow(&folder), out, cap, len)
        });
        assert_eq!(code, status::OK, "{text}");
        let made: serde_json::Value = serde_json::from_str(&text).expect("json");
        let key = std::fs::read_to_string(made["key"].as_str().expect("key")).expect("read");
        assert!(key.contains("PRIVATE KEY"));
        assert!(!text.contains("PRIVATE KEY"), "the key never crosses");
        let request = made["request"].as_str().expect("request");
        let request = std::fs::read_to_string(request).expect("read");
        assert!(request.contains("CERTIFICATE REQUEST"));

        // SAFETY: as above.
        let (code, text) = answer(|out, cap, len| unsafe {
            xmip_operator_request_v1(borrow("alice@example.org"), borrow(&folder), out, cap, len)
        });
        assert_eq!(code, status::INVALID);
        assert!(text.contains("nothing is overwritten"), "{text}");
        let other = base.join("other").display().to_string();
        // SAFETY: as above.
        let (code, text) = answer(|out, cap, len| unsafe {
            xmip_operator_request_v1(borrow("CN=alice"), borrow(&other), out, cap, len)
        });
        assert_eq!(code, status::INVALID);
        assert!(text.contains("person"), "{text}");

        let chain = base
            .join("phone")
            .join("operator.pem")
            .display()
            .to_string();
        // SAFETY: as above.
        let (code, said) = answer(|out, cap, len| unsafe {
            xmip_operator_keep_v1(borrow(&chain), borrow("first"), 0, out, cap, len)
        });
        assert_eq!(code, status::OK, "{said}");
        // SAFETY: as above.
        let (code, said) = answer(|out, cap, len| unsafe {
            xmip_operator_keep_v1(borrow(&chain), borrow("over"), 0, out, cap, len)
        });
        assert_eq!(code, status::INVALID);
        assert!(said.contains("nothing is overwritten"), "{said}");
        assert_eq!(std::fs::read_to_string(&chain).expect("kept"), "first");
        // SAFETY: as above.
        let (code, said) = answer(|out, cap, len| unsafe {
            xmip_operator_keep_v1(borrow(&chain), borrow("second"), 1, out, cap, len)
        });
        assert_eq!(code, status::OK, "{said}");
        assert_eq!(std::fs::read_to_string(&chain).expect("kept"), "second");
        let _ = std::fs::remove_dir_all(&base);
    }

    fn lent(bytes: &[u8]) -> Slice {
        Slice {
            ptr: bytes.as_ptr(),
            len: bytes.len(),
        }
    }

    fn bytes(call: impl Fn(*mut u8, usize, *mut usize) -> i32) -> (i32, Vec<u8>) {
        let mut room = vec![0u8; 8192];
        let mut length = 0usize;
        let code = call(room.as_mut_ptr(), room.len(), &raw mut length);
        room.truncate(length);
        (code, room)
    }

    #[test]
    fn a_keeper_signs_the_information_and_the_two_halves_make_a_request() {
        let keeper = provision::KeyPair::generate().expect("a key");
        let point = keeper.point().to_vec();
        // SAFETY: every pointer is to live, writable storage of its size.
        let (code, information) = bytes(|out, cap, len| unsafe {
            xmip_operator_information_v1(borrow("alice@example.org"), lent(&point), out, cap, len)
        });
        assert_eq!(code, status::OK);
        let signature = keeper.sign(&information).expect("signed");
        // SAFETY: as above.
        let (code, text) = answer(|out, cap, len| unsafe {
            xmip_operator_assemble_v1(lent(&information), lent(&signature), out, cap, len)
        });
        assert_eq!(code, status::OK, "{text}");
        assert!(text.contains("CERTIFICATE REQUEST"), "{text}");

        // SAFETY: as above.
        let (code, text) = answer(|out, cap, len| unsafe {
            xmip_operator_assemble_v1(lent(&information), lent(b"no signature"), out, cap, len)
        });
        assert_eq!(code, status::INVALID);
        assert!(text.contains("keeper"), "{text}");
        // SAFETY: as above.
        let (code, said) = bytes(|out, cap, len| unsafe {
            xmip_operator_information_v1(borrow("alice@example.org"), lent(b"no"), out, cap, len)
        });
        assert_eq!(code, status::INVALID, "{}", String::from_utf8_lossy(&said));
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
