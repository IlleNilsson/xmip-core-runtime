//! `xmip_operate.h` section 18: the role a caller holds and the one check
//! every act passes (`crate::plane::role`, ADR-0009), forwarded, so the
//! .NET surfaces' gate and a node's operate listener refuse in the same
//! words. Pure in the sense of section 7: no handle, any thread.
#![allow(unsafe_code)]

use abi::ffi::{Str, status};

use crate::ffi::rule::refuse;
use crate::ffi::text::{borrow, scope_text};
use crate::plane::role::{Role, admitted};

/// The role a word names, Observer for any other.
///
/// # Safety
/// `word` points at its stated length of readable bytes; `out` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_security_role_named_v1(word: Str, out: *mut i32) -> i32 {
    // SAFETY: the caller upholds the header's contract on `word`.
    let Some(word) = (unsafe { scope_text(word) }) else {
        return status::MALFORMED;
    };
    // SAFETY: `out` is writable per the contract.
    unsafe { *out = Role::named(word) as i32 };
    status::OK
}

/// What a role is called, and what it may do in the words a badge uses;
/// each static.
///
/// # Safety
/// `out_word` and `out_description` are writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_security_role_words_v1(
    role: i32,
    out_word: *mut Str,
    out_description: *mut Str,
) -> i32 {
    let Some(role) = Role::from_wire(role) else {
        return status::INVALID;
    };
    // SAFETY: both are writable per the contract.
    unsafe {
        *out_word = borrow(role.word());
        *out_description = borrow(role.describe());
    }
    status::OK
}

/// Whether `who` — proven where `proven` is non-zero — holding `role` may
/// `act` on `target`: `XMIP_OK` with nothing said, or `XMIP_E_AUTH` with
/// the refusal in `said`.
///
/// # Safety
/// The strings point at their stated lengths; `said` has room for `cap`
/// bytes and `said_len` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_act_admitted_v1(
    who: Str,
    proven: u8,
    role: i32,
    act: Str,
    target: Str,
    said: *mut u8,
    cap: usize,
    said_len: *mut usize,
) -> i32 {
    // SAFETY: the caller upholds the header's contract on every string.
    let (Some(who), Some(act), Some(target)) = (
        unsafe { scope_text(who) },
        unsafe { scope_text(act) },
        unsafe { scope_text(target) },
    ) else {
        return status::MALFORMED;
    };
    let Some(role) = Role::from_wire(role) else {
        return status::INVALID;
    };
    let caller = (proven != 0).then_some(who);
    let (code, sentence) = match admitted(caller, role, crate::plane::call::ACT, (act, target)) {
        Ok(()) => (status::OK, String::new()),
        Err(refused) => (status::AUTH, refused),
    };
    // SAFETY: per the contract above.
    unsafe { refuse(&sentence, said, cap, said_len) };
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(value: &str) -> Str {
        borrow(value)
    }

    #[test]
    fn the_gate_refuses_an_observer_in_the_one_sentence() {
        let mut said = vec![0u8; 512];
        let mut length = 0usize;
        // SAFETY: every pointer is to live, writable storage of its size.
        let code = unsafe {
            xmip_act_admitted_v1(
                text("CN=a"),
                1,
                0,
                text("pause"),
                text("x"),
                said.as_mut_ptr(),
                said.len(),
                &raw mut length,
            )
        };
        assert_eq!(code, status::AUTH);
        let sentence = String::from_utf8_lossy(&said[..length]).to_string();
        assert!(sentence.starts_with("REFUSED. CN=a may not pause x: CN=a is Observer"));

        // SAFETY: as above.
        let admitted = unsafe {
            xmip_act_admitted_v1(
                text("CN=a"),
                1,
                1,
                text("pause"),
                text("x"),
                said.as_mut_ptr(),
                said.len(),
                &raw mut length,
            )
        };
        assert_eq!((admitted, length), (status::OK, 0));
    }

    #[test]
    fn a_word_names_its_role_and_a_role_its_words() {
        let mut role = -1;
        // SAFETY: `role` is writable.
        assert_eq!(
            unsafe { xmip_security_role_named_v1(text("Operator"), &raw mut role) },
            status::OK
        );
        assert_eq!(role, 1);
        let (mut word, mut described) = (text(""), text(""));
        // SAFETY: both are writable.
        let code = unsafe { xmip_security_role_words_v1(2, &raw mut word, &raw mut described) };
        assert_eq!(code, status::OK);
        assert_eq!(word.len, "Developer".len());
        // SAFETY: as above.
        assert_eq!(
            unsafe { xmip_security_role_words_v1(9, &raw mut word, &raw mut described) },
            status::INVALID
        );
    }
}
