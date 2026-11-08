//! `xmip_operate.h` section 18: the role a caller holds, the callers the
//! runtime proved, held behind opaque handles (`crate::plane::held`), and
//! the one check every act passes (`crate::plane::role`, ADR-0009),
//! forwarded, so the .NET surfaces' gate and a node's operate listener
//! refuse in the same words and no host's word is a caller. Pure in the
//! sense of section 7: no object handle, any thread.
#![allow(unsafe_code)]

use abi::ffi::{Str, status};

use crate::ffi::rule::refuse;
use crate::ffi::text::{borrow, scope_text};
use crate::plane::held;
use crate::plane::role::{Role, act_admitted};

/// The role a word names, Observer for any other.
///
/// # Safety
/// `word` points at its stated length of readable bytes; `out` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_security_role_named_v1(word: Str, out: *mut i32) -> i32 {
    abi::guarded(status::PANIC, || {
        // SAFETY: the caller upholds the header's contract on `word`.
        let Some(word) = (unsafe { scope_text(word) }) else {
            return status::MALFORMED;
        };
        // SAFETY: `out` is writable per the contract.
        unsafe { *out = Role::named(word) as i32 };
        status::OK
    })
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
    abi::guarded(status::PANIC, || {
        let Some(role) = Role::from_wire(role) else {
            return status::INVALID;
        };
        // SAFETY: both are writable per the contract.
        unsafe {
            *out_word = borrow(role.word());
            *out_description = borrow(role.describe());
        }
        status::OK
    })
}

/// Whether the caller the handle `caller` holds — one the runtime handed
/// out (`xmip_caller_proven_v1`, `xmip_caller_hold_v1`,
/// `xmip_caller_process_v1`); 0, or one unknown, released, revoked or
/// expired, for no one — holding `role` may `act` on `target`: `XMIP_OK`
/// with nothing said, or `XMIP_E_AUTH` with the refusal in `said`.
///
/// # Safety
/// The strings point at their stated lengths; `said` has room for `cap`
/// bytes and `said_len` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_act_admitted_v1(
    caller: u64,
    role: i32,
    act: Str,
    target: Str,
    said: *mut u8,
    cap: usize,
    said_len: *mut usize,
) -> i32 {
    // SAFETY: the caller's contract is this export's, passed on whole.
    abi::guarded(status::PANIC, || unsafe {
        admitted_act(caller, role, act, target, said, cap, said_len)
    })
}

/// [`xmip_act_admitted_v1`] within its guard.
unsafe fn admitted_act(
    caller: u64,
    role: i32,
    act: Str,
    target: Str,
    said: *mut u8,
    cap: usize,
    said_len: *mut usize,
) -> i32 {
    // SAFETY: the caller upholds the header's contract on every string.
    let (Some(act), Some(target)) = (unsafe { scope_text(act) }, unsafe { scope_text(target) })
    else {
        return status::MALFORMED;
    };
    let Some(role) = Role::from_wire(role) else {
        return status::INVALID;
    };
    let (code, sentence) = match act_admitted(caller, role, (act, target)) {
        Ok(()) => (status::OK, String::new()),
        Err(refused) => (status::AUTH, refused),
    };
    // SAFETY: per the contract above.
    unsafe { refuse(&sentence, said, cap, said_len) };
    code
}

/// Another holder of the caller `caller` holds: a handle of its own in
/// `out_caller`, for as long and revoked by the same, which this holder
/// releases. `XMIP_OK`; `XMIP_E_AUTH` with 0 where `caller` is no one.
///
/// # Safety
/// `out_caller` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_caller_hold_v1(caller: u64, out_caller: *mut u64) -> i32 {
    abi::guarded(status::PANIC, || {
        let again = held::again(caller);
        // SAFETY: `out_caller` is writable per the contract.
        unsafe { *out_caller = again };
        if again == 0 { status::AUTH } else { status::OK }
    })
}

/// Release `caller`: no one after. Releasing 0, or one not held, does
/// nothing.
#[unsafe(no_mangle)]
pub extern "C" fn xmip_caller_release_v1(caller: u64) {
    abi::guarded((), || {
        held::release(caller);
    });
}

/// Who the caller `caller` holds is, for a host to show and a directory to
/// look its role up by: the identity the authentication gate answered,
/// empty for no one. Never a caller itself: an act takes the handle.
///
/// # Safety
/// `out` has room for `cap` bytes and `out_len` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_caller_named_v1(
    caller: u64,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: the caller's contract is this export's, passed on whole.
    abi::guarded(status::PANIC, || unsafe {
        caller_named(caller, out, cap, out_len)
    })
}

/// [`xmip_caller_named_v1`] within its guard.
unsafe fn caller_named(caller: u64, out: *mut u8, cap: usize, out_len: *mut usize) -> i32 {
    let name = held::proven(caller)
        .map(|caller| caller.value)
        .unwrap_or_default();
    // SAFETY: per the contract above.
    unsafe { refuse(&name, out, cap, out_len) };
    status::OK
}

/// The caller this process is: the account it runs as, read from the
/// operating system — its own token on Windows, its effective user on Unix,
/// never the environment — run through the authentication gate as
/// `peer-credentials` (`plane::caller::local`) and held as long as its
/// holder keeps it; the handle in `out_caller`, the identity in `out` for
/// display. `XMIP_OK`; `XMIP_E_AUTH` with 0 and the refusal in `out`. A
/// node's build only.
///
/// # Safety
/// `out_caller` is writable; `out` has room for `cap` bytes and `out_len`
/// is writable.
#[cfg(feature = "node")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_caller_process_v1(
    out_caller: *mut u64,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: the caller's contract is this export's, passed on whole.
    abi::guarded(status::PANIC, || unsafe {
        caller_process(out_caller, out, cap, out_len)
    })
}

/// [`xmip_caller_process_v1`] within its guard.
#[cfg(feature = "node")]
unsafe fn caller_process(
    out_caller: *mut u64,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    let proven =
        crate::plane::local::running_as().and_then(|account| crate::plane::caller::local(&account));
    let (code, handle, text) = match proven {
        Ok(caller) => {
            let name = caller.value.clone();
            match held::hold(caller, None, None, None) {
                0 => (status::AUTH, 0, format!("REFUSED. {name} is not held")),
                handle => (status::OK, handle, name),
            }
        }
        Err(refused) => (status::AUTH, 0, refused),
    };
    // SAFETY: per the contract above.
    unsafe {
        *out_caller = handle;
        refuse(&text, out, cap, out_len);
    }
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(value: &str) -> Str {
        borrow(value)
    }

    fn asked(caller: u64, role: i32) -> (i32, String) {
        let mut said = vec![0u8; 512];
        let mut length = 0usize;
        // SAFETY: every pointer is to live, writable storage of its size.
        let code = unsafe {
            xmip_act_admitted_v1(
                caller,
                role,
                text("pause"),
                text("x"),
                said.as_mut_ptr(),
                said.len(),
                &raw mut length,
            )
        };
        (code, String::from_utf8_lossy(&said[..length]).to_string())
    }

    fn named(caller: u64) -> String {
        let mut out = vec![0u8; 512];
        let mut length = 0usize;
        // SAFETY: as above.
        let code = unsafe { xmip_caller_named_v1(caller, out.as_mut_ptr(), 512, &raw mut length) };
        assert_eq!(code, status::OK);
        String::from_utf8_lossy(&out[..length]).to_string()
    }

    #[test]
    fn the_gate_takes_a_held_caller_and_refuses_an_observer_in_the_one_sentence() {
        use context::{AuthenticatedIdentity, Verified};
        use xcore::{Established, mechanism};
        let identity = AuthenticatedIdentity::new(
            mechanism::mutual_tls(),
            "CN=a",
            Established::Passed,
            Verified::Proven,
        );
        let a = held::hold(identity, None, None, None);
        let (code, sentence) = asked(a, 0);
        assert_eq!(code, status::AUTH);
        assert!(sentence.starts_with("REFUSED. CN=a may not pause x: CN=a is Observer"));
        assert_eq!(asked(a, 1), (status::OK, String::new()));
        assert_eq!(named(a), "CN=a");

        // Another holder outlives the first's release.
        let mut circuit = 0u64;
        // SAFETY: `circuit` is writable.
        assert_eq!(
            unsafe { xmip_caller_hold_v1(a, &raw mut circuit) },
            status::OK
        );
        xmip_caller_release_v1(a);
        assert_eq!(asked(circuit, 1).0, status::OK);
        xmip_caller_release_v1(circuit);

        // No one: released, never handed out, or 0, whatever the role.
        for nobody in [a, circuit, 0, 0x5eed] {
            let (code, sentence) = asked(nobody, 2);
            assert_eq!(code, status::AUTH);
            assert!(sentence.starts_with("REFUSED. Nothing proved who asks to pause x"));
            assert_eq!(named(nobody), "");
            let mut again = 7u64;
            // SAFETY: `again` is writable.
            let code = unsafe { xmip_caller_hold_v1(nobody, &raw mut again) };
            assert_eq!((code, again), (status::AUTH, 0));
        }
    }

    #[cfg(feature = "node")]
    #[test]
    fn this_process_is_the_account_the_system_names_held_and_proven() {
        let mut caller = 0u64;
        let mut out = vec![0u8; 512];
        let mut length = 0usize;
        // SAFETY: every pointer is to live, writable storage of its size.
        let code = unsafe {
            xmip_caller_process_v1(&raw mut caller, out.as_mut_ptr(), 512, &raw mut length)
        };
        let name = String::from_utf8_lossy(&out[..length]).to_string();
        assert_eq!(code, status::OK, "{name}");
        assert_ne!(caller, 0);
        assert_eq!(named(caller), name);
        assert_eq!(asked(caller, 1).0, status::OK);
        xmip_caller_release_v1(caller);
        assert_eq!(asked(caller, 1).0, status::AUTH);
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
