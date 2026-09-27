//! `xmip_operate.h` section 13: a System Process, declared (ADR-0053
//! clause 3). The exports only — the file, its directory, its words and its
//! reading are `node`'s ([`node::Declaration`], [`node::standing`]); a .NET
//! program declares itself and the estate's tooling lists the declarations
//! here, and neither writes nor reads a file of its own.
//!
//! In `ffi/`, the one folder of the runtime that may hold unsafe code
//! (ADR-0050, refined 2026-09-25): it reads what a surface handed over and
//! writes its answer where it was told.
#![allow(unsafe_code)]

use std::path::PathBuf;

use abi::ffi::{Str, status};
use serde_json::{Map, Value, json};

use crate::ffi::audit::pairs;
use crate::ffi::operate::scope_text;
use crate::ffi::rule::refuse;

/// `xmip_process_declare_v1`: [`node::Declaration::declare`], the file left
/// standing for the caller to take away where its process ends.
///
/// # Safety
/// As the header states: every `Str` readable for its length, `properties`
/// holding `properties_len` of them, `out` room for `cap` bytes, `out_len`
/// writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_process_declare_v1(
    name: Str,
    location: Str,
    purpose: Str,
    properties: *const Str,
    properties_len: usize,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    if !properties_len.is_multiple_of(2) || (properties.is_null() && properties_len > 0) {
        return status::INVALID;
    }

    // SAFETY: the caller upholds the header's contract on every string.
    let texts = unsafe { (scope_text(name), scope_text(location), scope_text(purpose)) };
    let (Some(name), Some(location), Some(purpose)) = texts else {
        return status::MALFORMED;
    };
    // SAFETY: `properties` holds `properties_len` strings per the contract.
    let Some(said) = (unsafe { pairs::<Vec<(String, String)>>(properties, properties_len) }) else {
        return status::MALFORMED;
    };

    let declared = node::Purpose::declared(purpose).and_then(|purpose| {
        said.iter().try_fold(
            node::Declaration::new(name, location, purpose),
            |declaration, (key, value)| declaration.with(key, value.as_str()),
        )
    });

    let (code, text) = match declared {
        Err(refusal) => (status::INVALID, refusal),
        Ok(declaration) => match declaration.declare() {
            Ok(standing) => (status::OK, standing.handed_over().display().to_string()),
            Err(error) => (status::IO, error.to_string()),
        },
    };

    // SAFETY: `out` has room for `cap` bytes and `out_len` is writable.
    unsafe { refuse(&text, out, cap, out_len) };
    code
}

/// `xmip_process_declarations_v1`: [`node::standing`], as the header's JSON.
///
/// # Safety
/// As the header states: `directory` readable for its length, `out` room
/// for `cap` bytes, `out_len` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_process_declarations_v1(
    directory: Str,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: the caller upholds the header's contract on `directory`.
    let Some(directory) = (unsafe { scope_text(directory) }) else {
        return status::MALFORMED;
    };
    let directory = if directory.is_empty() {
        node::declaration::directory()
    } else {
        PathBuf::from(directory)
    };

    let processes: Vec<Value> = node::standing(&directory)
        .into_iter()
        .map(|standing| {
            let said: Map<String, Value> = standing
                .declaration
                .said
                .into_iter()
                .map(|(key, value)| (key, Value::String(value)))
                .collect();

            json!({
                "file": standing.file.display().to_string(),
                "name": standing.declaration.name,
                "location": standing.declaration.location,
                "purpose": standing.declaration.purpose.word(),
                "pid": standing.pid,
                "started_unix": standing.started_unix,
                "path": standing.path,
                "said": said,
            })
        })
        .collect();
    let answer = json!({
        "directory": directory.display().to_string(),
        "processes": processes,
    });

    // SAFETY: `out` has room for `cap` bytes and `out_len` is writable.
    unsafe { refuse(&answer.to_string(), out, cap, out_len) };
    status::OK
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::operate::borrow;

    #[test]
    fn the_exports_have_the_shapes_the_binding_declares() {
        let _: abi::operate::process::DeclareFn = xmip_process_declare_v1;
        let _: abi::operate::process::DeclarationsFn = xmip_process_declarations_v1;
    }

    fn answer(code: i32, buffer: &[u8], length: usize) -> (i32, String) {
        (
            code,
            String::from_utf8_lossy(&buffer[..length]).into_owned(),
        )
    }

    #[test]
    fn a_process_declares_itself_and_is_listed_with_what_it_said() {
        let directory = std::env::temp_dir().join("xmip-process-ffi-test");
        let _ = std::fs::remove_dir_all(&directory);
        let pairs = [borrow("stress"), borrow("calm")];
        let mut buffer = vec![0u8; 4096];
        let mut length = 0usize;

        // SAFETY: every string is alive for the call; the buffer has room.
        let (code, file) = answer(
            unsafe {
                xmip_process_declare_v1(
                    borrow("xmip-ffi-test"),
                    borrow("xmip:///C1"),
                    borrow("test"),
                    pairs.as_ptr(),
                    pairs.len(),
                    buffer.as_mut_ptr(),
                    buffer.len(),
                    &raw mut length,
                )
            },
            &buffer,
            length,
        );
        assert_eq!(code, status::OK, "{file}");
        let file = PathBuf::from(file);
        let within = directory.join(file.file_name().expect("a file"));
        std::fs::create_dir_all(&directory).expect("made");
        std::fs::rename(&file, &within).expect("moved where this test reads");

        let place = directory.display().to_string();
        // SAFETY: as above.
        let (code, listed) = answer(
            unsafe {
                xmip_process_declarations_v1(
                    borrow(&place),
                    buffer.as_mut_ptr(),
                    buffer.len(),
                    &raw mut length,
                )
            },
            &buffer,
            length,
        );
        assert_eq!(code, status::OK);
        let listed: Value = serde_json::from_str(&listed).expect("JSON");
        let process = &listed["processes"][0];
        assert_eq!(process["name"], "xmip-ffi-test");
        assert_eq!(process["purpose"], "test");
        assert_eq!(process["said"]["stress"], "calm");
        assert_eq!(process["pid"], std::process::id());
        std::fs::remove_dir_all(&directory).expect("cleaned");
    }

    #[test]
    fn a_purpose_that_is_no_word_is_refused_in_a_sentence() {
        let mut buffer = vec![0u8; 512];
        let mut length = 0usize;

        // SAFETY: every string is alive for the call; the buffer has room.
        let (code, said) = answer(
            unsafe {
                xmip_process_declare_v1(
                    borrow("xmip-ffi-test"),
                    borrow(""),
                    borrow("production"),
                    std::ptr::null(),
                    0,
                    buffer.as_mut_ptr(),
                    buffer.len(),
                    &raw mut length,
                )
            },
            &buffer,
            length,
        );

        assert_eq!(code, status::INVALID);
        assert!(said.starts_with("REFUSED"), "{said}");
    }
}
