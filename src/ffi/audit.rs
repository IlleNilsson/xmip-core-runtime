//! `xmip_operate.h` section 9: a program's audit record, forwarded.
//!
//! Every Xmip program audits through `xmip-core-audit` (ADR-0062). A .NET
//! program and PowerShell cannot link it, so this library — the one they
//! already load for section 7 — forwards `xmip_audit_v1` to
//! `audit::program_audit::ProgramAudit` and nothing else: the record, its
//! policy, the file sink and the fallback to the operating system's log are
//! the capability's. The header's phase and severity integers are read here,
//! the one place that has both them and the capability's enums, as
//! `wire.rs` reads observe's.
//!
//! In `ffi/`, the one folder of the runtime that may hold unsafe code
//! (ADR-0050, refined 2026-09-25): a surface hands over where to write.
#![allow(unsafe_code)]

use std::collections::BTreeMap;
use std::path::Path;

use abi::ffi::{Str, status};
use abi::operate::audit::{kept, phase, severity};
use xaudit::emit::AuditOutcome;
use xaudit::program_audit::ProgramAudit;
use xcore::{ExecutionPhase, Severity};

use crate::ffi::operate::scope_text;
use crate::ffi::rule::refuse;

/// `audit::program_audit::ProgramAudit::record`, forwarded.
///
/// # Safety
/// Every `Str` points at its stated length of readable bytes; `properties`
/// at `properties_len` of them; `out_kept` and `said_len` are writable;
/// `said` has room for `said_cap` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_audit_v1(
    program: Str,
    directory: Str,
    action: Str,
    phase: i32,
    severity: i32,
    message: Str,
    properties: *const Str,
    properties_len: usize,
    out_kept: *mut i32,
    said: *mut u8,
    said_cap: usize,
    said_len: *mut usize,
) -> i32 {
    // SAFETY: said_len is writable per the contract.
    unsafe { *said_len = 0 };

    let (Some(phase), Some(severity)) = (from_wire_phase(phase), from_wire_severity(severity))
    else {
        return status::INVALID;
    };

    if !properties_len.is_multiple_of(2) || (properties.is_null() && properties_len > 0) {
        return status::INVALID;
    }

    // SAFETY: the caller upholds the header's contract on every string.
    let texts = unsafe {
        (
            scope_text(program),
            scope_text(directory),
            scope_text(action),
            scope_text(message),
        )
    };
    let (Some(program), Some(directory), Some(action), Some(message)) = texts else {
        return status::MALFORMED;
    };

    // SAFETY: `properties` holds `properties_len` strings per the contract.
    let Some(properties) = (unsafe { pairs(properties, properties_len) }) else {
        return status::MALFORMED;
    };

    let stated = (!directory.is_empty()).then(|| Path::new(directory));
    let said_message = (!message.is_empty()).then_some(message);
    let outcome = ProgramAudit::new(program, stated).record(
        action,
        phase,
        severity,
        said_message,
        properties,
    );

    // SAFETY: out_kept, said and said_len per the contract.
    unsafe {
        match outcome {
            Ok(AuditOutcome::Suppressed) => *out_kept = kept::SUPPRESSED,
            Ok(AuditOutcome::Persisted) => *out_kept = kept::PERSISTED,
            Ok(AuditOutcome::OperatingSystem { log, reason }) => {
                *out_kept = kept::OPERATING_SYSTEM;
                refuse(&format!("{log}: {reason}"), said, said_cap, said_len);
            }
            Err(error) => {
                refuse(&error.to_string(), said, said_cap, said_len);
                return status::IO;
            }
        }
    }

    status::OK
}

/// The key and value strings as a map, or `None` when one is not UTF-8.
///
/// # Safety
/// `properties` holds `len` readable strings, or `len` is 0.
unsafe fn pairs(properties: *const Str, len: usize) -> Option<BTreeMap<String, String>> {
    if len == 0 {
        return Some(BTreeMap::new());
    }

    // SAFETY: per the contract above.
    let strings = unsafe { core::slice::from_raw_parts(properties, len) };
    let mut map = BTreeMap::new();

    for [key, value] in strings.as_chunks::<2>().0 {
        // SAFETY: each string points at its stated length of readable bytes.
        let (key, value) = unsafe { (scope_text(*key), scope_text(*value)) };
        map.insert(key?.to_string(), value?.to_string());
    }

    Some(map)
}

/// The capability's phase for the header's `XmipPhase`, or `None`.
const fn from_wire_phase(value: i32) -> Option<ExecutionPhase> {
    match value {
        phase::BEGIN => Some(ExecutionPhase::Begin),
        phase::EXECUTE => Some(ExecutionPhase::Execute),
        phase::FINISHED => Some(ExecutionPhase::Finished),
        phase::FAILURE => Some(ExecutionPhase::Failure),
        _ => None,
    }
}

/// The capability's severity for the header's `XmipSeverity`, or `None`.
const fn from_wire_severity(value: i32) -> Option<Severity> {
    match value {
        severity::INFORMATION => Some(Severity::Information),
        severity::WARNING => Some(Severity::Warning),
        severity::ERROR => Some(Severity::Error),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::operate::borrow;
    use std::fs;

    fn call(directory: &str, phase: i32, properties: &[Str]) -> (i32, i32, String) {
        let mut kept = -1;
        let mut said = [0u8; 1024];
        let mut said_len = 0usize;

        // SAFETY: every pointer is to a live local of the stated size.
        let code = unsafe {
            xmip_audit_v1(
                borrow("xmip-core-runtime tests"),
                borrow(directory),
                borrow("probe"),
                phase,
                severity::INFORMATION,
                borrow("written by the runtime's own test"),
                properties.as_ptr(),
                properties.len(),
                &raw mut kept,
                said.as_mut_ptr(),
                said.len(),
                &raw mut said_len,
            )
        };
        let text = String::from_utf8_lossy(&said[..said_len.min(said.len())]).into_owned();

        (code, kept, text)
    }

    #[test]
    fn the_export_has_the_shape_the_binding_declares() {
        let _: abi::operate::audit::AuditFn = xmip_audit_v1;
    }

    #[test]
    fn a_record_reaches_the_directory_the_caller_was_told() {
        let directory =
            std::env::temp_dir().join(format!("xmip-runtime-audit-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        let pair = [borrow("url"), borrow("http://127.0.0.1:5087")];

        let (code, kept_as, said) = call(&directory.to_string_lossy(), phase::BEGIN, &pair);

        assert_eq!(code, status::OK, "{said}");
        assert_eq!(kept_as, kept::PERSISTED);
        assert!(said.is_empty(), "{said}");
        let text = fs::read_to_string(directory.join(xaudit::file_sink::FILE_NAME)).expect("read");
        assert!(
            text.contains("program = \"xmip-core-runtime tests\""),
            "{text}"
        );
        assert!(
            text.contains("\"url\" = \"http://127.0.0.1:5087\""),
            "{text}"
        );
        let _ = fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_phase_the_header_does_not_define_or_an_odd_list_is_invalid() {
        assert_eq!(call("", 9, &[]).0, status::INVALID);
        assert_eq!(call("", phase::BEGIN, &[borrow("key")]).0, status::INVALID);
    }
}
