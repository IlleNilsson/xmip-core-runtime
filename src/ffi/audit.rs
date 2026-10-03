//! `xmip_operate.h` section 9: a program's audit record, forwarded.
//!
//! Every Xmip program audits through `xmip-core-audit` (ADR-0062). A .NET
//! program and PowerShell cannot link it, so this library — the one they
//! already load for section 7 — forwards `xmip_audit_v1` to
//! `audit::program_audit::ProgramAudit` and nothing else: the record, its
//! policy, the file sink and the fallback to the operating system's log are
//! the capability's. The header's phase and severity integers are read by
//! `crate::wire`, with every other enum that crosses the header.
//!
//! `xmip_audit_read_v1` reads the records back for every surface through the
//! capability's one reader and one query (`audit_store`, `audit_query`) and
//! answers the header's JSON (ADR-0062, amendment 2026-09-29).
//!
//! In `ffi/`, the one folder of the runtime that may hold unsafe code
//! (ADR-0050, refined 2026-09-25): a surface hands over where to write.
#![allow(unsafe_code)]

use std::collections::BTreeMap;
use std::path::Path;

use abi::ffi::{Str, status};
use abi::operate::audit::kept;
use serde_json::{Map, Value, json};
use xaudit::audit_column::{Column, SEVERITIES};
use xaudit::audit_entry::AuditEntry;
use xaudit::audit_query::{AuditGroup, AuditQuery};
use xaudit::audit_store;
use xaudit::emit::AuditOutcome;
use xaudit::program_audit::ProgramAudit;

use crate::ffi::operate::scope_text;
use crate::ffi::rule::refuse;
use crate::wire::{from_wire_phase, from_wire_severity};

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
    let Some(properties) =
        (unsafe { pairs::<BTreeMap<String, String>>(properties, properties_len) })
    else {
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

/// `xmip_audit_read_v1`: [`audit_store::read`] and [`AuditQuery::ask`], as
/// the header's JSON.
///
/// # Safety
/// As the header states: `directory` readable for its length, `query`
/// holding `query_len` strings, `out` room for `cap` bytes, `out_len`
/// writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_audit_read_v1(
    directory: Str,
    query: *const Str,
    query_len: usize,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    let (code, text) = if !query_len.is_multiple_of(2) || (query.is_null() && query_len > 0) {
        (
            status::INVALID,
            "REFUSED: an audit query is keys and values, so its length is even.".to_string(),
        )
    } else {
        // SAFETY: the caller upholds the header's contract on every string.
        let asked = unsafe {
            (
                scope_text(directory),
                pairs::<Vec<(String, String)>>(query, query_len),
            )
        };
        match asked {
            (Some(directory), Some(query)) => answer(directory, &query),
            _ => return status::MALFORMED,
        }
    };

    // SAFETY: `out` has room for `cap` bytes and `out_len` is writable.
    unsafe { refuse(&text, out, cap, out_len) };
    code
}

/// The read, the status it ends in and the text it writes.
fn answer(directory: &str, query: &[(String, String)]) -> (i32, String) {
    let asked = match AuditQuery::from_pairs(query.iter().map(|(k, v)| (k.as_str(), v.as_str()))) {
        Ok(asked) => asked,
        Err(refusal) => return (status::INVALID, refusal),
    };
    let stated = (!directory.is_empty()).then(|| Path::new(directory));
    let Some(file) = audit_store::stated(stated) else {
        let none = json!({"file": "", "read": 0, "matched": 0, "offset": asked.offset,
            "limit": asked.limit, "records": [], "groups": [], "actions": [],
            "columns": Column::ALL.map(Column::word), "severities": SEVERITIES});
        return (status::OK, none.to_string());
    };
    let entries = match audit_store::read(&file) {
        Ok(entries) => entries,
        Err(error) => return (status::IO, error.to_string()),
    };
    let page = asked.ask(&entries);
    let answer = json!({
        "file": file.display().to_string(),
        "read": page.read,
        "matched": page.matched,
        "offset": asked.offset,
        "limit": asked.limit,
        "records": page.records.iter().map(record).collect::<Vec<_>>(),
        "groups": page.groups.iter().map(group).collect::<Vec<_>>(),
        "actions": page.actions,
        "columns": Column::ALL.map(Column::word),
        "severities": SEVERITIES,
    });

    (status::OK, answer.to_string())
}

fn record(entry: &AuditEntry) -> Value {
    let texts = |map: &BTreeMap<String, String>| -> Map<String, Value> {
        map.iter()
            .map(|(key, value)| (key.clone(), Value::String(value.clone())))
            .collect()
    };
    let mut said = json!({
        "audit_id": entry.audit_id, "at": entry.at, "program": entry.program,
        "host": entry.host, "process": entry.process, "action": entry.action,
        "phase": entry.phase, "severity": entry.severity, "summary": entry.summary(),
        "scope": texts(&entry.scope), "properties": texts(&entry.properties),
        "hidden": entry.hidden,
    });
    for (key, value) in [
        ("location", entry.location.as_deref()),
        ("node", entry.node()),
        ("cluster", entry.cluster()),
        ("message", entry.message.as_deref()),
    ] {
        if let Some(value) = value {
            said[key] = Value::String(value.to_string());
        }
    }
    said
}

fn group(group: &AuditGroup) -> Value {
    json!({
        "kind": group.kind, "who": group.who, "count": group.count,
        "warnings": group.warnings, "errors": group.errors, "latest": group.latest,
        "hidden": group.hidden,
    })
}

/// The header's key-then-value strings, in order, gathered into whatever the
/// caller keeps them in — a map here, a list for section 13 — or `None` when
/// one is not UTF-8.
///
/// # Safety
/// `properties` holds `len` readable strings, or `len` is 0.
pub(crate) unsafe fn pairs<Kept: FromIterator<(String, String)>>(
    properties: *const Str,
    len: usize,
) -> Option<Kept> {
    if len == 0 {
        return Some(core::iter::empty().collect());
    }

    // SAFETY: per the contract above.
    let strings = unsafe { core::slice::from_raw_parts(properties, len) };

    strings
        .as_chunks::<2>()
        .0
        .iter()
        .map(|[key, value]| {
            // SAFETY: each string points at its stated length of readable bytes.
            let (key, value) = unsafe { (scope_text(*key), scope_text(*value)) };
            Some((key?.to_string(), value?.to_string()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::operate::borrow;
    use abi::operate::audit::{phase, severity};
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
        let _: abi::operate::audit::AuditReadFn = xmip_audit_read_v1;
    }

    fn read(directory: &str, query: &[&str]) -> (i32, String) {
        let query: Vec<Str> = query.iter().map(|text| borrow(text)).collect();
        let mut out = vec![0u8; 64 * 1024];
        let mut length = 0usize;

        // SAFETY: every string is alive for the call; the buffer has room.
        let code = unsafe {
            xmip_audit_read_v1(
                borrow(directory),
                query.as_ptr(),
                query.len(),
                out.as_mut_ptr(),
                out.len(),
                &raw mut length,
            )
        };
        (code, String::from_utf8_lossy(&out[..length]).into_owned())
    }

    #[test]
    fn a_record_written_across_the_boundary_is_read_back_across_it() {
        let directory =
            std::env::temp_dir().join(format!("xmip-runtime-audit-read-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        let place = directory.to_string_lossy().into_owned();
        let pair = [borrow("url"), borrow("http://127.0.0.1:5087")];
        assert_eq!(call(&place, phase::FAILURE, &pair).0, status::OK);

        let (code, text) = read(&place, &["severity", "information", "sort", "program"]);

        assert_eq!(code, status::OK, "{text}");
        let answer: Value = serde_json::from_str(&text).expect("JSON");
        assert_eq!(answer["read"], 1, "{text}");
        assert_eq!(answer["matched"], 1);
        let record = &answer["records"][0];
        assert_eq!(record["program"], "xmip-core-runtime tests");
        assert_eq!(record["phase"], "failure");
        assert_eq!(record["properties"]["url"], "http://127.0.0.1:5087");
        assert!(record.get("location").is_none(), "declared none: {record}");
        assert_eq!(answer["groups"][0]["kind"], "host");
        assert_eq!(answer["actions"][0], "probe");
        assert_eq!(answer["columns"][0], "at");
        assert_eq!(answer["severities"][2], "error");
        let _ = fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_hidden_run_is_read_back_only_when_the_query_includes_it() {
        let directory =
            std::env::temp_dir().join(format!("xmip-runtime-audit-hidden-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        let place = directory.to_string_lossy().into_owned();
        let hidden = xaudit::program_audit::ProgramAudit::new("probe", Some(&directory));
        let scope = configure::fixture::test_cluster().scope();
        hidden.locate(&scope);
        hidden.hide();
        hidden.failed("start", "a hidden run").expect("recorded");
        assert_eq!(call(&place, phase::BEGIN, &[]).0, status::OK);

        let (_, left_out) = read(&place, &[]);
        let answer: Value = serde_json::from_str(&left_out).expect("JSON");
        assert_eq!(answer["matched"], 1, "{left_out}");
        assert_eq!(answer["records"][0]["hidden"], false);

        let (_, included) = read(&place, &["hidden", "include"]);
        let answer: Value = serde_json::from_str(&included).expect("JSON");
        assert_eq!(answer["matched"], 2, "{included}");
        assert_eq!(answer["records"][1]["hidden"], true, "the older of the two");
        assert_eq!(answer["groups"][0]["who"], scope.as_str());
        assert_eq!(answer["groups"][0]["hidden"], true);
        let _ = fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_query_it_does_not_take_is_refused_in_its_words() {
        let (code, refusal) = read("", &["colour", "red"]);
        assert_eq!(code, status::INVALID);
        assert!(refusal.starts_with("REFUSED: "), "{refusal}");

        assert_eq!(read("", &["pattern"]).0, status::INVALID, "an odd query");
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
