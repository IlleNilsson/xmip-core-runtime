//! `xmip_operate.h` section 25: every Report listed, and one opened
//! (ADR-0072, amendment 2026-11-10). The export only — what it answers is
//! `crate::report`'s, and the list and its answers are `xmip-core-report`'s.
//! A node's build only, as section 23.
//!
//! In `ffi/`, the one folder of the runtime that may hold unsafe code
//! (ADR-0050, refined 2026-09-25): it reads the act and the arguments a
//! surface handed over and writes its answer where it was told.
#![allow(unsafe_code)]

use abi::ffi::{Str, status};

use crate::ffi::rule::refuse;
use crate::ffi::text::scope_text;
use crate::report::{self, Unanswered};

/// `xmip_report_v1`: [`report::act`].
///
/// # Safety
/// As the header states: `act` and `arguments` readable for their lengths,
/// `out` room for `cap` bytes, `out_len` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_report_v1(
    act: Str,
    arguments: Str,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: the caller's contract is this export's, passed on whole.
    abi::guarded(status::PANIC, || unsafe {
        acted(act, arguments, out, cap, out_len)
    })
}

/// [`xmip_report_v1`] within its guard.
unsafe fn acted(act: Str, arguments: Str, out: *mut u8, cap: usize, out_len: *mut usize) -> i32 {
    // SAFETY: the caller upholds the header's contract on both strings:
    // their bytes are the caller's, alive for the call, and not freed here.
    let read = [act, arguments].map(|text| unsafe { scope_text(text) });
    let [Some(act), Some(arguments)] = read else {
        return status::MALFORMED;
    };

    // An open too long for `cap` is answered for its length and not
    // audited; the call that has room for it is (section 25).
    let room = if out.is_null() { 0 } else { cap };
    let (code, text) = match report::act(act, arguments, room) {
        Ok(answer) => (status::OK, answer),
        Err(Unanswered::Refused(refusal)) => (status::INVALID, refusal),
        Err(Unanswered::Failed(failure)) => (status::IO, failure),
    };

    // SAFETY: `out` has room for `cap` bytes and `out_len` is writable, per
    // the contract; the text shape a refusal takes is the answer's too.
    unsafe { refuse(&text, out, cap, out_len) };
    code
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::text::borrow;

    #[test]
    fn the_export_has_the_shape_the_binding_declares() {
        // A signature that drifted from xmip-core-abi's fails to compile here.
        let _: abi::operate::report::ReportFn = xmip_report_v1;
    }

    #[test]
    fn the_list_is_written_whole_once_its_length_is_asked() {
        let mut needed = 0usize;
        // An audit directory of the test's own, which holds no record.
        let unread = std::env::temp_dir().join(format!("xmip-report-ffi-{}", std::process::id()));
        let arguments =
            &serde_json::json!({ "directory": unread.display().to_string() }).to_string();
        // SAFETY: a null buffer of capacity 0 asks for the length only; both
        // strings are borrowed for the call.
        let code = unsafe {
            xmip_report_v1(
                borrow("list"),
                borrow(arguments),
                std::ptr::null_mut(),
                0,
                &raw mut needed,
            )
        };
        assert_eq!(code, status::OK);

        let mut buffer = vec![0u8; needed];
        // SAFETY: `buffer` has room for `needed` bytes.
        let code = unsafe {
            xmip_report_v1(
                borrow("list"),
                borrow(arguments),
                buffer.as_mut_ptr(),
                buffer.len(),
                &raw mut needed,
            )
        };
        assert_eq!((code, needed), (status::OK, buffer.len()));
        let said = String::from_utf8(buffer).expect("UTF-8");
        assert!(said.starts_with("{\"kinds\":["), "{said}");
        assert!(said.contains("\"name\":\"Regulation\""), "{said}");
    }

    #[test]
    fn an_act_that_is_none_is_invalid_and_a_string_not_utf8_malformed() {
        let mut room = vec![0u8; 256];
        let mut length = 0usize;
        // SAFETY: both strings are borrowed for the call and the room is ours.
        let code = unsafe {
            xmip_report_v1(
                borrow("probe"),
                borrow(""),
                room.as_mut_ptr(),
                room.len(),
                &raw mut length,
            )
        };
        assert_eq!(code, status::INVALID);
        let refused = String::from_utf8_lossy(&room[..length]).to_string();
        assert!(refused.starts_with("REFUSED: \"probe\""), "{refused}");

        let broken = [0xffu8, 0xfe];
        let act = Str {
            ptr: broken.as_ptr(),
            len: broken.len(),
        };
        // SAFETY: `act` points at its two bytes; the room is ours.
        let code = unsafe {
            xmip_report_v1(
                act,
                borrow(""),
                room.as_mut_ptr(),
                room.len(),
                &raw mut length,
            )
        };
        assert_eq!(code, status::MALFORMED);
    }

    #[test]
    fn a_probe_asked_its_length_first_is_audited_once_by_the_call_that_receives_it() {
        let folder =
            std::env::temp_dir().join(format!("xmip-report-ffi-once-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&folder);
        std::fs::create_dir_all(&folder).expect("a folder");
        let configuration = folder.join("node.xmip");
        // The test cluster's first node, by place (ADR-0056, amendment
        // 2026-10-03), keeping Xmip Storage itself.
        let cluster = configure::fixture::test_cluster();
        let node = &cluster.node(0).name;
        std::fs::write(
            &configuration,
            format!(
                "roles = \"storage\"\n[service]\nname = \"xmip-{node}\"\n\
                 cluster_name = \"{}\"\nnode_name = \"{node}\"\n",
                cluster.name
            ),
        )
        .expect("written");
        let arguments = serde_json::json!({
            "report": "Regulation", "parameter": "GDPR",
            "configuration": configuration.display().to_string(), "program": "xmip",
            "directory": folder.display().to_string(),
        })
        .to_string();
        let mut needed = 0usize;
        // SAFETY: a null buffer of capacity 0 asks for the length only; both
        // strings are borrowed for the call.
        let code = unsafe {
            xmip_report_v1(
                borrow("open"),
                borrow(&arguments),
                std::ptr::null_mut(),
                0,
                &raw mut needed,
            )
        };
        assert_eq!(code, status::OK);
        // Room to spare: the second probe may take a millisecond longer.
        let mut buffer = vec![0u8; needed + 16];
        let mut written = 0usize;
        // SAFETY: `buffer` has room for its length.
        let code = unsafe {
            xmip_report_v1(
                borrow("open"),
                borrow(&arguments),
                buffer.as_mut_ptr(),
                buffer.len(),
                &raw mut written,
            )
        };
        assert_eq!(code, status::OK);
        let file = xaudit::audit_store::stated(Some(&folder)).expect("a file");
        let query = xaudit::audit_query::AuditQuery::from_pairs([("action", report::PROBED)])
            .expect("a query");
        let page = xaudit::audit_store::ask(&file, &query).expect("read");
        let _ = std::fs::remove_dir_all(&folder);
        assert_eq!(
            page.matched, 1,
            "the length asked for is not a probe recorded"
        );
        assert!(written <= buffer.len());
    }

    #[test]
    fn a_configuration_that_cannot_be_read_fails_as_input_and_output() {
        let missing = std::env::temp_dir().join(format!("xmip-report-none-{}", std::process::id()));
        let arguments = serde_json::json!({
            "report": "Regulation", "parameter": "GDPR",
            "configuration": missing.display().to_string(), "program": "xmip",
        })
        .to_string();
        let mut room = vec![0u8; 1024];
        let mut length = 0usize;
        // SAFETY: both strings are borrowed for the call and the room is ours.
        let code = unsafe {
            xmip_report_v1(
                borrow("open"),
                borrow(&arguments),
                room.as_mut_ptr(),
                room.len(),
                &raw mut length,
            )
        };
        assert_eq!(code, status::IO);
        assert!(String::from_utf8_lossy(&room[..length]).starts_with("FAILED: "));
    }
}
