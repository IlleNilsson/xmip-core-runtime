//! `xmip_operate.h` section 22: a node's certificate from the cluster's own
//! authority, issued on the operator's machine for a node an environment
//! template puts on a machine of its own (ADR-0015, amendment 2026-10-21):
//! `provision::node::issue_into`. A forwarder only: the rules are the
//! capability's. A node's build only, as section 19's signing.
#![allow(unsafe_code)]

use abi::ffi::{Str, status};
use serde_json::json;

use crate::ffi::rule::refuse;
use crate::ffi::text::scope_text;

/// The authority kept in the folder `authority` — made there, called
/// `name`, where none is kept — and a fresh key and certificate for the node
/// `node` under it, for every name in `names` (comma separated) and the
/// node's own, written into `folder` as `node.pem`, `node.key` and
/// `anchors.pem`, private files. The answer is JSON,
/// `{"certificate","key","anchors"}`, the three files' paths;
/// `XMIP_E_INVALID` with the refusal.
///
/// # Safety
/// The strings point at their stated lengths of readable bytes; `out` has
/// room for `cap` bytes and `out_len` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_node_issue_v1(
    authority: Str,
    name: Str,
    node: Str,
    names: Str,
    folder: Str,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: the caller upholds the header's contract on every string.
    let read = [authority, name, node, names, folder].map(|text| unsafe { scope_text(text) });
    let [
        Some(authority),
        Some(name),
        Some(node),
        Some(names),
        Some(folder),
    ] = read
    else {
        return status::MALFORMED;
    };
    let names: Vec<String> = names
        .split(',')
        .map(str::trim)
        .filter(|one| !one.is_empty())
        .map(str::to_string)
        .collect();
    let issued = provision::node::issue_into(
        std::path::Path::new(authority),
        name,
        node,
        &names,
        std::path::Path::new(folder),
        provision::now(),
    );
    let (code, text) = match issued {
        Ok(written) => (
            status::OK,
            json!({
                "certificate": written.certificate.display().to_string(),
                "key": written.key.display().to_string(),
                "anchors": written.anchor.display().to_string(),
            })
            .to_string(),
        ),
        Err(refused) => (status::INVALID, refused.message),
    };
    // SAFETY: `out` has room for `cap` bytes and `out_len` is writable.
    unsafe { refuse(&text, out, cap, out_len) };
    code
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::text::borrow;

    #[test]
    fn a_node_is_issued_into_a_folder_and_one_unnamed_is_refused() {
        let base = std::env::temp_dir().join(format!("xmip-ffi-node-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let authority = base.join("authority").display().to_string();
        let folder = base.join("node").display().to_string();
        let mut room = vec![0u8; 8192];
        let mut length = 0usize;
        // SAFETY: every string is borrowed for the call and the room is ours.
        let code = unsafe {
            xmip_node_issue_v1(
                borrow(&authority),
                borrow("test authority"),
                borrow("node"),
                borrow("node.example, cluster.example"),
                borrow(&folder),
                room.as_mut_ptr(),
                room.len(),
                &raw mut length,
            )
        };
        let answer = String::from_utf8_lossy(&room[..length]).to_string();
        assert_eq!(code, status::OK, "{answer}");
        let written: serde_json::Value = serde_json::from_str(&answer).expect("JSON");
        for file in ["certificate", "key", "anchors"] {
            let path = written[file].as_str().expect("a path");
            assert!(std::path::Path::new(path).exists(), "{file} at {path}");
        }

        // SAFETY: as above.
        let refused = unsafe {
            xmip_node_issue_v1(
                borrow(&authority),
                borrow("test authority"),
                borrow(" "),
                borrow(""),
                borrow(&folder),
                room.as_mut_ptr(),
                room.len(),
                &raw mut length,
            )
        };
        assert_eq!(refused, status::INVALID);
        std::fs::remove_dir_all(&base).expect("removes what it wrote");
    }
}
