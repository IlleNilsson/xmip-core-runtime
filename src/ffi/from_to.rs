//! `xmip_operate.h` section 8, from and to: where the work observed at a
//! scope of a read publication came from and where it went, as
//! `observe::topology::from_to` says it — the one rule — forwarded as JSON
//! (the owner, 2026-11-10: *from and to in every observation*; ADR-0027
//! and ADR-0052, amendments 2026-11-11). Nothing here touches a running
//! node.
//!
//! In `ffi/`, the one folder of the runtime that may hold unsafe code
//! (ADR-0050, refined 2026-09-25): a surface hands over where to write.
#![allow(unsafe_code)]

use abi::ffi::{Str, status};
use abi::operate::publication::Publication as Handle;
use observe::topology::from_to::from_to;

use crate::ffi::publication::held;
use crate::ffi::rule::refuse;
use crate::ffi::text::scope_text;

/// The from and to of `scope` in a read publication, as JSON: `from` and
/// `to` in words, `hops` in path order — each its `kind`, `name`, `node`
/// and `transport` — and `unrouted`, what a Dead Message Queue entry's to
/// says.
///
/// # Safety
/// `publication` is a live handle; `scope` points at its stated length of
/// readable bytes; `out` has room for `cap` bytes; `out_len` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_publication_from_to_v1(
    publication: *const Handle,
    scope: Str,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: the caller's contract is this export's, passed on whole.
    abi::guarded(status::PANIC, || unsafe {
        publication_from_to(publication, scope, out, cap, out_len)
    })
}

/// [`xmip_publication_from_to_v1`] within its guard.
unsafe fn publication_from_to(
    publication: *const Handle,
    scope: Str,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: per the contract above.
    let Some(read) = (unsafe { held(publication) }) else {
        return status::INVALID;
    };
    // SAFETY: the caller upholds the header's contract on `scope`.
    let Some(scope) = (unsafe { scope_text(scope) }) else {
        return status::MALFORMED;
    };
    let found = from_to(read.snapshot(), read.publication.topology.as_ref(), scope);
    let text = serde_json::to_string(&found).unwrap_or_default();
    // SAFETY: `out` and `out_len` per the contract.
    unsafe { refuse(&text, out, cap, out_len) };
    status::OK
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;
    use crate::ffi::publication::{xmip_publication_free_v1, xmip_publication_read_v1};
    use crate::ffi::text::borrow;

    #[test]
    fn the_export_has_the_shape_the_binding_declares() {
        let _: abi::operate::publication::FromToFn = xmip_publication_from_to_v1;
    }

    #[test]
    fn a_read_publications_send_port_says_where_its_work_came_from_and_went() {
        let cluster = configure::fixture::test_cluster();
        let (receiving, sending) = (cluster.node(0).name.clone(), cluster.node(2).name.clone());
        let text = format!(
            "node = \"{root}\"\n\
             [[records]]\nscope = \"{s}/send/Out\"\nstate = \"fine\"\n\
             [[subscriptions]]\nnode = \"{r}\"\nname = \"onward\"\nsend_ports = [\"Out\"]\n\
             [topology]\nsource = \"a roll\"\nobserved_unix_nanos = 1\n\
             [[topology.links]]\nid = \"in\"\nfrom = \"node/{receiving}/receive/In\"\n\
             to = \"node/{receiving}/process/onward\"\n\
             [[topology.links]]\nid = \"out\"\nfrom = \"node/{sending}/send\"\n\
             to = \"party/receiving/any-party\"\nprotocol = \"file\"\n",
            root = cluster.scope(),
            r = cluster.node_scope(0),
            s = cluster.node_scope(2),
        );
        let mut handle = core::ptr::null_mut();
        let mut buffer = vec![0u8; 8192];
        let mut length = 0usize;
        // SAFETY: every pointer is this test's own string or buffer, alive for the call.
        let read = unsafe {
            xmip_publication_read_v1(
                borrow(&text),
                &raw mut handle,
                buffer.as_mut_ptr(),
                buffer.len(),
                &raw mut length,
            )
        };
        assert_eq!(
            read,
            status::OK,
            "{}",
            String::from_utf8_lossy(&buffer[..length])
        );
        let scope = format!("{}/send/Out", cluster.node_scope(2));
        // SAFETY: every pointer is this test's own string or buffer, alive for the call.
        let code = unsafe {
            xmip_publication_from_to_v1(
                handle,
                borrow(&scope),
                buffer.as_mut_ptr(),
                buffer.len(),
                &raw mut length,
            )
        };
        // SAFETY: the handle is this test's own, freed once.
        unsafe { xmip_publication_free_v1(handle) };
        assert_eq!(code, status::OK);
        let found: Value = serde_json::from_slice(&buffer[..length]).expect("JSON");
        assert_eq!(found["from"], "In [".to_string() + &receiving + "]");
        assert_eq!(found["to"], "any-party over file");
        assert_eq!(found["unrouted"], "no Subscription");
        let kinds: Vec<&str> = found["hops"]
            .as_array()
            .expect("hops")
            .iter()
            .filter_map(|hop| hop["kind"].as_str())
            .collect();
        assert_eq!(
            kinds,
            [
                "Receive Location",
                "Subscription",
                "Send Port",
                "Receiving Party"
            ]
        );
    }
}
