//! `xmip_operate.h` section 7: the rules a surface calls instead of keeping
//! its own.
//!
//! The owner, 2026-09-24: *Code shall be uniquely placed, used by others,
//! who in turn have unique code used by others.* Scope containment, and the
//! node and stage a scope is on, are `observe::Scope`'s; a mood's word, its
//! color name, the rollup and the worst-first order are `observe::Health`'s
//! and `observe::Standing`'s; a
//! counted kind's word and the kind a stage counts are `observe::Counted`'s,
//! those forwarded by [`health`]; where a node's capability record sits is
//! `observe::capability`'s. The
//! stage words, their parse and the other facts of a stage, and a run's node
//! entry, are `node`'s, forwarded by [`node`]. The .NET surfaces cannot link
//! those crates, so the runtime's cdylib — the one native library they
//! already load — forwards each: one call into the owner per export, the
//! pointers read and written, and no rule of its own (ADR-0027 and ADR-0052,
//! amendments 2026-09-24).
//!
//! Nothing here reads the snapshot or a table; every export is pure and may
//! be called from any thread, before any node started.
//!
//! In `ffi/`, the one folder of the runtime that may hold unsafe code
//! (ADR-0050, refined 2026-09-25): a surface hands over where to write.
#![allow(unsafe_code)]

pub mod health;
pub mod node;

use abi::ffi::{Str, status};
use observe::Scope;

use crate::ffi::text::{borrow, scope_text};

/// The header's fill shape: up to `cap` entries into `out`, the true count
/// in `out_len`.
///
/// # Safety
/// `out` has room for `cap` entries; `out_len` is writable.
pub(crate) unsafe fn fill<'a>(
    items: impl Iterator<Item = &'a str>,
    out: *mut Str,
    cap: usize,
    out_len: *mut usize,
) {
    let mut count = 0usize;

    for item in items {
        if count < cap && !out.is_null() {
            // SAFETY: `count < cap` and `out` has room for `cap` entries.
            unsafe { out.add(count).write(borrow(item)) };
        }
        count += 1;
    }

    if !out_len.is_null() {
        // SAFETY: `out_len` is writable per the contract, and not null.
        unsafe { *out_len = count };
    }
}

/// A refusal sentence written as UTF-8 into the caller's buffer, its true
/// length in `said_len` whether or not it fit — the way `xmip_validate_v1`
/// writes its report.
///
/// # Safety
/// `said` has room for `cap` bytes; `said_len` is writable.
pub(crate) unsafe fn refuse(sentence: &str, said: *mut u8, cap: usize, said_len: *mut usize) {
    // SAFETY: per the contract above.
    unsafe { hand(sentence.as_bytes(), said, cap, said_len) };
}

/// Bytes written into the caller's buffer, their true length in `out_len`
/// whether or not they fit: a sentence's, or DER (section 19). A null
/// `out_len` is told nothing, and a null `out` is given nothing.
///
/// # Safety
/// `out` is null or has room for `cap` bytes; `out_len` is null or
/// writable.
pub(crate) unsafe fn hand(bytes: &[u8], out: *mut u8, cap: usize, out_len: *mut usize) {
    if !out_len.is_null() {
        // SAFETY: `out_len` is writable per the contract, and not null.
        unsafe { *out_len = bytes.len() };
    }
    if cap > 0 && !out.is_null() {
        // SAFETY: `out` has room for `cap` bytes; at most `cap` are copied.
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len().min(cap)) };
    }
}

/// `observe::Scope::contains`, forwarded.
///
/// # Safety
/// Both scopes point at their stated length of readable bytes;
/// `out_contains` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_scope_contains_v1(
    scope: Str,
    candidate: Str,
    out_contains: *mut u8,
) -> i32 {
    // SAFETY: the caller's contract is this export's, passed on whole.
    abi::guarded(status::PANIC, || unsafe {
        scope_contains(scope, candidate, out_contains)
    })
}

/// [`xmip_scope_contains_v1`] within its guard.
unsafe fn scope_contains(scope: Str, candidate: Str, out_contains: *mut u8) -> i32 {
    // SAFETY: the caller upholds the header's contract on both.
    let (Some(scope), Some(candidate)) = (unsafe { scope_text(scope) }, unsafe {
        scope_text(candidate)
    }) else {
        return status::MALFORMED;
    };

    let contains = Scope::new(scope).contains(Scope::new(candidate));

    // SAFETY: `out_contains` is writable per the contract.
    unsafe { *out_contains = u8::from(contains) };
    status::OK
}

/// `observe::wildcard::matches`, forwarded: the one wildcard, which every
/// surface's `ScopePattern` calls rather than keeping a copy (ADR-0052,
/// amendment 2026-09-19; moved to Rust 2026-09-29).
///
/// # Safety
/// Both strings point at their stated length of readable bytes;
/// `out_matches` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_scope_matches_v1(
    candidate: Str,
    pattern: Str,
    out_matches: *mut u8,
) -> i32 {
    // SAFETY: the caller's contract is this export's, passed on whole.
    abi::guarded(status::PANIC, || unsafe {
        scope_matches(candidate, pattern, out_matches)
    })
}

/// [`xmip_scope_matches_v1`] within its guard.
unsafe fn scope_matches(candidate: Str, pattern: Str, out_matches: *mut u8) -> i32 {
    // SAFETY: the caller upholds the header's contract on both.
    let (Some(candidate), Some(pattern)) = (unsafe { scope_text(candidate) }, unsafe {
        scope_text(pattern)
    }) else {
        return status::MALFORMED;
    };

    // SAFETY: `out_matches` is writable per the contract.
    unsafe { *out_matches = u8::from(observe::wildcard::matches(candidate, pattern)) };
    status::OK
}

/// `observe::run::shown`, forwarded: whether what a run made is shown, as
/// the run declared and the reader asked (ADR-0028, amendment 2026-09-30).
///
/// # Safety
/// `out_shown` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_run_shown_v1(hidden: u8, including: u8, out_shown: *mut u8) -> i32 {
    abi::guarded(status::PANIC, || {
        // SAFETY: `out_shown` is writable per the contract.
        unsafe { *out_shown = u8::from(observe::run::shown(hidden != 0, including != 0)) };
        status::OK
    })
}

/// `observe::Scope::segments`, forwarded. Each entry borrows from `scope`.
///
/// # Safety
/// `scope` points at its stated length of readable bytes; `out` has room for
/// `cap` entries; `out_len` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_scope_parts_v1(
    scope: Str,
    out: *mut Str,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: the caller's contract is this export's, passed on whole.
    abi::guarded(status::PANIC, || unsafe {
        scope_parts(scope, out, cap, out_len)
    })
}

/// [`xmip_scope_parts_v1`] within its guard.
unsafe fn scope_parts(scope: Str, out: *mut Str, cap: usize, out_len: *mut usize) -> i32 {
    // SAFETY: the caller upholds the header's contract on `scope`.
    let Some(scope) = (unsafe { scope_text(scope) }) else {
        return status::MALFORMED;
    };

    // SAFETY: per the contract above.
    unsafe { fill(Scope::new(scope).segments(), out, cap, out_len) };
    status::OK
}

/// `observe::Scope::node` and `observe::Scope::stage`, forwarded: the node a
/// scope is on, borrowed from `scope`, and its stage's static word, each
/// empty where there is none.
///
/// # Safety
/// `scope` points at its stated length of readable bytes; `out_node` and
/// `out_stage` are writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_scope_node_v1(
    scope: Str,
    out_node: *mut Str,
    out_stage: *mut Str,
) -> i32 {
    // SAFETY: the caller's contract is this export's, passed on whole.
    abi::guarded(status::PANIC, || unsafe {
        scope_node(scope, out_node, out_stage)
    })
}

/// [`xmip_scope_node_v1`] within its guard.
unsafe fn scope_node(scope: Str, out_node: *mut Str, out_stage: *mut Str) -> i32 {
    // SAFETY: the caller upholds the header's contract on `scope`.
    let Some(scope) = (unsafe { scope_text(scope) }) else {
        return status::MALFORMED;
    };
    let scope = Scope::new(scope);

    // SAFETY: both outs are writable per the contract.
    unsafe {
        out_node.write(scope.node().map_or(Str::empty(), borrow));
        out_stage.write(
            scope
                .stage()
                .map_or(Str::empty(), |stage| borrow(stage.name())),
        );
    }
    status::OK
}

/// `observe::capability::declared`, forwarded: the node a capability record
/// sits beneath, and what its evidence declares or why it is refused.
///
/// # Safety
/// `scope` and `evidence` point at their stated length of readable bytes;
/// `roles` has room for `cap` entries and `refusal` for `refusal_cap`
/// bytes; every other out is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_capability_published_v1(
    scope: Str,
    evidence: Str,
    out_node: *mut Str,
    roles: *mut Str,
    cap: usize,
    out_len: *mut usize,
    out_online: *mut u8,
    refusal: *mut u8,
    refusal_cap: usize,
    refusal_len: *mut usize,
) -> i32 {
    // SAFETY: the caller's contract is this export's, passed on whole.
    abi::guarded(status::PANIC, || unsafe {
        capability_published(
            scope,
            evidence,
            out_node,
            roles,
            cap,
            out_len,
            out_online,
            refusal,
            refusal_cap,
            refusal_len,
        )
    })
}

/// [`xmip_capability_published_v1`] within its guard.
#[expect(clippy::too_many_arguments, reason = "the export's own parameters")]
unsafe fn capability_published(
    scope: Str,
    evidence: Str,
    out_node: *mut Str,
    roles: *mut Str,
    cap: usize,
    out_len: *mut usize,
    out_online: *mut u8,
    refusal: *mut u8,
    refusal_cap: usize,
    refusal_len: *mut usize,
) -> i32 {
    // SAFETY: the caller upholds the header's contract on both.
    let (Some(scope), Some(evidence)) = (unsafe { scope_text(scope) }, unsafe {
        scope_text(evidence)
    }) else {
        return status::MALFORMED;
    };
    let Some((node, said)) = observe::capability::declared(scope, evidence) else {
        return status::NOT_FOUND;
    };

    // SAFETY: per the contract above.
    unsafe {
        out_node.write(borrow(node));
        match node::write_declared(said, roles, cap, out_len, refusal, refusal_cap, refusal_len) {
            Some(online) => {
                *out_online = u8::from(online);
                status::OK
            }
            None => status::INVALID,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_null_length_or_buffer_is_written_nothing_and_never_dereferenced() {
        // SAFETY: both nulls are what the test hands over; nothing is written.
        unsafe { hand(b"said", core::ptr::null_mut(), 4, core::ptr::null_mut()) };
        let mut length = 0usize;
        // SAFETY: a null buffer, and a writable length.
        unsafe { hand(b"said", core::ptr::null_mut(), 4, &raw mut length) };
        assert_eq!(length, 4, "the true length, with nothing copied");
        // SAFETY: a null length and a null buffer of no room.
        unsafe {
            fill(
                ["a"].into_iter(),
                core::ptr::null_mut(),
                1,
                core::ptr::null_mut(),
            )
        };
    }

    /// Read a `Str` an export handed back.
    fn text(value: Str) -> String {
        if value.ptr.is_null() {
            return String::new();
        }

        // SAFETY: the export promises `len` readable bytes.
        let bytes = unsafe { core::slice::from_raw_parts(value.ptr, value.len) };

        String::from_utf8(bytes.to_vec()).expect("UTF-8")
    }

    fn contains(scope: &str, candidate: &str) -> bool {
        let mut out = 9u8;
        // SAFETY: both borrow live strings; `out` is writable.
        let code =
            unsafe { xmip_scope_contains_v1(borrow(scope), borrow(candidate), &raw mut out) };

        assert_eq!(code, status::OK);
        out == 1
    }

    #[test]
    fn the_wildcard_crosses_as_the_one_rule() {
        let matches = |candidate: &str, pattern: &str| {
            let mut out = 9u8;
            // SAFETY: both borrow live strings; `out` is writable.
            let code =
                unsafe { xmip_scope_matches_v1(borrow(candidate), borrow(pattern), &raw mut out) };
            assert_eq!(code, status::OK);
            out == 1
        };

        let cluster = configure::fixture::test_cluster();
        let (node, initial) = (cluster.node_scope(0), &cluster.node(0).name[..1]);
        let pattern = format!("{}/node/{}*", cluster.name, initial.to_lowercase());
        assert!(matches(&node, &pattern));
        assert!(!matches(&node, &format!("{}/node", cluster.scope())));
        assert!(matches("", "*"));
    }

    #[test]
    fn a_hidden_run_crosses_as_the_one_rule() {
        let shown = |hidden: u8, including: u8| {
            let mut out = 9u8;
            // SAFETY: `out` is writable.
            let code = unsafe { xmip_run_shown_v1(hidden, including, &raw mut out) };
            assert_eq!(code, status::OK);
            out
        };

        assert_eq!(
            [shown(0, 0), shown(0, 1), shown(1, 0), shown(1, 1)],
            [1, 1, 0, 1]
        );
    }

    fn parts(scope: &str) -> (i32, Vec<String>) {
        let mut out = [Str::empty(); 8];
        let mut len = 0usize;
        // SAFETY: `out` has 8 entries; `len` is writable.
        let code = unsafe { xmip_scope_parts_v1(borrow(scope), out.as_mut_ptr(), 8, &raw mut len) };

        (
            code,
            out[..len.min(8)].iter().map(|part| text(*part)).collect(),
        )
    }

    #[test]
    fn every_export_has_the_shape_the_binding_declares() {
        use abi::operate::rule;

        // A signature that drifted from xmip-core-abi's fails to compile here.
        let _: rule::ScopeContainsFn = xmip_scope_contains_v1;
        let _: rule::ScopeMatchesFn = xmip_scope_matches_v1;
        let _: rule::RunShownFn = xmip_run_shown_v1;
        let _: rule::ScopePartsFn = xmip_scope_parts_v1;
        let _: rule::ScopeNodeFn = xmip_scope_node_v1;
        let _: rule::CapabilityPublishedFn = xmip_capability_published_v1;
    }

    #[test]
    fn a_capability_record_crosses_as_observe_reads_it() {
        let evidence = ::node::Capability::of(&[::node::NodeRole::Sending])
            .with_online(true)
            .evidence();
        let published = |scope: &str, evidence: &str| {
            let (mut node, mut roles) =
                (Str::empty(), [Str::empty(); ::node::NodeRole::WORDS.len()]);
            let (mut len, mut online, mut said_len) = (0usize, 9u8, 0usize);
            let mut said = [0u8; 256];
            // SAFETY: every buffer has the capacity passed; every out writable.
            let code = unsafe {
                xmip_capability_published_v1(
                    borrow(scope),
                    borrow(evidence),
                    &raw mut node,
                    roles.as_mut_ptr(),
                    7,
                    &raw mut len,
                    &raw mut online,
                    said.as_mut_ptr(),
                    said.len(),
                    &raw mut said_len,
                )
            };
            let words: Vec<String> = roles[..len.min(::node::NodeRole::WORDS.len())]
                .iter()
                .map(|s| text(*s))
                .collect();
            let sentence = String::from_utf8(said[..said_len.min(256)].to_vec()).expect("UTF-8");
            (code, text(node), words, online, sentence)
        };

        let cluster = configure::fixture::test_cluster();
        let sender = &cluster.with_role("sending").name;
        let at = format!("{}/{sender}", cluster.scope());
        let capability = format!("{at}/capability");

        let (code, node, words, online, said) = published(&capability, &evidence);
        assert_eq!((code, &node, online), (status::OK, sender, 1));
        assert_eq!((words, said), (vec!["sending".to_string()], String::new()));

        let (code, node, _, _, said) = published(&capability, "declares relay;");
        assert_eq!((code, &node), (status::INVALID, sender));
        assert!(said.starts_with("REFUSED"), "{said}");

        assert_eq!(
            published(&format!("{at}/receive"), &evidence).0,
            status::NOT_FOUND
        );
    }

    #[test]
    fn containment_is_observe_scope_and_nothing_else() {
        let cluster = configure::fixture::test_cluster();
        let (name, scope) = (&cluster.name, cluster.scope());
        for (scope, candidate) in [
            (scope.clone(), format!("{scope}/receive/a")),
            (scope.clone(), format!("{scope}x")),
            (String::new(), scope.clone()),
            (
                format!("xmip://localhost/{name}"),
                format!("{scope}/receive"),
            ),
            (format!("XMIP:///{name}"), scope.clone()),
        ] {
            assert_eq!(
                contains(&scope, &candidate),
                Scope::new(&scope).contains(Scope::new(&candidate)),
                "{scope} / {candidate}"
            );
        }
    }

    #[test]
    fn the_parts_are_observe_scope_segments_borrowed_from_the_input() {
        let node = configure::fixture::test_cluster().node(0).name.clone();
        let (code, read) = parts(&format!("xmip://localhost:9000/{node}/receive/orders/"));

        assert_eq!(code, status::OK);
        assert_eq!(read, [node.as_str(), "receive", "orders"]);
        assert_eq!(parts("xmip:///").1, [] as [String; 0]);
    }

    #[test]
    fn the_node_and_stage_are_observe_scopes_and_the_cluster_is_none() {
        let node = |scope: &str| {
            let (mut node, mut stage) = (Str::empty(), Str::empty());
            // SAFETY: `scope` borrows a live string; both outs are writable.
            let code = unsafe { xmip_scope_node_v1(borrow(scope), &raw mut node, &raw mut stage) };
            assert_eq!(code, status::OK);
            (text(node), text(stage))
        };

        let cluster = configure::fixture::test_cluster();
        let (at, first) = (cluster.scope(), cluster.node_scope(0));
        let received = format!("{first}/receive/tcp");
        for scope in [
            received.clone(),
            format!("{}/process/x", cluster.node_scope(1)),
            format!("{at}/round-trip/send/tcp/json"),
            format!("{at}/node"),
            "xmip:///".to_string(),
        ] {
            let read = Scope::new(&scope);
            assert_eq!(
                node(&scope),
                (
                    read.node().unwrap_or_default().to_string(),
                    read.stage().map_or("", ::node::Stage::name).to_string()
                ),
                "{scope}"
            );
        }
        assert_eq!(
            node(&received),
            (cluster.node(0).name.clone(), "receive".to_string())
        );
        assert_eq!(node(&format!("{at}/x")), (String::new(), String::new()));
    }

    #[test]
    fn a_short_buffer_is_told_the_true_count() {
        let mut len = 0usize;
        let scope = format!("{}/b/c", configure::fixture::test_cluster().scope());
        // SAFETY: `cap` is 0, so `out` is never written.
        let code =
            unsafe { xmip_scope_parts_v1(borrow(&scope), core::ptr::null_mut(), 0, &raw mut len) };

        assert_eq!(code, status::OK);
        assert_eq!(len, 3);
    }
}
