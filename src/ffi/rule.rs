//! `xmip_operate.h` section 7: the rules a surface calls instead of keeping
//! its own.
//!
//! The owner, 2026-09-24: *Code shall be uniquely placed, used by others,
//! whom in turn has unique code used by others.* Scope containment, and the
//! node and stage a scope is on, are `observe::Scope`'s; a mood's word, its
//! color name, the rollup and the worst-first order are `observe::Health`'s
//! and `observe::Standing`'s; a
//! counted kind's word and the kind a stage counts are `observe::Counted`'s;
//! where a node's capability record sits is `observe::capability`'s. The
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

pub mod node;

use abi::ffi::{Str, status};
use abi::operate::HealthEntry;
use observe::{Counted, Health, Scope, Standing};

use crate::ffi::operate::{borrow, scope_text};
use crate::wire::{from_wire_counted, from_wire_health, wire_counted, wire_health};

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
        if count < cap {
            // SAFETY: `count < cap` and `out` has room for `cap` entries.
            unsafe { out.add(count).write(borrow(item)) };
        }
        count += 1;
    }

    // SAFETY: `out_len` is writable per the contract.
    unsafe { *out_len = count };
}

/// A refusal sentence written as UTF-8 into the caller's buffer, its true
/// length in `said_len` whether or not it fit — the way `xmip_validate_v1`
/// writes its report.
///
/// # Safety
/// `said` has room for `cap` bytes; `said_len` is writable.
pub(crate) unsafe fn refuse(sentence: &str, said: *mut u8, cap: usize, said_len: *mut usize) {
    let bytes = sentence.as_bytes();

    // SAFETY: per the contract above; at most `cap` bytes are copied.
    unsafe {
        *said_len = bytes.len();
        if cap > 0 {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), said, bytes.len().min(cap));
        }
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

/// A mood's static text, by the owner's function.
///
/// # Safety
/// `out` is writable.
unsafe fn health_text(value: i32, text: fn(Health) -> &'static str, out: *mut Str) -> i32 {
    let Some(health) = from_wire_health(value) else {
        return status::INVALID;
    };

    // SAFETY: `out` is writable per the contract.
    unsafe { out.write(borrow(text(health))) };
    status::OK
}

/// `observe::Health::word`, forwarded. Static.
///
/// # Safety
/// `out` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_health_word_v1(health: i32, out: *mut Str) -> i32 {
    // SAFETY: per the contract above.
    unsafe { health_text(health, Health::word, out) }
}

/// `observe::Health::color`, forwarded. Static.
///
/// # Safety
/// `out` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_health_color_v1(health: i32, out: *mut Str) -> i32 {
    // SAFETY: per the contract above.
    unsafe { health_text(health, Health::color, out) }
}

/// `observe::Health::named`, forwarded.
///
/// # Safety
/// `word` points at its stated length of readable bytes; `out` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_health_named_v1(word: Str, out: *mut i32) -> i32 {
    // SAFETY: the caller upholds the header's contract on `word`.
    let Some(word) = (unsafe { scope_text(word) }) else {
        return status::MALFORMED;
    };
    let Some(health) = Health::named(word) else {
        return status::NOT_FOUND;
    };

    // SAFETY: `out` is writable per the contract.
    unsafe { *out = wire_health(health) };
    status::OK
}

/// `observe::Health::rolled`, forwarded.
///
/// # Safety
/// `out` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_health_rolled_v1(health: i32, out: *mut i32) -> i32 {
    let Some(health) = from_wire_health(health) else {
        return status::INVALID;
    };

    // SAFETY: `out` is writable per the contract.
    unsafe { *out = wire_health(health.rolled()) };
    status::OK
}

/// `observe::Counted::word`, forwarded. Static.
///
/// # Safety
/// `out` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_counted_word_v1(counted: i32, out: *mut Str) -> i32 {
    let Some(counted) = from_wire_counted(counted) else {
        return status::INVALID;
    };

    // SAFETY: `out` is writable per the contract.
    unsafe { out.write(borrow(counted.word())) };
    status::OK
}

/// `observe::Counted::at`, forwarded, for the stage a word names.
///
/// # Safety
/// `stage` points at its stated length of readable bytes; `out` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_stage_counted_v1(stage: Str, out: *mut i32) -> i32 {
    // SAFETY: the caller upholds the header's contract on `stage`.
    let Some(word) = (unsafe { scope_text(stage) }) else {
        return status::MALFORMED;
    };
    let Some(stage) = ::node::Stage::named(word) else {
        return status::NOT_FOUND;
    };

    // SAFETY: `out` is writable per the contract.
    unsafe { *out = wire_counted(Counted::at(stage)) };
    status::OK
}

/// `observe::capability::declared`, forwarded: the node a capability record
/// sits beneath, and what its evidence declares or why it is refused.
///
/// # Safety
/// `scope` and `evidence` point at their stated length of readable bytes;
/// `stages` has room for `cap` entries and `refusal` for `refusal_cap`
/// bytes; every other out is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_capability_published_v1(
    scope: Str,
    evidence: Str,
    out_node: *mut Str,
    stages: *mut Str,
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
        match node::write_declared(
            said,
            stages,
            cap,
            out_len,
            refusal,
            refusal_cap,
            refusal_len,
        ) {
            Some(online) => {
                *out_online = u8::from(online);
                status::OK
            }
            None => status::INVALID,
        }
    }
}

/// `observe::Standing::worst_first`, forwarded: `out_order` receives the
/// entries' positions worst first.
///
/// # Safety
/// `entries` points at `len` entries whose scopes point at their stated
/// length of readable bytes; `out_order` has room for `len` indices.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_health_order_v1(
    entries: *const HealthEntry,
    len: usize,
    out_order: *mut usize,
) -> i32 {
    if len == 0 {
        return status::OK;
    }
    if entries.is_null() || out_order.is_null() {
        return status::INVALID;
    }

    // SAFETY: `entries` points at `len` entries per the contract.
    let entries = unsafe { core::slice::from_raw_parts(entries, len) };
    let mut standings = Vec::with_capacity(len);

    for entry in entries {
        let Some(health) = from_wire_health(entry.health) else {
            return status::INVALID;
        };
        // SAFETY: the caller upholds the header's contract on each scope.
        let Some(scope) = (unsafe { scope_text(entry.scope) }) else {
            return status::MALFORMED;
        };

        standings.push(Standing {
            health,
            severity: entry.severity,
            scope,
        });
    }

    let order = Standing::worst_first(&standings);

    // SAFETY: `out_order` has room for `len` indices, and `order` holds `len`.
    unsafe { core::ptr::copy_nonoverlapping(order.as_ptr(), out_order, len) };
    status::OK
}

#[cfg(test)]
mod tests {
    use super::*;
    use abi::operate::health;

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

    fn entry(health: i32, severity: u8, scope: &str) -> HealthEntry {
        HealthEntry {
            scope: borrow(scope),
            health,
            severity,
            evidence: Str::empty(),
            observed_unix_nanos: 0,
        }
    }

    #[test]
    fn every_export_has_the_shape_the_binding_declares() {
        use abi::operate::rule;

        // A signature that drifted from xmip-core-abi's fails to compile here.
        let _: rule::ScopeContainsFn = xmip_scope_contains_v1;
        let _: rule::ScopePartsFn = xmip_scope_parts_v1;
        let _: rule::ScopeNodeFn = xmip_scope_node_v1;
        let _: rule::HealthTextFn = xmip_health_word_v1;
        let _: rule::HealthTextFn = xmip_health_color_v1;
        let _: rule::HealthNamedFn = xmip_health_named_v1;
        let _: rule::HealthOrderFn = xmip_health_order_v1;
        let _: rule::HealthRolledFn = xmip_health_rolled_v1;
        let _: rule::CountedWordFn = xmip_counted_word_v1;
        let _: rule::StageCountedFn = xmip_stage_counted_v1;
        let _: rule::CapabilityPublishedFn = xmip_capability_published_v1;
    }

    #[test]
    fn a_parent_rolls_up_as_observe_says_and_a_stranger_is_refused() {
        for mood in Health::ALL {
            let mut out = -1;
            // SAFETY: `out` is writable.
            let code = unsafe { xmip_health_rolled_v1(wire_health(mood), &raw mut out) };

            assert_eq!(code, status::OK);
            assert_eq!(out, wire_health(mood.rolled()));
        }
        let mut out = -1;
        // SAFETY: `out` is writable.
        assert_eq!(
            unsafe { xmip_health_rolled_v1(99, &raw mut out) },
            status::INVALID
        );
    }

    #[test]
    fn every_counted_kind_crosses_with_its_word_and_each_stage_with_its_kind() {
        for counted in Counted::ALL {
            let mut word = Str::empty();
            // SAFETY: `word` is writable.
            let code = unsafe { xmip_counted_word_v1(wire_counted(counted), &raw mut word) };

            assert_eq!(code, status::OK);
            assert_eq!(text(word), counted.word());
        }
        for stage in ::node::Stage::ALL {
            let mut out = -1;
            // SAFETY: the word is static; `out` is writable.
            let code = unsafe { xmip_stage_counted_v1(borrow(stage.name()), &raw mut out) };

            assert_eq!(code, status::OK);
            assert_eq!(out, wire_counted(Counted::at(stage)));
        }
        let mut out = -1;
        // SAFETY: as above.
        assert_eq!(
            unsafe { xmip_stage_counted_v1(borrow("capability"), &raw mut out) },
            status::NOT_FOUND
        );
    }

    #[test]
    fn a_capability_record_crosses_as_observe_reads_it() {
        let evidence = ::node::Capability::of(&[::node::Stage::Send])
            .with_online(true)
            .evidence();
        let published = |scope: &str, evidence: &str| {
            let (mut node, mut stages) = (Str::empty(), [Str::empty(); 3]);
            let (mut len, mut online, mut said_len) = (0usize, 9u8, 0usize);
            let mut said = [0u8; 256];
            // SAFETY: every buffer has the capacity passed; every out writable.
            let code = unsafe {
                xmip_capability_published_v1(
                    borrow(scope),
                    borrow(evidence),
                    &raw mut node,
                    stages.as_mut_ptr(),
                    3,
                    &raw mut len,
                    &raw mut online,
                    said.as_mut_ptr(),
                    said.len(),
                    &raw mut said_len,
                )
            };
            let words: Vec<String> = stages[..len.min(3)].iter().map(|s| text(*s)).collect();
            let sentence = String::from_utf8(said[..said_len.min(256)].to_vec()).expect("UTF-8");
            (code, text(node), words, online, sentence)
        };

        let (code, node, words, online, said) = published("xmip:///C1/alpha/capability", &evidence);
        assert_eq!((code, node.as_str(), online), (status::OK, "alpha", 1));
        assert_eq!((words, said), (vec!["send".to_string()], String::new()));

        let (code, node, _, _, said) = published("xmip:///C1/alpha/capability", "declares relay;");
        assert_eq!((code, node.as_str()), (status::INVALID, "alpha"));
        assert!(said.starts_with("REFUSED"), "{said}");

        assert_eq!(
            published("xmip:///C1/alpha/receive", &evidence).0,
            status::NOT_FOUND
        );
    }

    #[test]
    fn many_are_ordered_as_standing_orders_them() {
        let entries = [
            entry(health::FINE, 0, "xmip:///a"),
            entry(health::DONE, 60, "xmip:///d"),
            entry(health::HOLDING, 0, "xmip:///h"),
            entry(health::DONE, 90, "xmip:///e"),
        ];
        let mut order = [9usize; 4];

        // SAFETY: four live entries; `order` has room for four.
        let code = unsafe { xmip_health_order_v1(entries.as_ptr(), 4, order.as_mut_ptr()) };

        assert_eq!(code, status::OK);
        assert_eq!(order, [2, 3, 1, 0]);

        let unknown = [entry(42, 0, "xmip:///a")];
        // SAFETY: one live entry; `order` has room for it.
        let refused = unsafe { xmip_health_order_v1(unknown.as_ptr(), 1, order.as_mut_ptr()) };
        assert_eq!(refused, status::INVALID);
        // SAFETY: nothing is read or written for none.
        let none = unsafe { xmip_health_order_v1(core::ptr::null(), 0, core::ptr::null_mut()) };
        assert_eq!(none, status::OK);
    }

    #[test]
    fn containment_is_observe_scope_and_nothing_else() {
        for (scope, candidate) in [
            ("xmip:///n", "xmip:///n/receive/a"),
            ("xmip:///n", "xmip:///nx"),
            ("", "xmip:///n"),
            ("xmip://edge-01/n", "xmip:///n/receive"),
            ("XMIP:///C1", "xmip:///C1"),
        ] {
            assert_eq!(
                contains(scope, candidate),
                Scope::new(scope).contains(Scope::new(candidate)),
                "{scope} / {candidate}"
            );
        }
    }

    #[test]
    fn the_parts_are_observe_scope_segments_borrowed_from_the_input() {
        let (code, read) = parts("xmip://lab:9000/edge-01/receive/orders/");

        assert_eq!(code, status::OK);
        assert_eq!(read, ["edge-01", "receive", "orders"]);
        assert!(parts("xmip:///").1.is_empty());
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

        for scope in [
            "xmip:///C1/node/alpha/receive/tcp",
            "xmip:///C1/node/send/process/x",
            "xmip:///C1/round-trip/send/tcp/json",
            "xmip:///C1/node",
            "xmip:///",
        ] {
            let read = Scope::new(scope);
            assert_eq!(
                node(scope),
                (
                    read.node().unwrap_or_default().to_string(),
                    read.stage().map_or("", ::node::Stage::name).to_string()
                ),
                "{scope}"
            );
        }
        assert_eq!(
            node("xmip:///C1/node/alpha/receive/tcp"),
            ("alpha".to_string(), "receive".to_string())
        );
        assert_eq!(node("xmip:///C1/x"), (String::new(), String::new()));
    }

    #[test]
    fn a_short_buffer_is_told_the_true_count() {
        let mut len = 0usize;
        // SAFETY: `cap` is 0, so `out` is never written.
        let code = unsafe {
            xmip_scope_parts_v1(
                borrow("xmip:///a/b/c"),
                core::ptr::null_mut(),
                0,
                &raw mut len,
            )
        };

        assert_eq!(code, status::OK);
        assert_eq!(len, 3);
    }

    #[test]
    fn every_mood_crosses_with_the_word_and_color_observe_gives_it() {
        for mood in Health::ALL {
            let (mut word, mut color, mut back) = (Str::empty(), Str::empty(), -1);
            // SAFETY: every out is writable.
            unsafe {
                assert_eq!(
                    xmip_health_word_v1(wire_health(mood), &raw mut word),
                    status::OK
                );
                assert_eq!(
                    xmip_health_color_v1(wire_health(mood), &raw mut color),
                    status::OK
                );
                assert_eq!(xmip_health_named_v1(word, &raw mut back), status::OK);
            }
            assert_eq!(text(word), mood.word());
            assert_eq!(text(color), mood.color());
            assert_eq!(back, wire_health(mood));
        }
    }

    #[test]
    fn an_unknown_mood_or_word_is_refused() {
        let (mut out, mut back) = (Str::empty(), -1);
        // SAFETY: every out is writable.
        unsafe {
            assert_eq!(xmip_health_word_v1(99, &raw mut out), status::INVALID);
            assert_eq!(xmip_health_color_v1(-1, &raw mut out), status::INVALID);
            assert_eq!(
                xmip_health_named_v1(borrow("Fine"), &raw mut back),
                status::NOT_FOUND
            );
        }
    }
}
