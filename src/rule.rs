//! `xmip_operate.h` section 7: the rules a surface calls instead of keeping
//! its own.
//!
//! The owner, 2026-09-24: *Code shall be uniquely placed, used by others,
//! whom in turn has unique code used by others.* Scope containment is
//! `observe::Scope`'s, the stage words and their parse are `node::Stage`'s,
//! and a mood's word, its color name and the worst-first order are
//! `observe::Health`'s and `observe::Standing`'s. The .NET surfaces cannot
//! link those crates, so the runtime's cdylib — the one native library they
//! already load — forwards each: one call into the owner per export, the
//! pointers read and written, and no rule of its own (ADR-0027 and ADR-0052,
//! amendments 2026-09-24).
//!
//! Nothing here reads the snapshot or a table; every export is pure and may
//! be called from any thread, before any node started.
//!
//! One of five files in this crate that dereference a pointer, for the reason
//! `operate.rs` gives: a surface hands over where to write.
#![allow(unsafe_code)]

use abi::ffi::{Str, status};
use abi::operate::HealthEntry;
use node::Stage;
use observe::{Health, Scope, Standing};

use crate::operate::scope_text;
use crate::wire::{from_wire_health, wire_health};

/// A static or borrowed `&str` as the header's `XmipStr`.
fn borrow(text: &str) -> Str {
    Str {
        ptr: text.as_ptr(),
        len: text.len(),
    }
}

/// The header's fill shape: up to `cap` entries into `out`, the true count
/// in `out_len`.
///
/// # Safety
/// `out` has room for `cap` entries; `out_len` is writable.
unsafe fn fill<'a>(
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

/// `node::Stage::WORDS`, forwarded. Static.
///
/// # Safety
/// `out` has room for `cap` entries; `out_len` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_stage_words_v1(
    out: *mut Str,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: per the contract above.
    unsafe { fill(Stage::WORDS.into_iter(), out, cap, out_len) };
    status::OK
}

/// `node::Stage::declared`, forwarded: the stages in the fill shape, or
/// `XMIP_E_INVALID` and the refusal written as UTF-8.
///
/// # Safety
/// `declared` points at its stated length of readable bytes; `stages` has
/// room for `cap` entries and `refusal` for `refusal_cap` bytes; `out_len`
/// and `refusal_len` are writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_stage_declared_v1(
    declared: Str,
    stages: *mut Str,
    cap: usize,
    out_len: *mut usize,
    refusal: *mut u8,
    refusal_cap: usize,
    refusal_len: *mut usize,
) -> i32 {
    // SAFETY: the caller upholds the header's contract on `declared`.
    let Some(declared) = (unsafe { scope_text(declared) }) else {
        return status::MALFORMED;
    };

    match Stage::declared(declared) {
        Ok(read) => {
            // SAFETY: per the contract above.
            unsafe {
                fill(read.into_iter().map(Stage::name), stages, cap, out_len);
                *refusal_len = 0;
            }
            status::OK
        }
        Err(said) => {
            let bytes = said.as_bytes();

            // SAFETY: per the contract above; at most `refusal_cap` bytes are
            // copied into `refusal`.
            unsafe {
                *out_len = 0;
                *refusal_len = bytes.len();
                if refusal_cap > 0 {
                    let n = bytes.len().min(refusal_cap);
                    core::ptr::copy_nonoverlapping(bytes.as_ptr(), refusal, n);
                }
            }
            status::INVALID
        }
    }
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

    fn declared(raw: &str) -> (i32, Vec<String>, String) {
        let mut stages = [Str::empty(); 3];
        let mut len = 0usize;
        let mut refusal = [0u8; 256];
        let mut refusal_len = 0usize;
        // SAFETY: the buffers have the capacities passed; lengths writable.
        let code = unsafe {
            xmip_stage_declared_v1(
                borrow(raw),
                stages.as_mut_ptr(),
                stages.len(),
                &raw mut len,
                refusal.as_mut_ptr(),
                refusal.len(),
                &raw mut refusal_len,
            )
        };
        let words = stages[..len.min(3)]
            .iter()
            .map(|word| text(*word))
            .collect();
        let said = String::from_utf8(refusal[..refusal_len.min(256)].to_vec()).expect("UTF-8");

        (code, words, said)
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
        let _: rule::StageWordsFn = xmip_stage_words_v1;
        let _: rule::StageDeclaredFn = xmip_stage_declared_v1;
        let _: rule::HealthTextFn = xmip_health_word_v1;
        let _: rule::HealthTextFn = xmip_health_color_v1;
        let _: rule::HealthNamedFn = xmip_health_named_v1;
        let _: rule::HealthOrderFn = xmip_health_order_v1;
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
    fn the_stage_words_are_the_node_crates() {
        let mut out = [Str::empty(); 3];
        let mut len = 0usize;
        // SAFETY: `out` has 3 entries.
        let code = unsafe { xmip_stage_words_v1(out.as_mut_ptr(), 3, &raw mut len) };

        assert_eq!(code, status::OK);
        assert_eq!(out.map(text), Stage::WORDS);
    }

    #[test]
    fn a_declaration_reads_as_stage_declared_says_and_a_refusal_crosses_whole() {
        assert_eq!(
            declared(" send + receive "),
            (
                status::OK,
                vec!["receive".into(), "send".into()],
                String::new()
            )
        );
        assert_eq!(declared(""), (status::OK, vec![], String::new()));

        let (code, words, said) = declared("Send+relay");
        assert_eq!(code, status::INVALID);
        assert!(words.is_empty());
        assert_eq!(said, Stage::declared("Send+relay").expect_err("refused"));
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
