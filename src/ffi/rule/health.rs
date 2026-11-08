//! `xmip_operate.h` section 7, a mood and a count: a mood's word, its color
//! name, its parse and the rollup, and the worst-first order are
//! `observe::Health`'s and `observe::Standing`'s; a counted kind's word and
//! the kind a stage counts are `observe::Counted`'s. Forwarded, one call
//! into the owner per export, and no rule of its own (`super`).
#![allow(unsafe_code)]

use abi::ffi::{Str, status};
use abi::operate::HealthEntry;
use observe::{Counted, Health, Standing};

use crate::ffi::text::{borrow, scope_text};
use crate::wire::{from_wire_counted, from_wire_health, wire_counted, wire_health};

/// A mood's static text, by the owner's function: the whole of the two
/// exports that call it, so their outermost frame and their panic guard.
///
/// # Safety
/// `out` is writable.
unsafe fn health_text(value: i32, text: fn(Health) -> &'static str, out: *mut Str) -> i32 {
    abi::guarded(status::PANIC, || {
        let Some(health) = from_wire_health(value) else {
            return status::INVALID;
        };

        // SAFETY: `out` is writable per the contract.
        unsafe { out.write(borrow(text(health))) };
        status::OK
    })
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
    // SAFETY: the caller's contract is this export's, passed on whole.
    abi::guarded(status::PANIC, || unsafe { health_named(word, out) })
}

/// [`xmip_health_named_v1`] within its guard.
unsafe fn health_named(word: Str, out: *mut i32) -> i32 {
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
    abi::guarded(status::PANIC, || {
        let Some(health) = from_wire_health(health) else {
            return status::INVALID;
        };

        // SAFETY: `out` is writable per the contract.
        unsafe { *out = wire_health(health.rolled()) };
        status::OK
    })
}

/// `observe::Counted::word`, forwarded. Static.
///
/// # Safety
/// `out` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_counted_word_v1(counted: i32, out: *mut Str) -> i32 {
    abi::guarded(status::PANIC, || {
        let Some(counted) = from_wire_counted(counted) else {
            return status::INVALID;
        };

        // SAFETY: `out` is writable per the contract.
        unsafe { out.write(borrow(counted.word())) };
        status::OK
    })
}

/// `observe::Counted::at`, forwarded, for the stage a word names.
///
/// # Safety
/// `stage` points at its stated length of readable bytes; `out` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_stage_counted_v1(stage: Str, out: *mut i32) -> i32 {
    // SAFETY: the caller's contract is this export's, passed on whole.
    abi::guarded(status::PANIC, || unsafe { stage_counted(stage, out) })
}

/// [`xmip_stage_counted_v1`] within its guard.
unsafe fn stage_counted(stage: Str, out: *mut i32) -> i32 {
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
    // SAFETY: the caller's contract is this export's, passed on whole.
    abi::guarded(status::PANIC, || unsafe {
        health_order(entries, len, out_order)
    })
}

/// [`xmip_health_order_v1`] within its guard.
unsafe fn health_order(entries: *const HealthEntry, len: usize, out_order: *mut usize) -> i32 {
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
        let _: rule::HealthTextFn = xmip_health_word_v1;
        let _: rule::HealthTextFn = xmip_health_color_v1;
        let _: rule::HealthNamedFn = xmip_health_named_v1;
        let _: rule::HealthOrderFn = xmip_health_order_v1;
        let _: rule::HealthRolledFn = xmip_health_rolled_v1;
        let _: rule::CountedWordFn = xmip_counted_word_v1;
        let _: rule::StageCountedFn = xmip_stage_counted_v1;
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
    fn many_are_ordered_as_standing_orders_them() {
        let at = configure::fixture::test_cluster().node_scope(0);
        let scopes = ["a", "d", "h", "e"].map(|leaf| format!("{at}/receive/{leaf}"));
        let entries = [
            entry(health::FINE, 0, &scopes[0]),
            entry(health::DONE, 60, &scopes[1]),
            entry(health::HOLDING, 0, &scopes[2]),
            entry(health::DONE, 90, &scopes[3]),
        ];
        let mut order = [9usize; 4];

        // SAFETY: four live entries; `order` has room for four.
        let code = unsafe { xmip_health_order_v1(entries.as_ptr(), 4, order.as_mut_ptr()) };

        assert_eq!(code, status::OK);
        assert_eq!(order, [2, 3, 1, 0]);

        let unknown = [entry(42, 0, &scopes[0])];
        // SAFETY: one live entry; `order` has room for it.
        let refused = unsafe { xmip_health_order_v1(unknown.as_ptr(), 1, order.as_mut_ptr()) };
        assert_eq!(refused, status::INVALID);
        // SAFETY: nothing is read or written for none.
        let none = unsafe { xmip_health_order_v1(core::ptr::null(), 0, core::ptr::null_mut()) };
        assert_eq!(none, status::OK);
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
