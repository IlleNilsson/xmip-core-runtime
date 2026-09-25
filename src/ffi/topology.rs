//! `xmip_operate.h` section 8: what a topology value is called.
//!
//! A publication carries a topology's kind, origin and pattern as the
//! header's integers, and a surface drawing them needs the word each is
//! written as — a class to style it by — and the name a person reads it by.
//! Both are `observe::topology`'s (`word` and `name`), and until 2026-09-25
//! the web GUI kept a copy of each list (ADR-0052, amendment of that date).
//! Each export here is one call into the owner, the pointers written and no
//! word of its own. Pure, like section 7: no handle, any thread.
//!
//! In `ffi/`, the one folder of the runtime that may hold unsafe code
//! (ADR-0050, refined 2026-09-25): a surface hands over where to write.
#![allow(unsafe_code)]

use abi::ffi::{Str, status};

use crate::ffi::operate::borrow;
use crate::wire::{from_wire_kind, from_wire_origin, from_wire_pattern};

/// The word and the name of whatever `value` reads as, both static.
///
/// # Safety
/// `out_word` and `out_name` are writable.
unsafe fn words(
    said: Option<(&'static str, &'static str)>,
    out_word: *mut Str,
    out_name: *mut Str,
) -> i32 {
    let Some((word, name)) = said else {
        return status::INVALID;
    };

    // SAFETY: both are writable per the contract; the text is static.
    unsafe {
        out_word.write(borrow(word));
        out_name.write(borrow(name));
    }
    status::OK
}

/// `observe::NodeKind::word` and `name`, forwarded. Static.
///
/// # Safety
/// `out_word` and `out_name` are writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_topology_kind_words_v1(
    kind: i32,
    out_word: *mut Str,
    out_name: *mut Str,
) -> i32 {
    let said = from_wire_kind(kind).map(|kind| (kind.word(), kind.name()));

    // SAFETY: per the contract above.
    unsafe { words(said, out_word, out_name) }
}

/// `observe::Origin::word` and `name`, forwarded. Static.
///
/// # Safety
/// `out_word` and `out_name` are writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_topology_origin_words_v1(
    origin: i32,
    out_word: *mut Str,
    out_name: *mut Str,
) -> i32 {
    let said = from_wire_origin(origin).map(|origin| (origin.word(), origin.name()));

    // SAFETY: per the contract above.
    unsafe { words(said, out_word, out_name) }
}

/// `observe::Pattern::word` and `name`, forwarded. Static.
///
/// # Safety
/// `out_word` and `out_name` are writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_topology_pattern_words_v1(
    pattern: i32,
    out_word: *mut Str,
    out_name: *mut Str,
) -> i32 {
    let said = from_wire_pattern(pattern).map(|pattern| (pattern.word(), pattern.name()));

    // SAFETY: per the contract above.
    unsafe { words(said, out_word, out_name) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{wire_kind, wire_origin, wire_pattern};
    use abi::operate::publication::TopologyWordsFn;
    use observe::{NodeKind, Origin, Pattern};

    /// What one export says of one value: its status, word and name.
    fn said(export: TopologyWordsFn, value: i32) -> (i32, String, String) {
        let (mut word, mut name) = (Str::empty(), Str::empty());
        // SAFETY: both outs are writable.
        let code = unsafe { export(value, &raw mut word, &raw mut name) };

        (code, read(word), read(name))
    }

    fn read(value: Str) -> String {
        if value.ptr.is_null() {
            return String::new();
        }
        // SAFETY: the export promises `len` readable bytes.
        let bytes = unsafe { core::slice::from_raw_parts(value.ptr, value.len) };
        String::from_utf8(bytes.to_vec()).expect("UTF-8")
    }

    #[test]
    fn every_value_crosses_with_the_word_and_name_observe_gives_it() {
        for kind in NodeKind::ALL {
            let expected = (status::OK, kind.word().into(), kind.name().into());
            assert_eq!(
                said(xmip_topology_kind_words_v1, wire_kind(*kind)),
                expected
            );
        }
        for origin in Origin::ALL {
            let expected = (status::OK, origin.word().into(), origin.name().into());
            assert_eq!(
                said(xmip_topology_origin_words_v1, wire_origin(*origin)),
                expected
            );
        }
        for pattern in Pattern::ALL {
            let expected = (status::OK, pattern.word().into(), pattern.name().into());
            assert_eq!(
                said(xmip_topology_pattern_words_v1, wire_pattern(*pattern)),
                expected
            );
        }
    }

    #[test]
    fn a_value_no_enum_defines_is_refused() {
        for export in [
            xmip_topology_kind_words_v1 as TopologyWordsFn,
            xmip_topology_origin_words_v1,
            xmip_topology_pattern_words_v1,
        ] {
            assert_eq!(said(export, 99).0, status::INVALID);
            assert_eq!(said(export, -1).0, status::INVALID);
        }
    }
}
