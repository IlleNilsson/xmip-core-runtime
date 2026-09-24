//! `xmip_operate.h` section 7, the node crate's part: the stage words and
//! their parse, the other facts of a stage, and a run's node entry — each
//! `node::Stage`'s or `node::Capability`'s, forwarded with no rule of its
//! own (ADR-0027 and ADR-0052, amendments 2026-09-24).
//!
//! One of the files in this crate that dereference a pointer, for the reason
//! `operate.rs` gives: a surface hands over where to write.
#![allow(unsafe_code)]

use abi::ffi::{Str, status};
use node::{Capability, Stage};

use super::{fill, refuse};
use crate::operate::{borrow, scope_text};

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
    let said = Stage::declared(declared).map(|stages| Capability::of(&stages));

    // SAFETY: per the contract above.
    unsafe {
        write_declared(
            said,
            stages,
            cap,
            out_len,
            refusal,
            refusal_cap,
            refusal_len,
        )
    }
    .map_or(status::INVALID, |_| status::OK)
}

/// The stage a word names, or `None` for a word that is no stage or text
/// that is not UTF-8.
///
/// # Safety
/// `stage` points at its stated length of readable bytes.
unsafe fn named(stage: Str) -> Result<Stage, i32> {
    // SAFETY: the caller upholds the header's contract on `stage`.
    let word = unsafe { scope_text(stage) }.ok_or(status::MALFORMED)?;
    Stage::named(word).ok_or(status::NOT_FOUND)
}

/// `node::Stage::pausable`, forwarded.
///
/// # Safety
/// `stage` points at its stated length of readable bytes; `out` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_stage_pausable_v1(stage: Str, out: *mut u8) -> i32 {
    // SAFETY: per the contract above.
    match unsafe { named(stage) } {
        Ok(stage) => {
            // SAFETY: `out` is writable per the contract.
            unsafe { *out = u8::from(stage.pausable()) };
            status::OK
        }
        Err(code) => code,
    }
}

/// `node::Stage::location`, forwarded. Static.
///
/// # Safety
/// `stage` points at its stated length of readable bytes; `out` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_stage_location_v1(stage: Str, out: *mut Str) -> i32 {
    // SAFETY: per the contract above.
    match unsafe { named(stage) } {
        Ok(stage) => {
            // SAFETY: `out` is writable per the contract.
            unsafe { out.write(borrow(stage.location())) };
            status::OK
        }
        Err(code) => code,
    }
}

/// `node::Capability::from_entry`, forwarded: the name borrowed from
/// `entry`, and the stages or the refusal.
///
/// # Safety
/// `entry` points at its stated length of readable bytes; `stages` has room
/// for `cap` entries and `refusal` for `refusal_cap` bytes; every other out
/// is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_capability_entry_v1(
    entry: Str,
    out_node: *mut Str,
    stages: *mut Str,
    cap: usize,
    out_len: *mut usize,
    refusal: *mut u8,
    refusal_cap: usize,
    refusal_len: *mut usize,
) -> i32 {
    // SAFETY: the caller upholds the header's contract on `entry`.
    let Some(entry) = (unsafe { scope_text(entry) }) else {
        return status::MALFORMED;
    };
    let (name, said) = Capability::from_entry(entry);

    // SAFETY: per the contract above.
    unsafe {
        out_node.write(borrow(name));
        write_declared(
            said,
            stages,
            cap,
            out_len,
            refusal,
            refusal_cap,
            refusal_len,
        )
    }
    .map_or(status::INVALID, |_| status::OK)
}

/// A declaration's answer in the header's shape: its stages in the fill
/// shape and no refusal, or no stage and the refusal written. `Some` with
/// the online capability when it was declared, `None` when refused.
///
/// # Safety
/// `stages` has room for `cap` entries and `refusal` for `refusal_cap`
/// bytes; `out_len` and `refusal_len` are writable.
pub(crate) unsafe fn write_declared(
    said: Result<Capability, String>,
    stages: *mut Str,
    cap: usize,
    out_len: *mut usize,
    refusal: *mut u8,
    refusal_cap: usize,
    refusal_len: *mut usize,
) -> Option<bool> {
    match said {
        Ok(capability) => {
            let words = capability.features().iter().map(|stage| stage.name());
            // SAFETY: per the contract above.
            unsafe {
                fill(words, stages, cap, out_len);
                *refusal_len = 0;
            }
            Some(capability.is_online())
        }
        Err(sentence) => {
            // SAFETY: per the contract above.
            unsafe {
                *out_len = 0;
                refuse(&sentence, refusal, refusal_cap, refusal_len);
            }
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(value: Str) -> String {
        if value.ptr.is_null() {
            return String::new();
        }
        // SAFETY: the export promises `len` readable bytes.
        let bytes = unsafe { core::slice::from_raw_parts(value.ptr, value.len) };
        String::from_utf8(bytes.to_vec()).expect("UTF-8")
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

    fn entry(raw: &str) -> (i32, String, Vec<String>, String) {
        let (mut node, mut stages) = (Str::empty(), [Str::empty(); 3]);
        let (mut len, mut said_len) = (0usize, 0usize);
        let mut said = [0u8; 256];
        // SAFETY: the buffers have the capacities passed; every out writable.
        let code = unsafe {
            xmip_capability_entry_v1(
                borrow(raw),
                &raw mut node,
                stages.as_mut_ptr(),
                3,
                &raw mut len,
                said.as_mut_ptr(),
                said.len(),
                &raw mut said_len,
            )
        };
        let words = stages[..len.min(3)].iter().map(|s| text(*s)).collect();
        let sentence = String::from_utf8(said[..said_len.min(256)].to_vec()).expect("UTF-8");
        (code, text(node), words, sentence)
    }

    #[test]
    fn every_export_has_the_shape_the_binding_declares() {
        use abi::operate::rule;

        let _: rule::StageWordsFn = xmip_stage_words_v1;
        let _: rule::StageDeclaredFn = xmip_stage_declared_v1;
        let _: rule::StagePausableFn = xmip_stage_pausable_v1;
        let _: rule::StageLocationFn = xmip_stage_location_v1;
        let _: rule::CapabilityEntryFn = xmip_capability_entry_v1;
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
    fn every_stage_crosses_with_the_facts_node_gives_it() {
        for stage in Stage::ALL {
            let (mut pausable, mut location) = (9u8, Str::empty());
            // SAFETY: the word is static; every out is writable.
            unsafe {
                assert_eq!(
                    xmip_stage_pausable_v1(borrow(stage.name()), &raw mut pausable),
                    status::OK
                );
                assert_eq!(
                    xmip_stage_location_v1(borrow(stage.name()), &raw mut location),
                    status::OK
                );
            }
            assert_eq!(pausable, u8::from(stage.pausable()));
            assert_eq!(text(location), stage.location());
        }
        let mut out = 9u8;
        // SAFETY: as above.
        let code = unsafe { xmip_stage_pausable_v1(borrow("Receive"), &raw mut out) };
        assert_eq!(code, status::NOT_FOUND);
    }

    #[test]
    fn an_entry_crosses_as_node_reads_it_and_its_name_survives_a_refusal() {
        assert_eq!(
            entry(" edge-01 =send+receive"),
            (
                status::OK,
                "edge-01".to_string(),
                vec!["receive".into(), "send".into()],
                String::new()
            )
        );
        assert_eq!(
            entry("edge-02"),
            (status::OK, "edge-02".into(), vec![], String::new())
        );

        let (code, node, words, said) = entry("edge-03=relay");
        assert_eq!((code, node.as_str()), (status::INVALID, "edge-03"));
        assert!(words.is_empty() && said.starts_with("REFUSED"), "{said}");
    }
}
