//! `xmip_operate.h` section 7, the node crate's part: the stage words and
//! the facts of a stage, the role words and their parse, and a run's node
//! entry — each `node::Stage`'s, `node::NodeRole`'s or `node::Capability`'s,
//! forwarded with no rule of its own (ADR-0027 and ADR-0052, amendments
//! 2026-09-24; ADR-0056, amendment 2026-10-01).
//!
//! In `ffi/`, the one folder of the runtime that may hold unsafe code
//! (ADR-0050, refined 2026-09-25): a surface hands over where to write.
#![allow(unsafe_code)]

use abi::ffi::{Str, status};
use node::{Capability, NodeRole, Stage};

use super::{fill, refuse};
use crate::ffi::operate::{borrow, scope_text};

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

/// `node::NodeRole::WORDS`, forwarded. Static.
///
/// # Safety
/// `out` has room for `cap` entries; `out_len` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_role_words_v1(out: *mut Str, cap: usize, out_len: *mut usize) -> i32 {
    // SAFETY: per the contract above.
    unsafe { fill(NodeRole::WORDS.into_iter(), out, cap, out_len) };
    status::OK
}

/// `node::NodeRole::declared`, forwarded: the roles in the fill shape, or
/// `XMIP_E_INVALID` and the refusal written as UTF-8.
///
/// # Safety
/// `declared` points at its stated length of readable bytes; `roles` has
/// room for `cap` entries and `refusal` for `refusal_cap` bytes; `out_len`
/// and `refusal_len` are writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_role_declared_v1(
    declared: Str,
    roles: *mut Str,
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
    let said = Capability::parse(declared);

    // SAFETY: per the contract above.
    unsafe { write_declared(said, roles, cap, out_len, refusal, refusal_cap, refusal_len) }
        .map_or(status::INVALID, |_| status::OK)
}

/// `node::NodeRole::stages`, forwarded: the stage words of the role a word
/// names, static, in the fill shape; `XMIP_E_NOT_FOUND` for a word that is
/// no role.
///
/// # Safety
/// `role` points at its stated length of readable bytes; `out` has room for
/// `cap` entries; `out_len` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_role_stages_v1(
    role: Str,
    out: *mut Str,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: the caller upholds the header's contract on `role`.
    let Some(word) = (unsafe { scope_text(role) }) else {
        return status::MALFORMED;
    };
    let Some(role) = NodeRole::named(word) else {
        return status::NOT_FOUND;
    };
    // SAFETY: per the contract above.
    unsafe {
        fill(
            role.stages().iter().map(|stage| stage.name()),
            out,
            cap,
            out_len,
        )
    };
    status::OK
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
/// `entry`, and the roles or the refusal.
///
/// # Safety
/// `entry` points at its stated length of readable bytes; `roles` has room
/// for `cap` entries and `refusal` for `refusal_cap` bytes; every other out
/// is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_capability_entry_v1(
    entry: Str,
    out_node: *mut Str,
    roles: *mut Str,
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
        write_declared(said, roles, cap, out_len, refusal, refusal_cap, refusal_len)
    }
    .map_or(status::INVALID, |_| status::OK)
}

/// A declaration's answer in the header's shape: its roles in the fill
/// shape and no refusal, or no role and the refusal written. `Some` with
/// the online capability when it was declared, `None` when refused.
///
/// # Safety
/// `roles` has room for `cap` entries and `refusal` for `refusal_cap`
/// bytes; `out_len` and `refusal_len` are writable.
pub(crate) unsafe fn write_declared(
    said: Result<Capability, String>,
    roles: *mut Str,
    cap: usize,
    out_len: *mut usize,
    refusal: *mut u8,
    refusal_cap: usize,
    refusal_len: *mut usize,
) -> Option<bool> {
    match said {
        Ok(capability) => {
            let words = capability.roles().iter().map(|role| role.name());
            // SAFETY: per the contract above.
            unsafe {
                fill(words, roles, cap, out_len);
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
        let mut roles = [Str::empty(); NodeRole::WORDS.len()];
        let mut len = 0usize;
        let mut refusal = [0u8; 256];
        let mut refusal_len = 0usize;
        // SAFETY: the buffers have the capacities passed; lengths writable.
        let code = unsafe {
            xmip_role_declared_v1(
                borrow(raw),
                roles.as_mut_ptr(),
                roles.len(),
                &raw mut len,
                refusal.as_mut_ptr(),
                refusal.len(),
                &raw mut refusal_len,
            )
        };
        let words = roles[..len.min(NodeRole::WORDS.len())]
            .iter()
            .map(|word| text(*word))
            .collect();
        let said = String::from_utf8(refusal[..refusal_len.min(256)].to_vec()).expect("UTF-8");

        (code, words, said)
    }

    fn entry(raw: &str) -> (i32, String, Vec<String>, String) {
        let (mut node, mut roles) = (Str::empty(), [Str::empty(); NodeRole::WORDS.len()]);
        let (mut len, mut said_len) = (0usize, 0usize);
        let mut said = [0u8; 256];
        // SAFETY: the buffers have the capacities passed; every out writable.
        let code = unsafe {
            xmip_capability_entry_v1(
                borrow(raw),
                &raw mut node,
                roles.as_mut_ptr(),
                7,
                &raw mut len,
                said.as_mut_ptr(),
                said.len(),
                &raw mut said_len,
            )
        };
        let words = roles[..len.min(NodeRole::WORDS.len())]
            .iter()
            .map(|s| text(*s))
            .collect();
        let sentence = String::from_utf8(said[..said_len.min(256)].to_vec()).expect("UTF-8");
        (code, text(node), words, sentence)
    }

    #[test]
    fn every_export_has_the_shape_the_binding_declares() {
        use abi::operate::rule;

        let _: rule::StageWordsFn = xmip_stage_words_v1;
        let _: rule::RoleWordsFn = xmip_role_words_v1;
        let _: rule::RoleDeclaredFn = xmip_role_declared_v1;
        let _: rule::RoleStagesFn = xmip_role_stages_v1;
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

        let mut out = [Str::empty(); NodeRole::WORDS.len()];
        // SAFETY: `out` has as many entries as there are roles.
        let code =
            unsafe { xmip_role_words_v1(out.as_mut_ptr(), NodeRole::WORDS.len(), &raw mut len) };

        assert_eq!(code, status::OK);
        assert_eq!(out.map(text), NodeRole::WORDS);
    }

    #[test]
    fn every_role_crosses_with_the_stages_it_serves() {
        for role in NodeRole::ALL {
            let (mut out, mut len) = ([Str::empty(); 3], 9usize);
            // SAFETY: the word is static; `out` has 3 entries.
            let code = unsafe {
                xmip_role_stages_v1(borrow(role.name()), out.as_mut_ptr(), 3, &raw mut len)
            };
            assert_eq!(code, status::OK);
            let words: Vec<String> = out[..len].iter().map(|word| text(*word)).collect();
            assert_eq!(
                words,
                role.stages().iter().map(|s| s.name()).collect::<Vec<_>>()
            );
        }
        let (mut out, mut len) = ([Str::empty(); 3], 0usize);
        // SAFETY: as above.
        let code =
            unsafe { xmip_role_stages_v1(borrow("receive"), out.as_mut_ptr(), 3, &raw mut len) };
        assert_eq!(code, status::NOT_FOUND);
    }

    #[test]
    fn a_declaration_reads_as_role_declared_says_and_a_refusal_crosses_whole() {
        assert_eq!(
            declared(" sending + receiving "),
            (
                status::OK,
                vec!["receiving".into(), "sending".into()],
                String::new()
            )
        );
        assert_eq!(
            declared("receiving,processing,sending"),
            (status::OK, vec!["executing".into()], String::new())
        );
        assert_eq!(declared(""), (status::OK, vec![], String::new()));

        let (code, words, said) = declared("Sending+relay");
        assert_eq!(code, status::INVALID);
        assert!(words.is_empty());
        assert_eq!(
            said,
            NodeRole::declared("Sending+relay").expect_err("refused")
        );
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
        let cluster = configure::fixture::test_cluster();
        let [first, second, third] = [0, 1, 2].map(|place| cluster.node(place).name.clone());
        assert_eq!(
            entry(&format!(" {first} =sending+receiving")),
            (
                status::OK,
                first,
                vec!["receiving".into(), "sending".into()],
                String::new()
            )
        );
        assert_eq!(
            entry(&second),
            (status::OK, second.clone(), vec![], String::new())
        );

        let (code, node, words, said) = entry(&format!("{third}=relay"));
        assert_eq!((code, node), (status::INVALID, third));
        assert!(words.is_empty() && said.starts_with("REFUSED"), "{said}");
    }
}
