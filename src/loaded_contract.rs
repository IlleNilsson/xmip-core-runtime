//! The contract trait of a loaded module, driven through its table.
//!
//! ADR-0042: a contract holds well-formedness always, and conformance when a
//! descriptor names one. Header section 12 is that trait as four functions
//! over an opaque contract handle, and this is the host side of them —
//! selecting the table by `descriptor.module`, binding a descriptor,
//! streaming bytes in through an `XmipReader` the host supplies, and copying
//! out diagnostics the module lends only until its next call.
//!
//! The second of the two files in this crate that cross the boundary inward;
//! `loaded_module.rs` opens and holds, this one asks. Every `unsafe` block
//! below names the invariant that makes it sound, for the same reasons that
//! file gives.
#![allow(unsafe_code)]

use std::ffi::c_void;

use abi::ModuleDescriptor;
use abi::ffi::{ContractVtable, Diagnostic, Reader, Str, status};

use crate::loaded_module::{LoadedModule, read_str};

/// The trait this file drives, as `descriptor.module` spells it (ADR-0011).
pub const CONTRACT: &str = "contract";

/// `configure`, `start` and `stop` differ only in what they are called; the
/// first also takes the artifact's TOML fragment.
type LifecycleFn = unsafe extern "C" fn(*mut c_void) -> i32;

/// What a contract said about one stream, copied out of the module.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verdict {
    pub status: i32,
    pub diagnostics: Vec<String>,
}

impl Verdict {
    /// `XMIP_OK` with nothing to report is the only answer that means the
    /// stream held. Header section 12: a valid stream returns `XMIP_OK` with
    /// `out_len` 0.
    #[must_use]
    pub fn held(&self) -> bool {
        self.status == status::OK && self.diagnostics.is_empty()
    }
}

/// The contract table of one loaded module, borrowed for as long as the
/// module is held.
pub struct LoadedContract<'a> {
    module: &'a LoadedModule,
    table: &'a ContractVtable,
}

impl<'a> LoadedContract<'a> {
    /// Select this module's contract table, by the name in its descriptor.
    ///
    /// # Errors
    ///
    /// A module that answers another trait, one that names `contract` and
    /// carries no table, or a table whose own header disagrees with the
    /// descriptor the host has just accepted.
    pub fn of(module: &'a LoadedModule) -> Result<Self, String> {
        let descriptor = module.descriptor();

        if descriptor.module != CONTRACT {
            return Err(format!(
                "{descriptor} answers the '{}' trait, and only '{CONTRACT}' \
                 can be driven from here",
                descriptor.module
            ));
        }

        if module.vtable().is_null() {
            return Err(format!(
                "{descriptor} names the '{CONTRACT}' trait and carries no table"
            ));
        }

        // SAFETY: header section 7 — the table is the one named by
        // `descriptor.module`, and that name has just been checked. The table
        // is `'static` inside the library, which this borrow cannot outlive
        // because `module` owns the library.
        let table = unsafe { &*module.vtable().cast::<ContractVtable>() };

        if table.header.trait_major != descriptor.trait_major
            || table.header.trait_minor != descriptor.trait_minor
        {
            return Err(format!(
                "{descriptor} declares trait {}.{} and its table says {}.{}: \
                 a module that disagrees with itself is not driven",
                descriptor.trait_major,
                descriptor.trait_minor,
                table.header.trait_major,
                table.header.trait_minor
            ));
        }

        Ok(Self { module, table })
    }

    fn descriptor(&self) -> &ModuleDescriptor {
        self.module.descriptor()
    }

    /// Header section 8: `configure` runs once, before `start`, with the
    /// artifact's TOML fragment.
    ///
    /// # Errors
    ///
    /// A table with no `configure`, or the module's own status.
    pub fn configure(&self, toml: &str) -> Result<(), String> {
        let Some(call) = self.table.header.configure else {
            return Err(format!("{} carries no configure", self.descriptor()));
        };
        let fragment = Str {
            ptr: toml.as_ptr(),
            len: toml.len(),
        };

        // SAFETY: `toml` outlives the call, which is all the header lends it
        // for — a module that keeps the fragment copies it. `state` is this
        // instance's own and no other call is in flight.
        let answer = unsafe { call(self.module.state(), fragment) };

        self.judge("configure", answer)
    }

    /// # Errors
    ///
    /// A table with no `start`, or the module's own status.
    pub fn start(&self) -> Result<(), String> {
        self.lifecycle("start", self.table.header.start)
    }

    /// # Errors
    ///
    /// A table with no `stop`, or the module's own status. Conformance rule 7
    /// makes this legal even where `start` never ran.
    pub fn stop(&self) -> Result<(), String> {
        self.lifecycle("stop", self.table.header.stop)
    }

    fn lifecycle(&self, what: &str, call: Option<LifecycleFn>) -> Result<(), String> {
        let Some(call) = call else {
            return Err(format!("{} carries no {what}", self.descriptor()));
        };

        // SAFETY: `state` is this instance's own, handed back untouched, and
        // no other call on it is in flight — the host serializes calls on one
        // instance (specification section 5).
        let answer = unsafe { call(self.module.state()) };

        self.judge(what, answer)
    }

    fn judge(&self, what: &str, answer: i32) -> Result<(), String> {
        if answer == status::OK {
            return Ok(());
        }

        Err(format!(
            "{} answered status {answer} to {what}: {}",
            self.descriptor(),
            self.module.last_error()
        ))
    }

    /// Bind a contract descriptor — a schema document, a profile URL, a
    /// message type — in the standard's own terms. The module interprets it.
    ///
    /// # Errors
    ///
    /// A table with no `load`, or the module's own status.
    pub fn bind(&self, descriptor: &str) -> Result<BoundContract<'_>, String> {
        let load = self
            .table
            .load
            .ok_or_else(|| format!("{} carries no load", self.descriptor()))?;
        let named = Str {
            ptr: descriptor.as_ptr(),
            len: descriptor.len(),
        };
        let mut contract: *mut c_void = std::ptr::null_mut();

        // SAFETY: `descriptor` outlives the call and the module copies what
        // it keeps. `contract` is a live local the module writes at most once.
        let answer = unsafe { load(self.module.state(), named, &raw mut contract) };

        if answer != status::OK || contract.is_null() {
            return Err(format!(
                "{} would not bind '{descriptor}': status {answer}",
                self.descriptor()
            ));
        }

        Ok(BoundContract {
            of: self,
            handle: contract,
        })
    }
}

/// What a byte slice looks like to a module reading an `XmipReader`.
struct Source<'a> {
    bytes: &'a [u8],
    at: usize,
}

/// The host's side of header section 5. Returns bytes written, 0 at end of
/// stream, or a negative status; a short read is not end of stream.
unsafe extern "C" fn read_source(ctx: *mut c_void, buf: *mut u8, len: usize) -> i64 {
    if ctx.is_null() || (buf.is_null() && len > 0) {
        return i64::from(status::INVALID);
    }

    // SAFETY: `ctx` is the `Source` that `validate` below keeps on its own
    // stack across the one call it passes this reader to; the module may not
    // keep the reader past that call, so nothing else can be behind this
    // pointer. `buf` is the module's, writable for `len` bytes for this call.
    let source = unsafe { &mut *ctx.cast::<Source<'_>>() };
    let taken = (source.bytes.len() - source.at).min(len);

    // SAFETY: `taken` bytes exist in both, and the two cannot overlap — one
    // is the host's slice, the other the module's buffer. Nothing in this
    // function can panic, so nothing can unwind out of an `extern "C"` frame.
    unsafe { std::ptr::copy_nonoverlapping(source.bytes[source.at..].as_ptr(), buf, taken) };

    source.at += taken;

    i64::try_from(taken).unwrap_or(i64::MAX)
}

/// One bound contract. Released through the module that produced it — an
/// opaque handle is meaningless to anyone else, and no allocator is shared
/// across the boundary (specification section 4).
pub struct BoundContract<'a> {
    of: &'a LoadedContract<'a>,
    handle: *mut c_void,
}

impl BoundContract<'_> {
    /// Judge `content` against this contract. Diagnostics come back copied,
    /// because the module lends them only until its next call.
    ///
    /// # Errors
    ///
    /// A table with no `validate`.
    pub fn validate(&self, content: &[u8]) -> Result<Verdict, String> {
        let validate = self
            .of
            .table
            .validate
            .ok_or_else(|| format!("{} carries no validate", self.of.descriptor()))?;
        let mut source = Source {
            bytes: content,
            at: 0,
        };
        let reader = Reader {
            ctx: (&raw mut source).cast(),
            read: Some(read_source),
        };
        let mut out: *const Diagnostic = std::ptr::null();
        let mut count: usize = 0;

        // SAFETY: `source` and `reader` live across the call and the module
        // may keep neither. `out` and `count` are live locals it writes. What
        // `out` points at is the module's, lent until its next call on this
        // instance, which is why it is copied before anything else is asked.
        let answer = unsafe {
            validate(
                self.of.module.state(),
                self.handle,
                &raw const reader,
                &raw mut out,
                &raw mut count,
            )
        };

        Ok(Verdict {
            status: answer,
            diagnostics: read_diagnostics(out, count),
        })
    }

    /// What the contract already determines about `key`, so an artifact does
    /// not have to restate it — or `None` where the standard implies nothing.
    #[must_use]
    pub fn implies(&self, key: &str) -> Option<String> {
        let implies = self.of.table.implies?;
        let asked = Str {
            ptr: key.as_ptr(),
            len: key.len(),
        };
        let mut answer = Str::empty();

        // SAFETY: `key` outlives the call; `answer` is a live local. What
        // comes back is lent until the module's next call and copied here.
        let told = unsafe { implies(self.of.module.state(), self.handle, asked, &raw mut answer) };

        (told == status::OK).then(|| read_str(answer))
    }
}

impl Drop for BoundContract<'_> {
    fn drop(&mut self) {
        if let Some(release) = self.of.table.release {
            // SAFETY: `handle` came from this table's own `load` and is
            // released exactly once, here, through the module that produced
            // it — never freed by the host, which shares no allocator with it.
            unsafe { release(self.of.module.state(), self.handle) };
        }
    }
}

/// Copy a borrowed diagnostic run out of the module before its next call.
fn read_diagnostics(first: *const Diagnostic, count: usize) -> Vec<String> {
    if first.is_null() || count == 0 {
        return Vec::new();
    }

    // SAFETY: the module wrote `first` and `count` in the call that has just
    // returned, and lends the run until its next call on this instance. It is
    // read and copied here, before any other call is made.
    let run = unsafe { std::slice::from_raw_parts(first, count) };

    run.iter()
        .map(|found| {
            let location = read_str(found.location);
            let message = read_str(found.message);

            if location.is_empty() {
                format!("[{}] {message}", found.code)
            } else {
                format!("[{}] {location}: {message}", found.code)
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compatibility::Expectation;
    use std::path::{Path, PathBuf};

    /// Where the real module is. `XMIP_MODULE_LIBRARY` first, as
    /// `contract/probe/verify.ps1` takes `XMIP_CONTRACT_PROBE`; else the
    /// estate's own mount, because this repository is a submodule of it and
    /// the technology it drives is another.
    ///
    /// Not skipped when neither is there. A proof that quietly passes because
    /// nothing was built is the failure ADR-0057 exists to stop, so the
    /// refusal names what to build and which variable to set.
    fn contract_library() -> PathBuf {
        if let Ok(told) = std::env::var("XMIP_MODULE_LIBRARY")
            && !told.trim().is_empty()
        {
            return PathBuf::from(told);
        }

        let name = if cfg!(target_os = "windows") {
            "xmip_core_contract_rust.dll"
        } else if cfg!(target_os = "macos") {
            "libxmip_core_contract_rust.dylib"
        } else {
            "libxmip_core_contract_rust.so"
        };

        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../core/capability/contract/rust/target/debug")
            .join(name)
    }

    fn open() -> LoadedModule {
        let library = contract_library();

        assert!(
            library.exists(),
            "no module library at {}. Build one — cargo build in \
             module/core/capability/contract/rust — or set XMIP_MODULE_LIBRARY to \
             a conforming contract module.",
            library.display()
        );

        LoadedModule::open(&library, &Expectation::new(CONTRACT, 1, 0))
            .expect("the host takes a core contract module at trait 1.0")
    }

    #[test]
    fn a_real_module_opens_and_says_what_it_is() {
        let module = open();
        let descriptor = module.descriptor();

        assert_eq!(descriptor.abi_version, 1);
        assert_eq!(descriptor.provider, "core");
        assert_eq!(descriptor.module, CONTRACT);
        assert_eq!((descriptor.trait_major, descriptor.trait_minor), (1, 0));
        assert!(!descriptor.standard.is_empty(), "a technology names one");
        assert_eq!(module.last_error(), "");
    }

    #[test]
    fn the_capability_that_did_not_ask_for_it_refuses_it_naming_the_field() {
        let library = contract_library();

        assert!(
            library.exists(),
            "build the module first: {}",
            library.display()
        );

        let refusal = LoadedModule::open(&library, &Expectation::new("transport", 1, 0))
            .expect_err("a contract module is not a transport");

        assert!(refusal.contains("descriptor.module"), "got: {refusal}");
        assert!(refusal.contains("'contract' trait"), "got: {refusal}");
        assert!(
            refusal.contains("'transport' is loading it"),
            "got: {refusal}"
        );
    }

    #[test]
    fn a_trait_generation_apart_is_refused_naming_trait_major() {
        let library = contract_library();

        assert!(
            library.exists(),
            "build the module first: {}",
            library.display()
        );

        let refusal = LoadedModule::open(&library, &Expectation::new(CONTRACT, 2, 0))
            .expect_err("trait_major must be equal");

        assert!(refusal.contains("trait_major 1"), "got: {refusal}");
        assert!(refusal.contains("speaks 2"), "got: {refusal}");
    }

    #[test]
    fn content_is_validated_through_the_loaded_table() {
        let module = open();
        let contract = LoadedContract::of(&module).expect("the contract table");

        contract
            .configure("unrecognized-key = true")
            .expect("configure");
        contract.start().expect("start");

        let bound = contract.bind("any").expect("a descriptor binds");
        let verdict = bound.validate(b"xmip round-trip").expect("validate");

        assert!(verdict.held(), "got: {verdict:?}");
        assert_eq!(verdict.status, status::OK);
        assert!(verdict.diagnostics.is_empty());

        assert_eq!(bound.implies("descriptor").as_deref(), Some("any"));
        assert_eq!(bound.implies("nothing-it-determines"), None);

        drop(bound);
        contract.stop().expect("stop");
        assert_eq!(module.last_error(), "");
    }

    #[test]
    fn an_empty_stream_is_read_to_its_end_like_any_other() {
        let module = open();
        let contract = LoadedContract::of(&module).expect("the contract table");

        contract.start().expect("start");

        let bound = contract.bind("any").expect("a descriptor binds");

        assert!(bound.validate(b"").expect("validate").held());
    }
}
