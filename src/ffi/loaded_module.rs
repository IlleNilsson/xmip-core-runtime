//! A module the host has opened: the library, one instance, and what it says
//! about itself.
//!
//! ADR-0057 clause 1 splits two purchases the estate had been calling by one
//! word. A trait table is a promise; this is the other half — the host
//! opening a shared library, resolving `xmip_create_module_v1`, calling it
//! with an `XmipHost`, checking the descriptor, holding the instance and
//! destroying it on the way down. Written against creation wave one, where
//! the table is already paid for, which is that record's clause 8 step 2.
//!
//! ADR-0025 clause 3 is what this makes real: a delayed Module is loaded on
//! the first call that needs it. Until this file there was nothing to delay —
//! `host::dynamic::verify_dynamic_module` checks a descriptor an operator
//! typed and has never opened a library.
//!
//! What a loaded module is then *asked* is the trait's subject and lives with
//! the trait: `loaded_contract.rs` for creation wave one's contract table.
//!
//! **This file and `loaded_contract.rs` are the only two in the runtime that
//! cross the module boundary inward**, both in `ffi/`, the one folder of the
//! runtime that may hold unsafe code (ADR-0050, refined 2026-09-25).
//! `operate.rs` and `start.rs` beside them allow
//! `unsafe` for the boundary that faces the other way (ADR-0027): a surface
//! handing this process a pointer. Here the process is the host and the
//! pointer comes out of somebody else's library, so every block below says
//! which invariant makes it sound — where the pointer came from, how long it
//! is good for, and who frees it. Specification section 4 is the rule all
//! three answers serve: whoever allocates, releases, and no allocator is
//! shared across the boundary.
//!
//! Unwinding crosses in neither direction (ADR-0012 clause 8). The host's own
//! callbacks below are `extern "C"`, and Rust aborts rather than unwinds out
//! of one, so the rule is kept by the ABI rather than by a `catch_unwind`
//! this file would have to remember at every edge.
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::path::{Path, PathBuf};

use abi::ffi::{CreateModuleFn, Host, Module, Str, status};
use abi::{ModuleDescriptor, XMIP_ABI_VERSION, XMIP_ENTRYPOINT};
use libloading::Library;

use crate::compatibility::{Expectation, accepts};

// ----------------------------------------------------------------------
// The host table. Header section 6: a module gets no allocator, no thread
// pool, no clock and no configuration store, and may call all three of these
// at any time between create and destroy.
// ----------------------------------------------------------------------

/// The runtime has no log sink to give a loaded module yet, and a null
/// function pointer is not the way to say so — a module is entitled to call
/// what the table carries. Discarding is honest; routing these into
/// `xmip-core-observe` is work this slice did not do.
unsafe extern "C" fn discard_log(_ctx: *mut c_void, _level: i32, _target: Str, _message: Str) {}

/// Nothing this host asks a module to do today is cancellable, so the answer
/// is always no.
unsafe extern "C" fn never_cancelled(_ctx: *mut c_void) -> i32 {
    0
}

/// Empty, which header section 6 makes the right answer for a module running
/// outside a journey — and a module loaded to be verified is.
unsafe extern "C" fn no_journey(_ctx: *mut c_void) -> Str {
    Str::empty()
}

fn host_table() -> Host {
    Host {
        abi_version: XMIP_ABI_VERSION,
        ctx: std::ptr::null_mut(),
        log: Some(discard_log),
        cancelled: Some(never_cancelled),
        journey_id: Some(no_journey),
    }
}

// ----------------------------------------------------------------------
// Reading what the module lent us.
// ----------------------------------------------------------------------

/// Copy a borrowed `XmipStr` into the host's own memory.
///
/// Specification section 4: anything passed across is borrowed for the
/// duration of one call, so a host that needs it longer copies it. Every
/// string this crate reads out of a module is copied here, at the call it
/// arrived in, which is what lets a [`LoadedModule`] outlive any single call
/// and what makes unloading sound at the end — no borrowed pointer into the
/// library is still held when it closes.
pub(crate) fn read_str(text: Str) -> String {
    if text.ptr.is_null() || text.len == 0 {
        return String::new();
    }

    // SAFETY: `text` is a field of a struct the module filled during a call
    // that has just returned, and the header guarantees ptr..ptr+len for that
    // call. The bytes are copied before this returns, so nothing outlives it.
    // Lossy rather than check-and-refuse: a name that is not UTF-8 is refused
    // by the compatibility rule anyway, and mangling it into the refusal
    // beats refusing to print the name at all.
    let bytes = unsafe { std::slice::from_raw_parts(text.ptr, text.len) };

    String::from_utf8_lossy(bytes).into_owned()
}

fn read_descriptor(module: &Module) -> ModuleDescriptor {
    let wire = &module.descriptor;

    ModuleDescriptor {
        abi_version: wire.abi_version,
        provider: read_str(wire.provider),
        module: read_str(wire.module),
        standard: read_str(wire.standard),
        trait_major: wire.trait_major,
        trait_minor: wire.trait_minor,
        module_major: wire.module_major,
        module_minor: wire.module_minor,
        module_patch: wire.module_patch,
    }
}

// ----------------------------------------------------------------------
// Opening.
// ----------------------------------------------------------------------

/// Specification section 3: load by absolute path, privately, never by name.
/// On Windows that is `LoadLibraryExW` with `LOAD_WITH_ALTERED_SEARCH_PATH`,
/// which `libloading`'s portable constructor does *not* pass, so this asks
/// for it by name. Everywhere else it is `dlopen` with `RTLD_LOCAL`, which
/// the portable constructor does pass — two modules may legitimately carry
/// the same symbol, and a global namespace makes the second bind to the
/// first one's copy.
#[cfg(windows)]
fn open_library(path: &Path) -> Result<Library, libloading::Error> {
    use libloading::os::windows::{LOAD_WITH_ALTERED_SEARCH_PATH, Library as Windows};

    // SAFETY: opening a library runs its initializers, which is arbitrary
    // code — the host trusts it by naming the path and nothing else here
    // assumes otherwise. The handle is owned by the returned `Library` and
    // closed by its `Drop`, after this file's `Drop` has destroyed the
    // instance.
    unsafe { Windows::load_with_flags(path, LOAD_WITH_ALTERED_SEARCH_PATH) }.map(Library::from)
}

#[cfg(not(windows))]
fn open_library(path: &Path) -> Result<Library, libloading::Error> {
    // SAFETY: as the Windows arm. `Library::new` is
    // `dlopen(RTLD_LAZY | RTLD_LOCAL)`, the private load section 3 requires.
    unsafe { Library::new(path) }
}

/// One module instance, its library, and the descriptor copied out of it.
///
/// Held for the module's life and taken down in the order specification
/// section 3 requires: `destroy` first, then unload, never the reverse.
/// `library` is declared last so it is dropped last.
pub struct LoadedModule {
    path: PathBuf,
    descriptor: ModuleDescriptor,
    module: Module,
    /// Never read again after `open`. Its whole job is to outlive every
    /// pointer this struct hands out and to close in `Drop`, after `destroy`
    /// — specification section 3: unloading frees the library's code, and any
    /// pointer still held into it becomes a jump into unmapped memory.
    #[expect(dead_code, reason = "held so the library outlives the instance")]
    library: Library,
}

impl std::fmt::Debug for LoadedModule {
    /// `Module` and `Library` are the boundary's own types and neither is
    /// `Debug`. What a reader wants is the descriptor and the file it came
    /// from, which is what a refusal names too.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} loaded from {}", self.descriptor, self.path.display())
    }
}

impl LoadedModule {
    /// Open `path`, create one instance, and keep it only if the capability
    /// that asked takes what the descriptor says.
    ///
    /// # Errors
    ///
    /// A library that will not open, one that exports no entrypoint, an
    /// entrypoint that refuses this host's ABI version, or a descriptor
    /// [`accepts`] turns down — which names the field that disagreed. A
    /// refusal after creation still destroys the instance and unloads the
    /// library, because the guard is built before the judgment is made.
    pub fn open(path: &Path, expected: &Expectation) -> Result<Self, String> {
        let library = open_library(path)
            .map_err(|why| format!("{} would not open: {why}", path.display()))?;

        let create = resolve(&library, path)?;
        let host = host_table();

        // SAFETY: all-zero is a valid `Module` — null pointers, and `None`
        // for every `Option<extern "C" fn>` — which is how the host can tell
        // an untouched `*out` from a filled one. Header section 7 leaves
        // `*out` untouched on a refusal.
        let mut module: Module = unsafe { std::mem::zeroed() };

        // SAFETY: `host` outlives the call, and its three callbacks are
        // `'static` items in this binary. The module writes `*out` only on
        // OK. Nothing can unwind back out: the entrypoint is `extern "C"`.
        let answer = unsafe { create(&raw const host, &raw mut module) };

        if answer != status::OK {
            return Err(format!(
                "{} refused to create a module: status {answer}, and *out was \
                 left untouched as header section 7 requires",
                path.display()
            ));
        }

        // Built before the descriptor is judged, so a refusal below leaves
        // through `Drop` and the instance is destroyed and the library
        // closed. A module the host will not take is still a module it
        // created (ADR-0055: refused, never half-loaded anyway).
        let loaded = Self {
            path: path.to_path_buf(),
            descriptor: read_descriptor(&module),
            module,
            library,
        };

        accepts(&loaded.descriptor, expected)?;

        Ok(loaded)
    }

    #[must_use]
    pub const fn descriptor(&self) -> &ModuleDescriptor {
        &self.descriptor
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Module-private state, opaque to the host and handed back untouched to
    /// every call on this instance.
    pub(crate) const fn state(&self) -> *mut c_void {
        self.module.state
    }

    /// The trait table named by `descriptor.module`. The host selects the
    /// type by that name; a mismatch is a load-time rejection, not a cast,
    /// which is why this hands back the untyped pointer the header defines
    /// and the trait's own file does the selecting.
    pub(crate) const fn vtable(&self) -> *const c_void {
        self.module.vtable
    }

    /// Header section 7: detail for the most recent failing call on this
    /// instance, borrowed until the next call and therefore copied here.
    #[must_use]
    pub fn last_error(&self) -> String {
        match self.module.last_error {
            // SAFETY: `state` is the module's own, handed back untouched, and
            // what comes back is valid until the next call on this instance —
            // `read_str` copies it before this returns.
            Some(ask) => read_str(unsafe { ask(self.module.state) }),
            None => String::new(),
        }
    }
}

/// Find the one exported symbol, by the header's own name.
fn resolve(library: &Library, path: &Path) -> Result<CreateModuleFn, String> {
    // libloading looks the name up as bytes and POSIX wants it terminated.
    let symbol = format!("{XMIP_ENTRYPOINT}\0");

    // SAFETY: the name is the header's and the signature is
    // `abi::ffi::CreateModuleFn`, which mirrors `XmipCreateModuleFn`. A
    // library exporting that name with another signature is a defect no host
    // can detect and conformance rule 1 forbids. The pointer is copied out,
    // so the borrow of `library` ends with this function.
    let found = unsafe { library.get::<CreateModuleFn>(symbol.as_bytes()) };

    found.map(|symbol| *symbol).map_err(|why| {
        format!(
            "{} exports no {XMIP_ENTRYPOINT}: {why}. Every conforming module \
             exports exactly that symbol",
            path.display()
        )
    })
}

impl Drop for LoadedModule {
    fn drop(&mut self) {
        if let Some(destroy) = self.module.destroy {
            // SAFETY: `state` came from this instance's own entrypoint call
            // and is destroyed exactly once, here, with no call in flight —
            // `&mut self` says there is none. Every string read out of this
            // module was copied at the call it arrived in, so no borrowed
            // pointer into the library is still held.
            unsafe { destroy(self.module.state) };
        }

        // `library` is dropped after this body returns, which is the order
        // specification section 3 requires: destroy, then unload.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_library_that_is_not_there_is_refused_naming_the_path() {
        let missing = Path::new("no_such_module_library.dll");

        let refusal = LoadedModule::open(missing, &Expectation::new("contract", 1, 0))
            .expect_err("nothing to open");

        assert!(refusal.contains("no_such_module_library"), "got: {refusal}");
        assert!(refusal.contains("would not open"), "got: {refusal}");
    }

    #[test]
    fn a_file_that_is_not_a_library_is_refused_rather_than_loaded() {
        // Cargo.toml is a real file and not an image for this platform, which
        // is the case an operator hits by pointing a path at a manifest.
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");

        let refusal = LoadedModule::open(&manifest, &Expectation::new("contract", 1, 0))
            .expect_err("a manifest is not a module");

        assert!(refusal.contains("would not open"), "got: {refusal}");
    }
}
