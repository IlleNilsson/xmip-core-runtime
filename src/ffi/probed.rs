//! What a module library says when the host opens it and asks, or why it
//! could not be asked: the one probe every surface shows (ADR-0012,
//! amendment 2026-11-17), exported as `xmip_module_probe_v1`
//! (`xmip_operate.h` section 26) by xmip-core-operate.
//!
//! It opens the library the way a node opens one (`loaded_module.rs`:
//! privately, by its path, through its one entrypoint, with the host table a
//! node hands), keeps the lines the module logs on the way, and judges the
//! descriptor by `abi::validate_module_abi`, the rule a node's
//! `abi::accepts` starts with. A probe has no capability asking, so the
//! three facts only a loading capability can judge — the trait it answers
//! and its version — are said, not judged. Until 2026-11-17 the .NET
//! surfaces opened the library themselves and judged it by a rule of their
//! own, which refused a core module naming a standard where the header
//! says only a core module may name none.
//!
//! The probe makes and destroys one instance and unloads the library before
//! it answers: nothing of the module outlives the call. Only its tests
//! write unsafe code here: the entrypoints they link.

use std::path::Path;
use std::sync::{Arc, PoisonError};

use abi::ffi::{CreateModuleFn, status};
use abi::{ModuleDescriptor, validate_module_abi};
use libloading::Library;

use crate::ffi::host_table::Heard;
use crate::ffi::loaded_module::LoadedModule;

/// What a probe found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Probed {
    /// Why the library could not be asked — it is not there, is no library
    /// for this platform, or exports no `xmip_create_module_v1` — naming
    /// the path; empty when it was asked.
    pub unloadable: String,
    /// What the entrypoint returned, `XMIP_OK` where it made an instance;
    /// `XMIP_E_NOT_FOUND` where the library could not be asked.
    pub status: i32,
    /// What the module declares, where it made an instance.
    pub descriptor: Option<ModuleDescriptor>,
    /// The module's last error, read before it was destroyed.
    pub last_error: String,
    /// Why the host refuses it, one sentence: the entrypoint refused, or the
    /// descriptor is not one a host takes. Empty when nothing is wrong.
    pub refusal: String,
    /// The lines the module logged while it was held, in order.
    pub log: Vec<String>,
}

impl Probed {
    /// The library opened and its entrypoint was asked.
    #[must_use]
    pub const fn loaded(&self) -> bool {
        self.unloadable.is_empty()
    }

    /// It made an instance, declared what it is, and got nothing wrong.
    #[must_use]
    pub const fn conforms(&self) -> bool {
        self.loaded() && self.status == status::OK && self.refusal.is_empty()
    }
}

/// Open the library at `path`, ask its entrypoint for one instance, read
/// what it declares and its last error, destroy it and unload the library.
/// A library that cannot be asked is an answer, not an error.
#[must_use]
pub fn probe(path: &Path) -> Probed {
    match LoadedModule::resolved(path) {
        Err(unloadable) => Probed {
            unloadable,
            status: status::NOT_FOUND,
            ..Probed::default()
        },
        Ok((create, library)) => asked(path, create, Some(library)),
    }
}

/// A module whose entrypoint is linked into this test program, probed as a
/// library's would be.
#[cfg(test)]
fn linked(create: CreateModuleFn) -> Probed {
    asked(Path::new("linked"), create, None)
}

fn asked(path: &Path, create: CreateModuleFn, library: Option<Library>) -> Probed {
    let heard = Heard::default();
    let instance = LoadedModule::instance(path, create, library, Some(Arc::clone(&heard)));

    let mut probed = match instance {
        Err(refused) => Probed {
            status: refused.status,
            refusal: refused.sentence,
            ..Probed::default()
        },
        // Destroyed, and the library unloaded, as this arm ends, so the
        // lines it logs as it goes are heard too.
        Ok(loaded) => {
            let descriptor = loaded.descriptor().clone();
            Probed {
                status: status::OK,
                refusal: validate_module_abi(&descriptor).err().unwrap_or_default(),
                last_error: loaded.last_error(),
                descriptor: Some(descriptor),
                ..Probed::default()
            }
        }
    };

    probed.log = heard.lock().unwrap_or_else(PoisonError::into_inner).clone();
    probed
}

#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use std::ffi::c_void;

    use abi::XMIP_ABI_VERSION;
    use abi::ffi::{Host, Module, Str, WireDescriptor};

    use super::*;

    fn descriptor(
        abi_version: u32,
        provider: &'static str,
        standard: &'static str,
    ) -> WireDescriptor {
        WireDescriptor {
            abi_version,
            provider: Str::from_static(provider),
            module: Str::from_static("contract"),
            standard: Str::from_static(standard),
            trait_major: 1,
            trait_minor: 0,
            module_major: 0,
            module_minor: 1,
            module_patch: 2,
        }
    }

    unsafe extern "C" fn said(_state: *mut c_void) -> Str {
        Str::from_static("nothing failed yet")
    }

    unsafe extern "C" fn gone(_state: *mut c_void) {}

    /// Log one line through the table the host handed, then fill `*out`.
    ///
    /// # Safety
    /// As the header's entrypoint: `host` and `out` valid for the call.
    unsafe fn create(host: *const Host, out: *mut Module, wire: WireDescriptor) -> i32 {
        // SAFETY: the host passes a table that outlives the module, and
        // `out` is the host's to fill.
        unsafe {
            let host = &*host;
            if let Some(log) = host.log {
                log(
                    host.ctx,
                    3,
                    Str::from_static("probe"),
                    Str::from_static("created"),
                );
            }
            *out = Module {
                descriptor: wire,
                state: std::ptr::null_mut(),
                vtable: std::ptr::null(),
                last_error: Some(said),
                destroy: Some(gone),
            };
        }
        status::OK
    }

    unsafe extern "C" fn conforming(host: *const Host, out: *mut Module) -> i32 {
        // SAFETY: passed on whole from the host.
        unsafe { create(host, out, descriptor(XMIP_ABI_VERSION, "core", "rust")) }
    }

    unsafe extern "C" fn nameless(host: *const Host, out: *mut Module) -> i32 {
        // SAFETY: passed on whole from the host.
        unsafe { create(host, out, descriptor(XMIP_ABI_VERSION, "example", "")) }
    }

    unsafe extern "C" fn foreign(host: *const Host, out: *mut Module) -> i32 {
        // SAFETY: passed on whole from the host.
        unsafe { create(host, out, descriptor(XMIP_ABI_VERSION + 1, "core", "rust")) }
    }

    unsafe extern "C" fn refusing(host: *const Host, _out: *mut Module) -> i32 {
        // SAFETY: the host passes a table valid for the call.
        unsafe {
            let host = &*host;
            if let Some(log) = host.log {
                log(
                    host.ctx,
                    2,
                    Str::from_static("probe"),
                    Str::from_static("no"),
                );
            }
        }
        status::UNSUPPORTED
    }

    #[test]
    fn a_library_that_is_not_there_is_unloadable_naming_the_path() {
        let probed = probe(Path::new("no_such_module_library.dll"));

        assert!(!probed.loaded());
        assert!(!probed.conforms());
        assert_eq!(probed.status, status::NOT_FOUND);
        assert!(
            probed.unloadable.contains("no_such_module_library"),
            "{probed:?}"
        );
        assert!(probed.unloadable.contains("would not open"), "{probed:?}");
    }

    #[test]
    fn a_file_that_is_not_a_library_is_unloadable_rather_than_loaded() {
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");

        let probed = probe(&manifest);

        assert!(probed.unloadable.contains("would not open"), "{probed:?}");
        assert_eq!(probed.descriptor, None);
    }

    #[test]
    fn a_conforming_module_says_what_it_is_and_what_it_logged() {
        let probed = linked(conforming);
        let descriptor = probed.descriptor.clone().expect("it made an instance");

        assert!(probed.conforms(), "{probed:?}");
        assert_eq!(descriptor.provider, "core");
        assert_eq!(descriptor.standard, "rust");
        assert_eq!(descriptor.module_patch, 2);
        assert_eq!(probed.last_error, "nothing failed yet");
        assert_eq!(probed.log, ["[Info] probe: created"]);
    }

    #[test]
    fn a_core_module_naming_a_standard_conforms_and_a_provider_naming_none_is_refused() {
        // Header section 4: empty only when provider is core. The rule the
        // .NET probe kept until 2026-11-17 refused the first and took the
        // second.
        assert!(linked(conforming).refusal.is_empty());

        let refusal = linked(nameless).refusal;

        assert!(
            refusal.contains("only the core provider may omit one"),
            "{refusal}"
        );
    }

    #[test]
    fn another_abi_version_is_refused_naming_both() {
        let probed = linked(foreign);

        assert!(!probed.conforms());
        assert!(probed.refusal.contains("ABI version 2"), "{probed:?}");
        assert!(probed.refusal.contains("speaks 1"), "{probed:?}");
    }

    #[test]
    fn an_entrypoint_that_refuses_says_its_status_and_what_it_logged() {
        let probed = linked(refusing);

        assert!(probed.loaded());
        assert_eq!(probed.status, status::UNSUPPORTED);
        assert_eq!(probed.descriptor, None);
        assert!(
            probed.refusal.contains("refused to create a module"),
            "{probed:?}"
        );
        assert_eq!(probed.log, ["[Warn] probe: no"]);
    }
}
