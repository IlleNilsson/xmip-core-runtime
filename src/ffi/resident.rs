//! The runtime's library stays in the process once loaded (`xmip_operate.h`
//! section 1).
//!
//! The library starts threads of its own that outlive every call: the audit
//! keeper, which keeps records handed over on paths that must not wait, and
//! a listening Event subscription's thread. A program that unloaded the
//! library after its last call would unmap the code those threads run, and
//! the first of them to wake would fault - the C and C++ bindings did exactly
//! that when they closed the library after unsubscribing. So the library pins
//! itself when Windows loads it, and `FreeLibrary` releases the caller's
//! reference and nothing more. Elsewhere the link does the same:
//! `build.rs` links the library `-z nodelete`, which `dlclose` honors.
//!
//! In `ffi/`, the one folder of the runtime that may hold unsafe code
//! (ADR-0050, refined 2026-09-25): the operating system's loader is called.
#![allow(unsafe_code)]

use std::ffi::c_void;

/// `GET_MODULE_HANDLE_EX_FLAG_PIN`: the module stays until the process ends.
const PIN: u32 = 0x1;
/// `GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS`: the module is named by an
/// address inside it.
const FROM_ADDRESS: u32 = 0x4;
/// `DLL_PROCESS_ATTACH`.
const PROCESS_ATTACH: u32 = 1;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetModuleHandleExW(flags: u32, name: *const u16, module: *mut *mut c_void) -> i32;
}

/// The library's entry point: pins the library the moment it is loaded.
///
/// Windows calls it under the loader lock; `GetModuleHandleExW` takes that
/// lock again on the same thread, which is allowed, and loads nothing.
#[allow(
    non_snake_case,
    reason = "the name Windows calls a library's entry point by"
)]
#[unsafe(no_mangle)]
pub extern "system" fn DllMain(module: *mut c_void, reason: u32, _reserved: *mut c_void) -> i32 {
    if reason == PROCESS_ATTACH {
        stay_resident(module);
    }
    1
}

/// Pin the module holding `address` for the rest of the process: unloading
/// it afterwards releases a reference and never unmaps it. True when pinned.
pub fn stay_resident(address: *const c_void) -> bool {
    let mut module = core::ptr::null_mut();
    // SAFETY: with FROM_ADDRESS the name is only an address, never read as
    // text; the out pointer is a live local.
    unsafe { GetModuleHandleExW(PIN | FROM_ADDRESS, address.cast(), &raw mut module) != 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LoadLibraryW(name: *const u16) -> *mut c_void;
        fn FreeLibrary(module: *mut c_void) -> i32;
        fn GetModuleHandleW(name: *const u16) -> *mut c_void;
    }

    fn wide(name: &str) -> Vec<u16> {
        name.encode_utf16().chain([0]).collect()
    }

    /// Whether `name` is mapped in this process now.
    fn loaded(name: &[u16]) -> bool {
        // SAFETY: a null-terminated name; the handle is not kept.
        !unsafe { GetModuleHandleW(name.as_ptr()) }.is_null()
    }

    /// Load `name`, pin it or not, free it: whether it is still mapped.
    fn mapped_after_free(name: &str, pinned: bool) -> bool {
        let name = wide(name);
        assert!(!loaded(&name), "the test's library is loaded already");
        // SAFETY: a system library by a null-terminated name, freed once.
        let module = unsafe { LoadLibraryW(name.as_ptr()) };
        assert!(!module.is_null(), "the system library loads");
        if pinned {
            assert!(stay_resident(module), "pinned");
        }
        // SAFETY: the handle LoadLibraryW returned, freed once.
        assert_ne!(unsafe { FreeLibrary(module) }, 0);
        loaded(&name)
    }

    #[test]
    fn a_pinned_library_stays_mapped_after_it_is_freed() {
        // Two system libraries nothing in a test loads: one freed as it is,
        // proving freeing unmaps, and one pinned first, as the runtime is.
        assert!(!mapped_after_free("mscms.dll", false), "freeing unmaps");
        assert!(
            mapped_after_free("winmm.dll", true),
            "a pinned library stays"
        );
    }
}
