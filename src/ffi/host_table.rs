//! The host table a module is created with, `XmipHost`: header section 6.
//! A module gets no allocator, no thread pool, no clock and no
//! configuration store, and may call the three callbacks here at any time
//! between create and destroy. The table is boxed and kept by the
//! [`LoadedModule`](crate::ffi::loaded_module::LoadedModule) it was handed
//! to, so it outlives the module, as header section 7 requires.
//!
//! Every callback runs its body through `abi::guarded`, the boundary's one
//! guard: unwinding crosses in neither direction (ADR-0012 clause 8;
//! specification section 6).
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::sync::{Arc, Mutex, PoisonError};

use abi::XMIP_ABI_VERSION;
use abi::ffi::{Host, Str};

use crate::ffi::loaded_module::read_str;

/// The lines a module logs while a probe holds it, each as
/// `[<level>] <target>: <message>`, which the probe shows. A node hands its
/// modules none: their lines are discarded, honestly, until routing them
/// into `xmip-core-observe` is built.
pub(crate) type Heard = Arc<Mutex<Vec<String>>>;

/// The table, boxed, its `ctx` lending `heard` where one is given.
pub(crate) fn host_table(heard: Option<&Heard>) -> Box<Host> {
    Box::new(Host {
        abi_version: XMIP_ABI_VERSION,
        ctx: heard.map_or(std::ptr::null_mut(), |heard| {
            Arc::as_ptr(heard).cast_mut().cast()
        }),
        log: Some(log),
        cancelled: Some(never_cancelled),
        journey_id: Some(no_journey),
    })
}

/// The one log callback: the line into the [`Heard`] `ctx` points at, or
/// nowhere where `ctx` is null — a null function pointer is not the way to
/// say so, since a module is entitled to call what the table carries.
unsafe extern "C" fn log(ctx: *mut c_void, level: i32, target: Str, message: Str) {
    abi::guarded((), || {
        if ctx.is_null() {
            return;
        }

        // SAFETY: a non-null `ctx` is the `Mutex` inside the `Heard` whose
        // clone the `LoadedModule` holding this table keeps, so it lives
        // until after `destroy`; a module calls this only between create
        // and destroy (header section 6).
        let heard = unsafe { &*ctx.cast_const().cast::<Mutex<Vec<String>>>() };
        let line = format!(
            "[{}] {}: {}",
            level_word(level),
            read_str(target),
            read_str(message)
        );
        heard
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(line);
    });
}

/// Header section 6's level, as the line says it: its name, or its number
/// where the header names none.
fn level_word(level: i32) -> String {
    match level {
        1 => "Error".to_string(),
        2 => "Warn".to_string(),
        3 => "Info".to_string(),
        4 => "Debug".to_string(),
        5 => "Trace".to_string(),
        other => other.to_string(),
    }
}

/// Nothing this host asks a module to do today is cancellable, so the answer
/// is always no.
unsafe extern "C" fn never_cancelled(_ctx: *mut c_void) -> i32 {
    abi::guarded(0, || 0)
}

/// Empty, which header section 6 makes the right answer for a module running
/// outside a journey — and a module loaded to be verified is.
unsafe extern "C" fn no_journey(_ctx: *mut c_void) -> Str {
    abi::guarded(Str::empty(), Str::empty)
}
