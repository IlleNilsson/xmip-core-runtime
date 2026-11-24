//! The lifecycle every trait table begins with (`include/xmip_module.h`
//! section 8), driven alike whichever table it heads: `configure` once,
//! before `start`, with the artifact's TOML fragment; `start` and `stop` in
//! that order, as often as asked; calls on the trait itself only between
//! them. A contract's table and a Promote unit's are driven through here.
#![allow(unsafe_code)]

use std::ffi::c_void;

use abi::ffi::{Str, VtableHeader, status};

use crate::ffi::loaded_module::LoadedModule;

/// `configure`, `start` and `stop` differ only in what they are called; the
/// first also takes the artifact's TOML fragment.
type LifecycleFn = unsafe extern "C" fn(*mut c_void) -> i32;

/// The header of one loaded module's table, borrowed for as long as the
/// module is held.
pub struct Lifecycle<'a> {
    module: &'a LoadedModule,
    header: &'a VtableHeader,
}

impl<'a> Lifecycle<'a> {
    /// The lifecycle of `module` through `header`, the head of the table its
    /// descriptor names, which the table's own file has selected.
    pub(crate) const fn of(module: &'a LoadedModule, header: &'a VtableHeader) -> Self {
        Self { module, header }
    }

    /// `configure`, once, before `start`, with the artifact's TOML fragment.
    ///
    /// # Errors
    /// A table with no `configure`, or the module's own status.
    pub fn configure(&self, toml: &str) -> Result<(), String> {
        let Some(call) = self.header.configure else {
            return Err(format!("{} carries no configure", self.module.descriptor()));
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
    /// A table with no `start`, or the module's own status.
    pub fn start(&self) -> Result<(), String> {
        self.call("start", self.header.start)
    }

    /// # Errors
    /// A table with no `stop`, or the module's own status. Conformance rule 7
    /// makes this legal even where `start` never ran.
    pub fn stop(&self) -> Result<(), String> {
        self.call("stop", self.header.stop)
    }

    fn call(&self, what: &str, call: Option<LifecycleFn>) -> Result<(), String> {
        let Some(call) = call else {
            return Err(format!("{} carries no {what}", self.module.descriptor()));
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
            self.module.descriptor(),
            self.module.last_error()
        ))
    }
}
