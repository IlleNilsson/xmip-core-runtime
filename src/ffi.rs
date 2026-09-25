//! The runtime's C boundary, in one folder (ADR-0050, refined 2026-09-25):
//! the operator's table and the exports a surface calls (`xmip_operate.h`
//! sections 5 to 9, ADR-0027) and the loader that opens a module's library
//! and calls through its table (ADR-0057). Unsafe code is allowed in these
//! files and nowhere else in the runtime; each file lowers the crate's
//! `deny` at its top, and `test/Unsafe.Test.ps1` holds the folder.

pub mod audit;
pub mod curve;
/// The contract trait of a loaded module (ADR-0057 clause 8 step 2).
#[cfg(feature = "dynamic-loading")]
pub mod loaded_contract;
/// Opening a module for real. Behind the feature that has always named it.
#[cfg(feature = "dynamic-loading")]
pub mod loaded_module;
pub mod operate;
pub mod publication;
pub mod rule;
pub mod start;
