//! The runtime's C boundary, in one folder (ADR-0050, refined 2026-09-25):
//! the operator's table and the exports a surface calls (`xmip_operate.h`
//! sections 5 to 14, ADR-0027, ADR-0053, ADR-0064, ADR-0065 and ADR-0013)
//! and the loader that opens a module's library and calls through its table
//! (ADR-0057). Unsafe
//! code is allowed in these files and nowhere else in the runtime; each file
//! lowers the crate's `deny` at its top, and `test/Unsafe.Test.ps1` holds the
//! folder.

pub mod audit;
pub mod catalogue;
pub mod curve;
pub mod design;
pub mod event;
/// The contract trait of a loaded module (ADR-0057 clause 8 step 2).
#[cfg(feature = "dynamic-loading")]
pub mod loaded_contract;
/// Opening a module for real. Behind the feature that has always named it.
#[cfg(feature = "dynamic-loading")]
pub mod loaded_module;
pub mod operate;
pub mod order;
pub mod process;
pub mod publication;
/// The library pins itself when Windows loads it; `build.rs` does the same
/// for `dlclose` (`xmip_operate.h` section 1).
#[cfg(windows)]
pub mod resident;
pub mod rule;
pub mod start;
pub mod subscription;
pub mod topology;
