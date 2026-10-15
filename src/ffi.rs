//! The runtime's C boundary, in one folder (ADR-0050, refined 2026-09-25):
//! the operator's table and the exports a surface calls (`xmip_operate.h`
//! sections 5 to 19, ADR-0027, ADR-0053, ADR-0064, ADR-0065, ADR-0013 and
//! ADR-0034) and the loader that opens a module's library and calls through
//! its table (ADR-0057), and the two Windows calls the local operate endpoint makes
//! (`system`; ADR-0014, amendment 2026-10-13). Unsafe
//! code is allowed in these files and nowhere else in the runtime; each file
//! lowers the crate's `deny` at its top, and `test/Unsafe.Test.ps1` holds the
//! folder.
//!
//! A remote build (`remote` without `node`) carries what a surface reads
//! and records with: sections 7, 8, 9 and 18, section 17's client, section
//! 19's request, and of sections 11, 14, 15 and 16 only what a read
//! publication carries; the rest is the node's.

#[cfg(feature = "remote")]
pub mod audit;
#[cfg(feature = "node")]
pub mod catalogue;
#[cfg(feature = "remote")]
pub mod certificate;
#[cfg(feature = "remote")]
pub mod curve;
#[cfg(feature = "remote")]
pub mod dead_message;
#[cfg(feature = "node")]
pub mod design;
#[cfg(feature = "remote")]
pub mod event;
#[cfg(feature = "remote")]
pub mod journey;
/// The contract trait of a loaded module (ADR-0057 clause 8 step 2).
#[cfg(feature = "dynamic-loading")]
pub mod loaded_contract;
/// Opening a module for real. Behind the feature that has always named it.
#[cfg(feature = "dynamic-loading")]
pub mod loaded_module;
#[cfg(feature = "node")]
pub mod operate;
#[cfg(feature = "node")]
pub mod order;
#[cfg(feature = "node")]
pub mod process;
#[cfg(feature = "remote")]
pub mod publication;
#[cfg(feature = "remote")]
pub mod remote;
/// The library pins itself when Windows loads it; `build.rs` does the same
/// for `dlclose` (`xmip_operate.h` section 1).
#[cfg(windows)]
pub mod resident;
#[cfg(feature = "remote")]
pub mod rule;
#[cfg(feature = "remote")]
pub mod security_role;
#[cfg(feature = "node")]
pub mod served;
#[cfg(feature = "node")]
pub mod start;
#[cfg(feature = "remote")]
pub mod subscription;
#[cfg(all(windows, feature = "remote"))]
pub(crate) mod system;
#[cfg(feature = "remote")]
mod text;
#[cfg(feature = "remote")]
pub mod topology;
