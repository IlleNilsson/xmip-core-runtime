//! The runtime's C boundary facing in, in one folder (ADR-0050, refined
//! 2026-09-25): the loader that opens a module's library and calls through
//! its table (ADR-0057), and the Windows calls a directory watch makes
//! (`directory_watch`; ADR-0018, amendment 2026-10-17). The boundary facing
//! out, the operator's table and the exports a surface calls
//! (`xmip_operate.h`), is xmip-core-operate's (ADR-0050, amendment
//! 2026-11-16). Unsafe code is allowed in these files and nowhere else in the
//! runtime; each file lowers the crate's `deny` at its top, and
//! `test/Unsafe.Test.ps1` holds the folder.

#[cfg(all(windows, feature = "node"))]
pub(crate) mod directory_watch;
/// The table a module is created with (`XmipHost`), kept beside it.
#[cfg(feature = "loader")]
pub(crate) mod host_table;
/// The contract trait of a loaded module (ADR-0057 clause 8 step 2).
#[cfg(feature = "dynamic-loading")]
pub mod loaded_contract;
/// Opening a module for real: what a node opens with, and what a probe
/// asks through.
#[cfg(feature = "loader")]
pub mod loaded_module;
/// The work process trait of a loaded module: a Work Process unit compiled
/// from a design (ADR-0066, amendment 2026-10-22).
#[cfg(feature = "dynamic-loading")]
pub mod loaded_work_process;
/// What a module library declares, judged once for every surface
/// (`xmip_module_probe_v1`; ADR-0012, amendment 2026-11-17).
#[cfg(feature = "loader")]
pub mod probed;
