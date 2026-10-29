//! The Xmip runtime: a node started from its configuration, the message path
//! it runs, and the native library the operator surfaces load.
//!
//! [`running::Running::start`] runs ADR-0018's nine startup phases over a node's
//! configuration and the technologies the process was built with
//! ([`linked::Linked`]), loads each module the configuration needs once, and
//! runs every Message that arrives through [`arrival`], routing and the
//! Ledger, and [`send_step`] sends it from there through [`departure`], until
//! it is stopped. [`start`] is the first three phases
//! alone, for a surface that validates and plans a node without running it.
//!
//! Two builds (ADR-0014, amendment 2026-10-14). The `node` feature, the
//! default, is all of the above. The `remote` feature alone is a surface
//! that follows nodes over their operate listener and runs none, the
//! phone: [`plane`]'s surface end and the exports a surface reads with
//! (`xmip_operate.h` sections 7, 8, 9, 18 and section 17's client).

#[cfg(feature = "node")]
pub mod applied;
#[cfg(feature = "node")]
pub mod arrival;
#[cfg(feature = "node")]
pub mod budget;
#[cfg(feature = "node")]
pub mod capability_registry;
#[cfg(feature = "node")]
pub mod catalogue;
#[cfg(feature = "node")]
pub mod configured_subscription;
#[cfg(feature = "node")]
pub mod dead_message;
#[cfg(feature = "node")]
pub mod departure;
#[cfg(feature = "node")]
pub mod design;
#[cfg(feature = "node")]
pub mod directory_watch;
#[cfg(feature = "node")]
pub mod execution_tree;
pub mod ffi;
#[cfg(all(feature = "node", any(test, feature = "test-support")))]
pub mod fixture;
#[cfg(feature = "node")]
pub mod generation;
#[cfg(feature = "node")]
pub mod held_work;
#[cfg(feature = "node")]
pub mod host;
#[cfg(feature = "node")]
pub mod ledger;
#[cfg(feature = "node")]
pub mod library;
#[cfg(feature = "node")]
pub mod linked;
#[cfg(feature = "node")]
pub mod message_path;
#[cfg(feature = "node")]
pub mod operator;
#[cfg(feature = "node")]
pub mod operator_certificate;
#[cfg(feature = "node")]
pub mod outcome;
#[cfg(feature = "node")]
pub mod pickup;
#[cfg(feature = "remote")]
pub mod plane;
#[cfg(feature = "node")]
pub mod pool;
#[cfg(feature = "node")]
pub mod presented;
#[cfg(feature = "node")]
#[cfg(feature = "node")]
pub mod receive_certificate;
#[cfg(feature = "node")]
pub mod receiving;
#[cfg(feature = "node")]
pub mod recognized;
#[cfg(feature = "node")]
pub mod registration;
#[cfg(feature = "node")]
pub mod running;
#[cfg(feature = "node")]
pub mod secret;
#[cfg(feature = "node")]
pub mod secure_listener;
#[cfg(feature = "node")]
pub mod send_step;
#[cfg(feature = "node")]
pub mod sending;
#[cfg(feature = "node")]
pub mod sequence;
#[cfg(feature = "node")]
pub mod service;
#[cfg(feature = "node")]
pub mod service_control;
#[cfg(feature = "node")]
pub mod split;
#[cfg(feature = "node")]
pub mod start;
#[cfg(feature = "node")]
mod startup;
#[cfg(feature = "node")]
pub mod stopping;
#[cfg(feature = "node")]
pub mod storage;
#[cfg(feature = "node")]
pub mod stream_share;
#[cfg(feature = "node")]
pub mod tuning;
#[cfg(feature = "remote")]
mod wire;
#[cfg(feature = "node")]
pub mod work_step;
