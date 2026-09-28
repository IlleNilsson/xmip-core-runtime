//! The Xmip runtime: a node started from its configuration, the message path
//! it runs, and the native library the operator surfaces load.
//!
//! [`running::Running::start`] runs ADR-0018's nine startup phases over a node's
//! configuration and the technologies the process was built with
//! ([`linked::Linked`]), loads each module the configuration needs once, and
//! runs every Message that arrives through [`arrival`], routing and
//! [`departure`] until it is stopped. [`start`] is the first three phases
//! alone, for a surface that validates and plans a node without running it.

pub mod arrival;
pub mod capability_registry;
pub mod catalogue;
pub mod departure;
pub mod design;
pub mod execution_tree;
pub mod ffi;
pub mod generation;
pub mod host;
pub mod library;
pub mod linked;
pub mod message_path;
pub mod operator;
pub mod outcome;
pub mod receiving;
pub mod registration;
pub mod running;
pub mod sending;
pub mod service;
pub mod start;
mod startup;
mod wire;
