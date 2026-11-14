//! The module's timing program (`doc/governance/rust-style.md` section
//! 5c): the runtime held to how long Xmip takes — the millisecond rule
//! (`CONTRIBUTING.md`, *Rust is here for one reason*). A plain `cargo test`
//! leaves it out; the landing runs it after every other test of the
//! module, alone, one test at a time (`cargo test --test measured
//! --all-features -- --test-threads=1`), so what is measured is Xmip's work
//! and not its neighbors':
//!
//! - `running.rs`: a node carries every Message from its Receive Location
//!   to the far end, Xmip's own share of each under a millisecond, and
//!   eight senders side by side;
//! - `plane.rs`: a follower told as the publication advances, over
//!   loopback TLS and on the local endpoint, a connection on the local
//!   endpoint answered, and a node known unreachable said so at once;
//! - `gathered.rs`: a gatherer's view of a cluster drawing 176 things,
//!   related by role, assembled within a millisecond;
//! - `clustered.rs`: `Cluster` answered from a monitoring node's gathered
//!   view of nine members within a millisecond over loopback TLS, and that
//!   view written, once an assembly, within a millisecond of processor time;
//! - `acted.rs`: an operator's act asked at a node's door, written to Xmip
//!   Storage, taken by its node's act watch and answered within a
//!   millisecond beyond Xmip Storage's own writes, reads and wakes;
//! - `deadline.rs`: a node that does not answer within the wait is
//!   unreachable at once after;
//! - `membership.rs`: a node's stop with its Xmip Storage gone adds no more
//!   than a millisecond, its stop not written and said why;
//! - `relayed.rs`: proving a browser's caller to one node, or three at once,
//!   adds under a
//!   millisecond to its session's start;
//! - `due.rs`: a queue's retry woken for within a millisecond of its due
//!   time;
//! - `directory_watch.rs`: a dropped watch ends its thread at once;
//! - `sequenced_cost.rs` and `work_turn.rs`: what a hop's sequence check
//!   and a Work Process's turn cost, held in a release build;
//! - `woken.rs`: a Message another node published is sent over the wire,
//!   through one Storage node on `RocksDB`, within a millisecond of one the
//!   sending node published itself, each Storage call of the sending node
//!   timed (`fixture::Failing::taken`).
//!
//! What it stands up is the other test programs' own, shared, not copied:
//! `tests/running/node.rs`, `tests/plane/certified.rs`, `endpoint.rs` and
//! `browsing.rs`,
//! and `tests/ledger/receive_cycle.rs`, `sending.rs`, `work_design.rs` and
//! `said.rs`. Each is written for every test of its own program, so what
//! this program does not use of it is allowed here as dead.

#[allow(dead_code)]
#[path = "../plane/browsing.rs"]
mod browsing;
#[allow(dead_code)]
#[path = "../plane/certified.rs"]
mod certified;
#[allow(dead_code)]
#[path = "../plane/endpoint.rs"]
mod endpoint;
#[allow(dead_code)]
#[path = "../running/node.rs"]
mod node;
#[allow(dead_code)]
#[path = "../ledger/receive_cycle.rs"]
mod receive_cycle;
#[allow(dead_code)]
#[path = "../ledger/said.rs"]
mod said;
#[allow(dead_code)]
#[path = "../ledger/sending.rs"]
mod sending;
#[allow(dead_code)]
#[path = "../ledger/work_design.rs"]
mod work_design;

mod acted;
mod clustered;
mod deadline;
mod directory_watch;
mod due;
mod gathered;
mod membership;
mod plane;
mod relayed;
mod running;
mod sequenced_cost;
mod woken;
mod work_turn;

use said::say;
