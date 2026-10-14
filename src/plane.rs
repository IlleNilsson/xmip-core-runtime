//! The operate plane (ADR-0067): how an operator surface reads and follows
//! a node, and acts on it — over gRPC to the node's operate listener: on
//! TCP inside Xmip's mutual TLS from another machine (ADR-0014, amendment
//! 2026-10-12; ADR-0063), on the node's local endpoint, a named pipe or a
//! Unix domain socket, from its own (ADR-0014, amendment 2026-10-13;
//! ADR-0052, amendment 2026-10-05). Every .NET surface operates a node
//! this way, on its machine and elsewhere alike. SignalR stays
//! between a web host and the browser it serves, and running a command on
//! another machine stays shell remoting (ADR-0014 clause 6).
//!
//! Both ends are here, once. The node's side is a [`Listener`] serving what
//! a [`Published`] holds — a [`Board`] the program running the node posts
//! its publication to — and the acts on the nodes of its process, each
//! admitted by the caller's [`Role`] and audited. The surface's side is
//! [`Remote`], exported through `xmip_operate.h` section 17 so every
//! language's surface follows a node the same way.
//!
//! **gRPC on Xmip's own stack.** The estate speaks HTTP/2 itself
//! (`net::http2`, with HPACK) and TLS itself (`xmip-core-library-tls`), and
//! the gRPC logic technology already frames on them (`net::grpc`); so the
//! plane takes no gRPC crate and no async runtime — a connection is a
//! thread, as every protocol in the estate is. The messages are JSON
//! (`application/grpc+json`): the estate keeps JSON for memory and the
//! wire, and the publication they carry is the TOML its file holds, read
//! by the one reader every surface reads with.

#[cfg(feature = "node")]
pub mod board;
pub mod call;
pub mod deadline;
mod follow;
mod line;
#[cfg(feature = "node")]
pub mod listener;
pub mod local;
pub mod remote;
pub mod role;
#[cfg(feature = "node")]
pub mod served;
mod shared;

#[cfg(feature = "node")]
pub use board::{Board, Published};
pub use line::host_of;
#[cfg(feature = "node")]
pub use listener::Listener;
pub use remote::{Outcome, Remote, State};
pub use role::Role;
