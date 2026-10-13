//! The operate plane (ADR-0067): how an operator surface reads and follows
//! a node on another machine, and acts on it — over gRPC on TCP to the
//! node's operate listener, inside Xmip's mutual TLS (ADR-0014, amendment
//! 2026-10-12; ADR-0052, amendment 2026-10-05; ADR-0063). SignalR stays
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

pub mod board;
pub mod call;
mod follow;
mod line;
pub mod listener;
pub mod remote;
pub mod role;
pub mod served;

pub use board::{Board, Published};
pub use line::host_of;
pub use listener::Listener;
pub use remote::{Outcome, Remote, State};
pub use role::Role;
