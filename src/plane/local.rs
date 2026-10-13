//! A node's local operate endpoint (ADR-0014, amendment 2026-10-13): the
//! operate listener on this machine, a named pipe on Windows and a Unix
//! domain socket elsewhere, which every surface on the machine reaches the
//! node through — gRPC over HTTP/2 as on the network, without TLS, because
//! the operating system proves who connected and admits only whom the
//! endpoint's permissions name (ADR-0063 clause 1: the one exception
//! inside one machine, said where it is made).
//!
//! **Who may open it** is the account the node runs as, the system and the
//! machine's administrators: on Windows the pipe's own security descriptor
//! (the owner, `SYSTEM` and `BUILTIN\Administrators`, and no caller from
//! another machine); on Unix the socket file's mode, `0600`, so the node's
//! account and the superuser. **Who acts** is the operating system user
//! the connecting process runs as, read from the connection, never a name
//! the caller says: `DOMAIN\user` on Windows, the user name elsewhere
//! (ADR-0009, amendment 2026-10-03).
//!
//! Where a name puts the endpoint is `net::pipe::path_of`, the one rule
//! the named pipe transport finds its pipe by.

#[cfg(unix)]
#[path = "local/unix.rs"]
mod system;
#[cfg(windows)]
#[path = "local/windows.rs"]
mod system;

pub(crate) use system::{Acceptor, Cancel, Stream, connect, wake};

/// Where the endpoint called `name` is on this system.
#[must_use]
pub fn path_of(name: &str) -> std::path::PathBuf {
    net::pipe::path_of(name)
}
