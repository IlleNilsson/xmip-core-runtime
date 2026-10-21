//! The local operate endpoint on Windows: a named pipe under `\\.\pipe\`,
//! made, connected, read and written in `net::pipe`, the estate's one
//! pipe, which the named pipe transport makes its pipe through too.
//!
//! **Who may open it** is its security descriptor's to say: the account
//! that made it — the node's — the system and the machine's
//! administrators, fully; each account or group `[operate] admit` names,
//! to read and write it and no more; nobody else, and no caller from
//! another machine. **Who connected** is the account the client's token
//! names, lent for identification alone: every surface opens the pipe so
//! (`net::pipe::connect`), and the node reads the account and can never
//! act as it (open problem 35).
//!
//! A pipe has no read timeout, so a read waiting on its peer is ended by
//! [`Cancel`] — the I/O on the pipe cancelled from another thread — where
//! a socket's is ended by `net::watched` looking between short timeouts.
//! Until 2026-10-21 the runtime's own `ffi::pipe`, `ffi::pipe_io` and
//! `ffi::system` made, read and wrote it.

use std::io::{Read, Write};
use std::path::Path;
use std::time::Duration;

pub(crate) use net::pipe::Cancel;

/// The made end, waiting for a connection.
#[cfg(feature = "node")]
pub(crate) struct Acceptor(net::pipe::Listener);

#[cfg(feature = "node")]
impl Acceptor {
    /// Make the pipe at `path`, opened only by the node's account, the
    /// system, the administrators and whom `admitting` names, and never
    /// from another machine; a pipe has no group of its own, so
    /// `admitting.group` says nothing here.
    ///
    /// # Errors
    ///
    /// A name Windows does not permit, a pipe of that name another process
    /// already made, or an admitted name Windows does not know.
    pub(crate) fn bind(path: &Path, admitting: super::Admitting<'_>) -> Result<Self, String> {
        net::pipe::Listener::bind(path, admitting.admit)
            .map(Self)
            .map_err(|error| format!("{}: {error}", path.display()))
    }

    /// The next connection; waits until a client has connected.
    ///
    /// # Errors
    ///
    /// The pipe's own failure.
    pub(crate) fn accept(&self) -> std::io::Result<Stream> {
        // bounded: a listener waits as long as its node runs; a stop wakes it
        self.0.accept(None).map(Stream)
    }
}

/// One connection, either end.
pub(crate) struct Stream(net::pipe::Stream);

impl Stream {
    /// The account the connecting process runs as, `DOMAIN\user`, by its
    /// token's word (`net::pipe::Stream::caller`).
    ///
    /// # Errors
    ///
    /// Where Windows does not say, or the client sent nothing.
    #[cfg(feature = "node")]
    pub(crate) fn caller(&mut self) -> Result<String, String> {
        self.0.caller()
    }

    /// A pipe has no read timeout: a wait is ended by [`Cancel`].
    #[allow(clippy::unnecessary_wraps, clippy::unused_self)]
    pub(crate) fn watch(&self, _: Duration) -> std::io::Result<()> {
        Ok(())
    }

    /// What ends a read waiting on this connection, from another thread.
    pub(crate) fn cancel(&self) -> Cancel {
        self.0.cancel()
    }
}

impl Read for Stream {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buffer)
    }
}

impl Write for Stream {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.write(bytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

/// Connect to the pipe at `path`, lending the node this process's account
/// for identification alone, waiting at most `patience` for an instance
/// to be free.
///
/// # Errors
///
/// No pipe there, or none free within `patience`, in words.
pub(crate) fn connect(path: &Path, patience: Duration) -> Result<Stream, String> {
    net::pipe::connect(path, Some(patience))
        .map(Stream)
        .map_err(|error| format!("{}: {error}", path.display()))
}

/// Wake a listener waiting at `path` for a connection; whether it connected.
#[cfg(feature = "node")]
pub(crate) fn wake(path: &Path) -> bool {
    connect(path, Duration::from_secs(1)).is_ok()
}
