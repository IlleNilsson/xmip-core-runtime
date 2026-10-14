//! The local operate endpoint on Unix: a Unix domain socket, its file
//! `0600`, so the node's account and the superuser connect and nobody else.
//!
//! A socket has a read timeout, so a read waiting on its peer is ended by
//! `net::watched` looking between short ones, and [`Cancel`] has nothing
//! to do.

use std::io::{Read, Write};
#[cfg(feature = "node")]
use std::os::unix::fs::PermissionsExt;
#[cfg(feature = "node")]
use std::os::unix::net::UnixListener;
use std::os::unix::net::UnixStream;
use std::path::Path;
#[cfg(feature = "node")]
use std::path::PathBuf;
use std::time::Duration;

/// The made end, waiting for a connection; its socket file goes with it.
#[cfg(feature = "node")]
pub(crate) struct Acceptor {
    inner: UnixListener,
    path: PathBuf,
}

#[cfg(feature = "node")]
impl Acceptor {
    /// Make the socket at `path`, readable and writable by its owner only.
    /// A socket file a node that stopped left behind is replaced; one a
    /// running node answers on is not.
    ///
    /// # Errors
    ///
    /// A path that cannot be bound, or one another node listens on.
    pub(crate) fn bind(path: &Path) -> Result<Self, String> {
        if path.exists() {
            if UnixStream::connect(path).is_ok() {
                return Err(format!("{}: another node listens there", path.display()));
            }
            std::fs::remove_file(path).map_err(|e| format!("{}: {e}", path.display()))?;
        }
        let inner = UnixListener::bind(path).map_err(|e| format!("{}: {e}", path.display()))?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("{}: {e}", path.display()))?;
        Ok(Self {
            inner,
            path: path.to_path_buf(),
        })
    }

    /// The next connection; waits until one comes.
    ///
    /// # Errors
    ///
    /// The socket's own failure.
    pub(crate) fn accept(&self) -> std::io::Result<Stream> {
        // bounded: a listener waits as long as its node runs; a stop wakes it
        self.inner.accept().map(|(stream, _)| Stream(stream))
    }
}

#[cfg(feature = "node")]
impl Drop for Acceptor {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// One connection, either end.
pub(crate) struct Stream(UnixStream);

impl Stream {
    /// The user the connecting process runs as, by the kernel's word: its
    /// name where the system names it, else `uid` and the number.
    ///
    /// # Errors
    ///
    /// Where the kernel does not say.
    #[cfg(feature = "node")]
    pub(crate) fn caller(&mut self) -> Result<String, String> {
        let uid = peer_uid(&self.0).map_err(|error| format!("the caller is not known: {error}"))?;
        Ok(nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
            .ok()
            .flatten()
            .map_or_else(|| format!("uid {uid}"), |user| user.name))
    }

    /// Wait at most `within` on each read, so `net::watched` looks between.
    ///
    /// # Errors
    ///
    /// The socket's own failure.
    pub(crate) fn watch(&self, within: Duration) -> std::io::Result<()> {
        self.0.set_read_timeout(Some(within))
    }

    /// What ends a read waiting on this connection: nothing to do here.
    #[allow(clippy::unused_self)]
    pub(crate) fn cancel(&self) -> Cancel {
        Cancel
    }
}

#[cfg(all(feature = "node", any(target_os = "linux", target_os = "android")))]
fn peer_uid(stream: &UnixStream) -> nix::Result<u32> {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
    getsockopt(stream, PeerCredentials).map(|credentials| credentials.uid())
}

#[cfg(all(feature = "node", not(any(target_os = "linux", target_os = "android"))))]
fn peer_uid(stream: &UnixStream) -> nix::Result<u32> {
    nix::unistd::getpeereid(stream).map(|(uid, _)| uid.as_raw())
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

/// A read on a socket ends by its timeout; nothing to cancel.
pub(crate) struct Cancel;

impl Cancel {
    #[allow(clippy::unused_self)]
    pub(crate) const fn cancel(&self) {}
}

/// Connect to the socket at `path`.
///
/// # Errors
///
/// No socket there, or nobody listening, in words.
pub(crate) fn connect(path: &Path, patience: Duration) -> Result<Stream, String> {
    let stream = UnixStream::connect(path).map_err(|e| format!("{}: {e}", path.display()))?;
    stream
        .set_write_timeout(Some(patience))
        .map_err(|error| error.to_string())?;
    Ok(Stream(stream))
}

/// Wake a listener waiting at `path` for a connection.
#[cfg(feature = "node")]
pub(crate) fn wake(path: &Path) {
    let _ = UnixStream::connect(path);
}
