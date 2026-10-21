//! The local operate endpoint on Unix: a Unix domain socket in the node's
//! runtime folder, `/run/xmip/` on Linux and `/var/run/xmip/` on macOS.
//!
//! **Who may open it**: the node's account and the superuser always, and
//! each user or group `[operate] admit` names; nobody else. The kernel
//! says who connected (`SO_PEERCRED` on Linux, `getpeereid` elsewhere) and
//! the node judges that account against the admitted, so a caller nobody
//! admitted is refused in words. The socket file is `0600` where nobody
//! else is admitted, so the file system refuses everyone else first; it
//! is `0666` where some are, and the kernel's word is the gate. **The
//! folder** must be the node's account's or the superuser's and writable
//! by nobody else, or a stranger could put a socket of their own where a
//! surface looks; a node refuses to make its endpoint in any other (open
//! problem 35).
//!
//! A socket has a read timeout, so a read waiting on its peer is ended by
//! `net::watched` looking between short ones, and [`Cancel`] has nothing
//! to do.

use std::io::{Read, Write};
#[cfg(feature = "node")]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
#[cfg(feature = "node")]
use std::os::unix::net::UnixListener;
use std::os::unix::net::UnixStream;
use std::path::Path;
#[cfg(feature = "node")]
use std::path::PathBuf;
#[cfg(feature = "node")]
use std::sync::Arc;
use std::time::Duration;

#[cfg(feature = "node")]
use nix::unistd::{Gid, Group, Uid, User};

/// Who the node admits beside its own account and the superuser: the
/// users and the groups `[operate] admit` names, each as the system
/// numbers it.
#[cfg(feature = "node")]
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Admitted {
    users: Vec<u32>,
    groups: Vec<u32>,
}

#[cfg(feature = "node")]
impl Admitted {
    /// The users and groups `names` name; a name that is both is both.
    ///
    /// # Errors
    ///
    /// A name the system knows no user or group by, in words.
    pub(crate) fn named(names: &[String]) -> Result<Self, String> {
        let mut admitted = Self::default();
        for name in names {
            let user = User::from_name(name).ok().flatten();
            let group = Group::from_name(name).ok().flatten();
            if user.is_none() && group.is_none() {
                return Err(format!(
                    "the system knows no user or group called \"{name}\""
                ));
            }
            admitted.users.extend(user.map(|user| user.uid.as_raw()));
            admitted
                .groups
                .extend(group.map(|group| group.gid.as_raw()));
        }
        Ok(admitted)
    }

    /// Whether the account `uid`, whose primary group is `gid`, may open
    /// the endpoint of a node running as `node`.
    fn admits(&self, uid: u32, gid: u32, node: u32) -> bool {
        uid == node
            || uid == 0
            || self.users.contains(&uid)
            || self
                .groups
                .iter()
                .any(|&group| group == gid || member(uid, group))
    }
}

/// Whether the account `uid` is a member of the group `gid` beyond its
/// primary group, as the system's group list says now.
#[cfg(feature = "node")]
fn member(uid: u32, gid: u32) -> bool {
    let Some(user) = User::from_uid(Uid::from_raw(uid)).ok().flatten() else {
        return false;
    };
    Group::from_gid(Gid::from_raw(gid))
        .ok()
        .flatten()
        .is_some_and(|group| group.mem.contains(&user.name))
}

/// The made end, waiting for a connection; its socket file goes with it.
#[cfg(feature = "node")]
pub(crate) struct Acceptor {
    inner: UnixListener,
    path: PathBuf,
    admitted: Arc<Admitted>,
}

#[cfg(feature = "node")]
impl Acceptor {
    /// Make the socket at `path`, for the node's account and whom
    /// `admitted` names. A socket file a node that stopped left behind is
    /// replaced; one a running node answers on is not.
    ///
    /// # Errors
    ///
    /// A folder others may write or someone else owns, a name the system
    /// does not know, a path that cannot be bound, or one another node
    /// listens on.
    pub(crate) fn bind(path: &Path, admitted: &[String]) -> Result<Self, String> {
        let said = |error: &dyn std::fmt::Display| format!("{}: {error}", path.display());
        let admitted = Arc::new(Admitted::named(admitted)?);
        guarded(path.parent().unwrap_or_else(|| Path::new("/")))?;
        if path.exists() {
            if UnixStream::connect(path).is_ok() {
                return Err(said(&"another node listens there"));
            }
            std::fs::remove_file(path).map_err(|e| said(&e))?;
        }
        let inner = UnixListener::bind(path).map_err(|e| said(&e))?;
        let mode = if *admitted == Admitted::default() {
            0o600
        } else {
            0o666
        };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .map_err(|e| said(&e))?;
        Ok(Self {
            inner,
            path: path.to_path_buf(),
            admitted,
        })
    }

    /// The next connection; waits until one comes.
    ///
    /// # Errors
    ///
    /// The socket's own failure.
    pub(crate) fn accept(&self) -> std::io::Result<Stream> {
        // bounded: a listener waits as long as its node runs; a stop wakes it
        self.inner.accept().map(|(stream, _)| Stream {
            socket: stream,
            admitted: Some(Arc::clone(&self.admitted)),
        })
    }
}

#[cfg(feature = "node")]
impl Drop for Acceptor {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Whether `folder` is fit to hold a node's endpoint: there, the node's
/// account's or the superuser's, and writable by nobody else.
///
/// # Errors
///
/// What makes it unfit, in words.
#[cfg(feature = "node")]
pub(crate) fn guarded(folder: &Path) -> Result<(), String> {
    let found = std::fs::metadata(folder).map_err(|error| {
        format!(
            "{}: {error}; the service manager makes it for the node's account",
            folder.display()
        )
    })?;
    let node = nix::unistd::geteuid().as_raw();
    if found.uid() != node && found.uid() != 0 {
        return Err(format!(
            "{} belongs to uid {}, not the node's account or the superuser",
            folder.display(),
            found.uid()
        ));
    }
    if found.mode() & 0o022 != 0 {
        return Err(format!(
            "{} may be written by others (mode {:o}); a local endpoint is made only in a \
             folder only its owner writes",
            folder.display(),
            found.mode() & 0o7777
        ));
    }
    Ok(())
}

/// One connection, either end.
pub(crate) struct Stream {
    socket: UnixStream,
    /// Who the node admits, on the node's end; nothing on a surface's.
    #[cfg(feature = "node")]
    admitted: Option<Arc<Admitted>>,
}

impl Stream {
    /// The account the connecting process runs as, by the kernel's word:
    /// its name where the system names it, else `uid` and the number —
    /// where the node admits it.
    ///
    /// # Errors
    ///
    /// Where the kernel does not say, or the account is not admitted.
    #[cfg(feature = "node")]
    pub(crate) fn caller(&mut self) -> Result<String, String> {
        let (uid, gid) =
            peer(&self.socket).map_err(|error| format!("the caller is not known: {error}"))?;
        let name = User::from_uid(Uid::from_raw(uid))
            .ok()
            .flatten()
            .map_or_else(|| format!("uid {uid}"), |user| user.name);
        let node = nix::unistd::geteuid().as_raw();
        if self
            .admitted
            .as_ref()
            .is_some_and(|admitted| admitted.admits(uid, gid, node))
        {
            Ok(name)
        } else {
            Err(format!(
                "REFUSED. {name} is not admitted to this node's local endpoint: \
                 [operate] admit names who may open it beside the node's account"
            ))
        }
    }

    /// Wait at most `within` on each read, so `net::watched` looks between.
    ///
    /// # Errors
    ///
    /// The socket's own failure.
    pub(crate) fn watch(&self, within: Duration) -> std::io::Result<()> {
        self.socket.set_read_timeout(Some(within))
    }

    /// What ends a read waiting on this connection: nothing to do here.
    #[allow(clippy::unused_self)]
    pub(crate) fn cancel(&self) -> Cancel {
        Cancel
    }
}

/// The account and primary group the connecting process runs as.
#[cfg(all(feature = "node", any(target_os = "linux", target_os = "android")))]
fn peer(stream: &UnixStream) -> nix::Result<(u32, u32)> {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
    getsockopt(stream, PeerCredentials).map(|credentials| (credentials.uid(), credentials.gid()))
}

/// The account and primary group the connecting process runs as.
#[cfg(all(feature = "node", not(any(target_os = "linux", target_os = "android"))))]
fn peer(stream: &UnixStream) -> nix::Result<(u32, u32)> {
    nix::unistd::getpeereid(stream).map(|(uid, gid)| (uid.as_raw(), gid.as_raw()))
}

impl Read for Stream {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.socket.read(buffer)
    }
}

impl Write for Stream {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.socket.write(bytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.socket.flush()
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
    let socket = UnixStream::connect(path).map_err(|e| format!("{}: {e}", path.display()))?;
    socket
        .set_write_timeout(Some(patience))
        .map_err(|error| error.to_string())?;
    Ok(Stream {
        socket,
        #[cfg(feature = "node")]
        admitted: None,
    })
}

/// Wake a listener waiting at `path` for a connection; whether it connected.
#[cfg(feature = "node")]
pub(crate) fn wake(path: &Path) -> bool {
    UnixStream::connect(path).is_ok()
}

#[cfg(all(test, feature = "node"))]
mod tests {
    use super::*;

    #[test]
    fn the_node_and_the_superuser_are_admitted_and_others_only_where_named() {
        let none = Admitted::default();
        assert!(none.admits(1000, 1000, 1000), "the node's own account");
        assert!(none.admits(0, 0, 1000), "the superuser");
        assert!(!none.admits(1001, 1001, 1000), "nobody else");
        let named = Admitted {
            users: vec![1002],
            groups: vec![2000],
        };
        assert!(named.admits(1002, 1002, 1000), "a named user");
        assert!(named.admits(1003, 2000, 1000), "a named primary group");
        assert!(!named.admits(1004, 1004, 1000), "nobody else");
    }

    #[test]
    fn a_name_nobody_has_is_refused_and_a_folder_others_write_is_unfit() {
        let nobody = Admitted::named(&["xmip-no-such-account".to_string()]).unwrap_err();
        assert!(nobody.contains("knows no user or group"), "{nobody}");
        assert_eq!(
            Admitted::named(&["root".to_string()]).map(|a| a.users),
            Ok(vec![0])
        );
        let open = std::env::temp_dir().join(format!("xmip-unfit-{}", std::process::id()));
        std::fs::create_dir_all(&open).expect("a folder");
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).expect("open");
        let unfit = guarded(&open).unwrap_err();
        assert!(unfit.contains("may be written by others"), "{unfit}");
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755)).expect("shut");
        assert_eq!(guarded(&open), Ok(()));
        std::fs::remove_dir(&open).expect("removed");
    }
}
