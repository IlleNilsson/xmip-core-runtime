//! The local operate endpoint on Unix: a Unix domain socket in the node's
//! runtime folder, `/run/xmip/` on Linux and `/var/run/xmip/` on macOS.
//!
//! **Who may open it**: the node's account and the superuser always, and
//! each user or group `[operate] admit` names; nobody else. The kernel
//! says who connected (`SO_PEERCRED` on Linux, `getpeereid` elsewhere) and
//! the node judges that account against the admitted, so a caller nobody
//! admitted is refused in words. The socket file is `0600` where nobody
//! else is admitted, so the file system refuses everyone else first. Where
//! some are it is `0660` and belongs to a group — the one `[operate]
//! group` names, the node's own where it is left out — so the file system
//! is still the first gate, letting only that group's members connect, and
//! the kernel's word against the admitted the second (the owner,
//! 2026-10-21, where it was `0666` and the kernel's word the only gate). An
//! admitted account outside the group is refused by the file system.
//! **The folder** must be the node's account's or the superuser's and writable
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

/// The group a shared socket belongs to, and its name: the one `named`
/// names, or the node's own where it names none.
///
/// # Errors
///
/// A group the system does not know, in words.
#[cfg(feature = "node")]
fn socket_group(named: Option<&str>) -> Result<(Gid, String), String> {
    let Some(name) = named else {
        let own = nix::unistd::getegid();
        let name = Group::from_gid(own)
            .ok()
            .flatten()
            .map_or_else(|| format!("gid {own}"), |group| group.name);
        return Ok((own, name));
    };
    Group::from_name(name)
        .ok()
        .flatten()
        .map(|group| (group.gid, group.name))
        .ok_or_else(|| format!("[operate] group: the system knows no group called \"{name}\""))
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
    /// `admitting` names. A socket file a node that stopped left behind is
    /// replaced; one a running node answers on is not.
    ///
    /// # Errors
    ///
    /// A folder others may write or someone else owns, a name the system
    /// does not know, a group the node's account may not give the socket,
    /// a path that cannot be bound, or one another node listens on.
    pub(crate) fn bind(path: &Path, admitting: super::Admitting<'_>) -> Result<Self, String> {
        let said = |error: &dyn std::fmt::Display| format!("{}: {error}", path.display());
        let admitted = Arc::new(Admitted::named(admitting.admit)?);
        let shared = *admitted != Admitted::default();
        let group = if shared {
            Some(socket_group(admitting.group)?)
        } else {
            None
        };
        guarded(path.parent().unwrap_or_else(|| Path::new("/")))?;
        if path.exists() {
            if UnixStream::connect(path).is_ok() {
                return Err(said(&"another node listens there"));
            }
            std::fs::remove_file(path).map_err(|e| said(&e))?;
        }
        let inner = UnixListener::bind(path).map_err(|e| said(&e))?;
        if let Some((gid, name)) = group {
            std::os::unix::fs::chown(path, None, Some(gid.as_raw())).map_err(|error| {
                said(&format_args!(
                    "the node's account may not give its socket to the group \"{name}\": \
                     {error}; it must be a member of the group [operate] group names"
                ))
            })?;
        }
        let mode = if shared { 0o660 } else { 0o600 };
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

#[cfg(test)]
#[cfg(feature = "node")]
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

    /// A folder only its owner writes, for a test's sockets.
    fn folder(test: &str) -> PathBuf {
        let folder = std::env::temp_dir().join(format!("xmip-{test}-{}", std::process::id()));
        std::fs::create_dir_all(&folder).expect("a folder");
        std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o755)).expect("shut");
        folder
    }

    #[test]
    fn a_socket_others_are_admitted_to_is_0660_of_its_group_and_0600_otherwise() {
        let folder = folder("socket-group");
        let path = folder.join("node.sock");
        let alone = Acceptor::bind(&path, super::super::Admitting::default()).expect("bound");
        let found = std::fs::metadata(&path).expect("the socket");
        assert_eq!(found.mode() & 0o777, 0o600);
        drop(alone);

        // Admitting someone, the socket is the node's own group's, 0660.
        let me = User::from_uid(nix::unistd::geteuid())
            .ok()
            .flatten()
            .expect("this account's name")
            .name;
        let admit = [me];
        let admitting = super::super::Admitting {
            admit: &admit,
            group: None,
        };
        let shared = Acceptor::bind(&path, admitting).expect("bound");
        let found = std::fs::metadata(&path).expect("the socket");
        assert_eq!(found.mode() & 0o777, 0o660);
        assert_eq!(found.gid(), nix::unistd::getegid().as_raw());
        drop(shared);

        // A group named is the socket's, where the node's account may give
        // it; one the system does not know is refused in words.
        let own = Group::from_gid(nix::unistd::getegid())
            .ok()
            .flatten()
            .expect("this account's group")
            .name;
        let named = super::super::Admitting {
            admit: &admit,
            group: Some(&own),
        };
        drop(Acceptor::bind(&path, named).expect("its own group"));
        let unknown = super::super::Admitting {
            admit: &admit,
            group: Some("xmip-no-such-group"),
        };
        let refused = Acceptor::bind(&path, unknown).err().expect("refused");
        assert!(refused.contains("knows no group"), "{refused}");
        if !nix::unistd::geteuid().is_root() {
            let foreign = super::super::Admitting {
                admit: &admit,
                group: Some("root"),
            };
            let refused = Acceptor::bind(&path, foreign).err().expect("refused");
            assert!(refused.contains("must be a member"), "{refused}");
        }
        let _ = std::fs::remove_dir_all(&folder);
    }
}
