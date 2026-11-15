//! A node's local operate endpoint (ADR-0014, amendment 2026-10-13): the
//! operate listener on this machine, a named pipe on Windows and a Unix
//! domain socket elsewhere, which every surface on the machine reaches the
//! node through — gRPC over HTTP/2 as on the network, without TLS, because
//! the operating system proves who connected and admits only whom the
//! endpoint's permissions name (ADR-0063 clause 1: the one exception
//! inside one machine, said where it is made).
//!
//! **Local callers are proven by the operating system** — decided by the
//! owner, 2026-10-19, open problem 35 — and this is the one way a surface
//! on the node's machine reaches it: xmip, the PowerShell module and
//! the GUIs alike, through `xmip_remote_open_local_v1`. A tcp connection
//! over loopback is trusted for nothing; it presents a certificate like a
//! caller from another machine.
//!
//! **Who may open it** is the account the node runs as, the system and the
//! machine's administrators, and each account or group `[operate] admit`
//! names: on Windows the pipe's own security descriptor (the owner,
//! `SYSTEM` and `BUILTIN\Administrators` fully, the admitted to read and
//! write it, and no caller from another machine); on Unix the kernel's
//! word on the peer (`SO_PEERCRED`, `getpeereid`) judged against the same
//! list, the socket file `0600` where nobody else is admitted and `0660`,
//! of the group `[operate] group` names, where some are, in a folder
//! nobody else may write. **Who acts** is the account the connecting
//! process runs as, read from the connection, never a name the caller
//! says: `DOMAIN\user` on Windows, lent for identification alone so the
//! node can never act as it, the user name elsewhere (ADR-0009, amendment
//! 2026-10-21).
//!
//! **Where it is** — decided by the owner, 2026-10-13: *Linux
//! `/run/xmip/xmip-<node>.sock`, macOS `/var/run/xmip/xmip-<node>.sock`,
//! created by systemd / launchd for the node's account; a name may change,
//! the folder may not* — and amended by him on 2026-11-15 (ADR-0014): a
//! folder per node, so two nodes under two accounts on one machine never
//! take each other's socket, and [`DIRECTORY_VARIABLE`] may name another
//! folder for a run no service manager started; a deployment keeps the
//! system's, and nothing falls back on its own. The socket is
//! `<folder>/<name>/<name>.sock`: the endpoints' folder ([`folder`]), the
//! node's folder in it, named as the endpoint is and read for nothing
//! ([`own_folder`]), and the endpoint's name as it was, so `xmip-node1` is
//! `/run/xmip/xmip-node1/xmip-node1.sock`. On Windows the folder is the pipe
//! namespace, `\\.\pipe\`, with no node's folder. [`place`] is the one rule
//! the node binds by, every surface connects by and the service manager's
//! registration names the folder by, and it refuses a name that would leave
//! its folder, or a socket's path longer than the system holds.

use std::path::PathBuf;
use std::sync::OnceLock;

cfg_select! {
    unix => {
        #[path = "local/unix.rs"]
        mod system;
        #[cfg(feature = "node")]
        #[path = "local/folders.rs"]
        mod folders;
    }
    windows => {
        #[path = "local/windows.rs"]
        mod system;
    }
}

#[cfg(feature = "node")]
pub use system::running_as;
#[cfg(feature = "node")]
pub(crate) use system::{Acceptor, wake};
pub(crate) use system::{Cancel, Stream, connect};

/// Whom a local endpoint admits beside the node's account and the
/// machine's administrators: the accounts and groups `[operate] admit`
/// names, and on Unix the group its socket belongs to where `admit` names
/// anyone (`[operate] group`; the node's own group where it is left out).
/// Windows admits by the pipe's security descriptor and has no socket
/// group, so `group` is read on Unix alone.
#[derive(Clone, Copy, Debug, Default)]
pub struct Admitting<'a> {
    /// What `[operate] admit` names.
    pub admit: &'a [String],
    /// What `[operate] group` names.
    pub group: Option<&'a str>,
}

/// The pipe namespace, Windows' folder of local endpoints.
pub const WINDOWS_FOLDER: &str = r"\\.\pipe\";
/// Linux's folder of local endpoints, root's, in which the systemd unit
/// makes each node's folder for its account (`registration::systemd_unit`,
/// `RuntimeDirectory`).
pub const LINUX_FOLDER: &str = "/run/xmip/";
/// macOS' folder of local endpoints, root's, in which a launchd daemon
/// makes each node's folder for its account at every boot
/// (`registration::launchd_run_directory`).
pub const MACOS_FOLDER: &str = "/var/run/xmip/";

/// The system's folder of local endpoints: the one a deployment keeps.
pub const FOLDER: &str = if cfg!(windows) {
    WINDOWS_FOLDER
} else if cfg!(target_os = "linux") {
    LINUX_FOLDER
} else {
    MACOS_FOLDER
};

/// What names the folder of local endpoints for a run no service manager
/// started — a shell, the tests, the WSL guest — in place of [`FOLDER`]
/// (decided by the owner, 2026-11-15); read on Unix alone, once a process,
/// by the node binding and every surface connecting alike. Whatever starts
/// a node outside the service manager sets it; the estate's tooling names
/// `$XDG_RUNTIME_DIR/xmip` on Linux and `$TMPDIR/xmip` on macOS.
pub const DIRECTORY_VARIABLE: &str = "XMIP_RUNTIME_DIRECTORY";

/// The bytes a Unix domain socket's path has room for on Linux, its ending
/// zero among them (`sun_path`, unix(7)).
pub const LINUX_SOCKET_PATH: usize = 108;
/// The same on macOS (`sun_path`, `<sys/un.h>`).
pub const MACOS_SOCKET_PATH: usize = 104;

/// What a socket's path has room for on this system; nothing in the pipe
/// namespace, which has no folder of a node's own.
const SOCKET_PATH: Option<usize> = if cfg!(windows) {
    None
} else if cfg!(target_os = "linux") {
    Some(LINUX_SOCKET_PATH)
} else {
    Some(MACOS_SOCKET_PATH)
};

/// What a socket's file name ends in.
const SOCKET_SUFFIX: &str = ".sock";

/// What an endpoint's name ends in on this system; a pipe's in nothing.
const SUFFIX: &str = if cfg!(windows) { "" } else { SOCKET_SUFFIX };

/// The folder this process's local endpoints are in: on Unix the one
/// [`DIRECTORY_VARIABLE`] names, ending in `/`, else the system's
/// [`FOLDER`]; on Windows the pipe namespace. Read once a process.
///
/// # Errors
///
/// A variable that names no absolute path, in words naming it.
pub fn folder() -> Result<&'static str, String> {
    static NAMED_FOLDER: OnceLock<Result<String, String>> = OnceLock::new();
    if cfg!(windows) {
        return Ok(FOLDER);
    }
    NAMED_FOLDER
        .get_or_init(|| named(std::env::var_os(DIRECTORY_VARIABLE).as_deref()))
        .as_deref()
        .map_err(Clone::clone)
}

/// The folder `variable`, what [`DIRECTORY_VARIABLE`] holds, names: the
/// system's where it holds nothing.
fn named(variable: Option<&std::ffi::OsStr>) -> Result<String, String> {
    let Some(variable) = variable else {
        return Ok(FOLDER.to_string());
    };
    let said = variable.to_string_lossy();
    if said.trim().is_empty() || !said.starts_with('/') || variable.to_str().is_none() {
        return Err(format!(
            "{DIRECTORY_VARIABLE} = \"{said}\" names no folder: it names the folder of the \
             local endpoints for a node no service manager starts, an absolute path such as \
             $XDG_RUNTIME_DIR/xmip, or is left unset for {FOLDER}"
        ));
    }
    Ok(format!("{}/", said.trim_end_matches('/')))
}

/// How a system lays its local endpoints out.
#[derive(Clone, Copy)]
struct Layout<'a> {
    /// The folder every endpoint is in, ending in its separator.
    folder: &'a str,
    /// On Unix, the bytes a socket's path has room for, each endpoint in a
    /// folder of its own; nothing in the pipe namespace.
    socket: Option<usize>,
    /// What an endpoint's name ends in.
    suffix: &'a str,
}

/// Where the endpoint called `name` is on this system: on Unix
/// `<folder><name>/<name>.sock`, in its node's folder in [`folder`]; on
/// Windows `name` in the pipe namespace; or `name` itself where it is
/// already that place.
///
/// # Errors
///
/// An empty name, one that would leave its folder, a socket's path longer
/// than the system has room for, or a [`DIRECTORY_VARIABLE`] that names no
/// folder, in words.
pub fn place(name: &str) -> Result<PathBuf, String> {
    let layout = Layout {
        folder: folder()?,
        socket: SOCKET_PATH,
        suffix: SUFFIX,
    };
    place_in(layout, name)
}

/// The node's folder, in `folder`, a Unix system's folder of local
/// endpoints whose sockets' paths have room for `room` bytes, that the
/// endpoint called `name` is placed in by [`place`]'s one rule: named as
/// the endpoint is. What a service manager makes for the node's account
/// (`registration::systemd_unit`, `registration::launchd_run_directory`).
///
/// # Errors
///
/// As [`place`].
pub fn own_folder(folder: &str, room: usize, name: &str) -> Result<String, String> {
    let layout = Layout {
        folder,
        socket: Some(room),
        suffix: SOCKET_SUFFIX,
    };
    let placed = place_in(layout, name)?;
    let placed = placed.to_string_lossy();
    Ok(placed
        .rsplit_once('/')
        .map_or_else(String::new, |(own, _)| own.to_string()))
}

/// [`place`] by `layout`: the rule, apart from the system it is on.
fn place_in(layout: Layout<'_>, name: &str) -> Result<PathBuf, String> {
    let Layout {
        folder,
        socket,
        suffix,
    } = layout;
    let refused = || {
        format!(
            "the local endpoint \"{name}\" is no name in {folder}; it is a name like \
             xmip-node1"
        )
    };
    let bare = match name.strip_prefix(folder) {
        None => name,
        // The place itself: in its node's folder, where the system has one.
        Some(inside) => {
            let inside = inside.strip_suffix(suffix).unwrap_or(inside);
            match (socket, inside.split_once('/')) {
                (Some(_), Some((own, bare))) if own == bare => bare,
                (Some(_), _) => return Err(refused()),
                (None, _) => inside,
            }
        }
    };
    let leaves = bare.trim().is_empty()
        || bare == "."
        || bare == ".."
        || bare.chars().any(|c| matches!(c, '/' | '\\' | ':' | '\0'));
    if leaves {
        return Err(refused());
    }
    let Some(room) = socket else {
        return Ok(PathBuf::from(format!("{folder}{bare}{suffix}")));
    };
    let placed = format!("{folder}{bare}/{bare}{suffix}");
    if placed.len() >= room {
        return Err(format!(
            "the local endpoint \"{name}\" would be at {placed}, {} bytes, and a Unix domain \
             socket's path holds at most {} bytes there ({room} with its ending zero); \
             name a shorter endpoint, or a shorter folder in {DIRECTORY_VARIABLE}",
            placed.len(),
            room - 1
        ));
    }
    Ok(PathBuf::from(placed))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Linux system's endpoints in `folder`, each in its node's folder.
    const fn unix(folder: &str) -> Layout<'_> {
        Layout {
            folder,
            socket: Some(LINUX_SOCKET_PATH),
            suffix: SOCKET_SUFFIX,
        }
    }

    const PIPES: Layout<'static> = Layout {
        folder: WINDOWS_FOLDER,
        socket: None,
        suffix: "",
    };

    /// Decided while building, 2026-11-15: the node's folder is named as its
    /// endpoint is, whole, and the name is read for nothing.
    #[test]
    fn a_name_is_placed_in_a_folder_of_its_own_name_and_its_place_is_taken_as_it() {
        let placed = place_in(unix("/run/xmip/"), "xmip-n1").expect("a name");
        assert_eq!(placed, PathBuf::from("/run/xmip/xmip-n1/xmip-n1.sock"));
        assert_eq!(
            place_in(unix("/run/xmip/"), "/run/xmip/xmip-n1/xmip-n1.sock"),
            Ok(placed)
        );
        assert_eq!(
            place_in(PIPES, r"\\.\pipe\xmip-n1"),
            Ok(PathBuf::from(r"\\.\pipe\xmip-n1"))
        );
        assert_eq!(
            place_in(unix("/var/run/xmip/"), "xmip-n1"),
            Ok(PathBuf::from("/var/run/xmip/xmip-n1/xmip-n1.sock"))
        );
        assert_eq!(
            place_in(unix("/run/xmip/"), "orders"),
            Ok(PathBuf::from("/run/xmip/orders/orders.sock"))
        );
        assert_eq!(
            own_folder(LINUX_FOLDER, LINUX_SOCKET_PATH, "orders"),
            Ok("/run/xmip/orders".to_string())
        );
    }

    /// A socket's path the system has no room for is refused before
    /// anything binds or connects, in words naming the place and the room.
    #[test]
    fn a_socket_path_longer_than_the_system_holds_is_refused_in_words() {
        // 20 + 43 + 1 + 43 + 5 = 112 bytes, past Linux's 107.
        let long = format!("xmip-{}", "n".repeat(38));
        let refused = place_in(unix("/run/user/1000/xmip/"), &long).expect_err("too long");
        let path = format!("/run/user/1000/xmip/{long}/{long}.sock");
        assert!(refused.contains(&path), "{refused}");
        assert!(refused.contains("112 bytes"), "{refused}");
        assert!(refused.contains("at most 107 bytes"), "{refused}");
        assert!(refused.contains("108 with its ending zero"), "{refused}");
        // 20 + 41 + 1 + 41 + 5 = 108: one byte too many still.
        let edge = format!("xmip-{}", "n".repeat(36));
        assert!(place_in(unix("/run/user/1000/xmip/"), &edge).is_err());
        let fits = format!("xmip-{}", "n".repeat(35));
        assert!(place_in(unix("/run/user/1000/xmip/"), &fits).is_ok());
        // macOS has four bytes less.
        let mac = Layout {
            socket: Some(MACOS_SOCKET_PATH),
            ..unix("/var/run/xmip/")
        };
        let refused = place_in(mac, &format!("xmip-{}", "n".repeat(40))).expect_err("too long");
        assert!(refused.contains("at most 103 bytes"), "{refused}");
        assert!(own_folder(LINUX_FOLDER, LINUX_SOCKET_PATH, &"n".repeat(60)).is_err());
    }

    /// Decided by the owner, 2026-11-15: a folder per node, so two nodes
    /// under two accounts never take each other's socket.
    #[test]
    fn two_nodes_are_placed_in_two_folders() {
        let one = place_in(unix("/run/xmip/"), "xmip-n1").expect("a name");
        let two = place_in(unix("/run/xmip/"), "xmip-n2").expect("a name");
        assert_ne!(one.parent(), two.parent());
        assert_eq!(
            one.parent().and_then(|own| own.parent()),
            two.parent().and_then(|own| own.parent())
        );
    }

    #[test]
    fn a_name_that_would_leave_its_folder_is_refused() {
        for name in [
            "",
            "..",
            ".",
            "../etc/x",
            "/tmp/xmip",
            r"a\b",
            "c:x",
            "/run/xmip/a/b",
            "/run/xmip/xmip-n1.sock",
            "/run/xmip/n1/xmip-n1.sock",
            "/run/xmip/xmip-n2/xmip-n1.sock",
            "/run/xmip/xmip-n1/xmip-n1/x.sock",
        ] {
            let refused = place_in(unix("/run/xmip/"), name).expect_err(name);
            assert!(refused.contains("is no name in /run/xmip/"), "{refused}");
        }
        assert!(place_in(PIPES, r"\\.\pipe\a\b").is_err());
        assert!(place(" ").is_err());
        assert!(place("xmip-n1").is_ok());
    }

    /// Decided by the owner, 2026-11-15: the variable may name another
    /// folder for a run no service manager started; nothing falls back on
    /// its own.
    #[test]
    fn the_variable_names_the_folder_and_one_that_names_none_is_refused() {
        assert_eq!(named(None), Ok(FOLDER.to_string()));
        let given = std::ffi::OsStr::new("/run/user/1000/xmip");
        assert_eq!(named(Some(given)), Ok("/run/user/1000/xmip/".to_string()));
        let ended = std::ffi::OsStr::new("/tmp/xmip//");
        assert_eq!(named(Some(ended)), Ok("/tmp/xmip/".to_string()));
        for wrong in ["", " ", "xmip", "run/xmip"] {
            let refused = named(Some(std::ffi::OsStr::new(wrong))).expect_err(wrong);
            assert!(refused.starts_with(DIRECTORY_VARIABLE), "{refused}");
            assert!(refused.contains("an absolute path"), "{refused}");
        }
        let from = place_in(unix("/run/user/1000/xmip/"), "xmip-n1").expect("a name");
        assert_eq!(
            from,
            PathBuf::from("/run/user/1000/xmip/xmip-n1/xmip-n1.sock")
        );
        let elsewhere = "/run/xmip/xmip-n1/xmip-n1.sock";
        assert!(place_in(unix("/run/user/1000/xmip/"), elsewhere).is_err());
    }
}
