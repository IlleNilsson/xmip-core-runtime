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
//! **Where it is** — decided by the owner, 2026-10-13: *Linux
//! `/run/xmip/xmip-<node>.sock`, macOS `/var/run/xmip/xmip-<node>.sock`,
//! created by systemd / launchd for the node's account; a name may change,
//! the folder may not.* On Windows the folder is the pipe namespace,
//! `\\.\pipe\`. [`place`] is the one rule the node binds by and every
//! surface connects by, and it refuses a name that would leave the folder.

use std::path::PathBuf;

#[cfg(unix)]
#[path = "local/unix.rs"]
mod system;
#[cfg(windows)]
#[path = "local/windows.rs"]
mod system;

pub(crate) use system::{Acceptor, Cancel, Stream, connect, wake};

/// The pipe namespace, Windows' folder of local endpoints.
pub const WINDOWS_FOLDER: &str = r"\\.\pipe\";
/// Linux's folder of local endpoints, which the systemd unit makes for the
/// node's account (`registration::systemd_unit`, `RuntimeDirectory`).
pub const LINUX_FOLDER: &str = "/run/xmip/";
/// macOS' folder of local endpoints, which a launchd daemon makes for the
/// node's account at every boot (`registration::launchd_run_directory`).
pub const MACOS_FOLDER: &str = "/var/run/xmip/";

/// The folder every local endpoint on this system is in.
pub const FOLDER: &str = if cfg!(windows) {
    WINDOWS_FOLDER
} else if cfg!(target_os = "linux") {
    LINUX_FOLDER
} else {
    MACOS_FOLDER
};

/// What a socket's file name ends in; a pipe's name ends in nothing.
const SUFFIX: &str = if cfg!(windows) { "" } else { ".sock" };

/// Where the endpoint called `name` is on this system: `name` in
/// [`FOLDER`], or `name` itself where it is already that place.
///
/// # Errors
///
/// An empty name, or one that would leave the folder, in words.
pub fn place(name: &str) -> Result<PathBuf, String> {
    place_in(FOLDER, SUFFIX, name)
}

/// [`place`] in `folder`, a file name ending in `suffix`: the rule, apart
/// from the system it is on.
fn place_in(folder: &str, suffix: &str, name: &str) -> Result<PathBuf, String> {
    let bare = name
        .strip_prefix(folder)
        .map_or(name, |inside| inside.strip_suffix(suffix).unwrap_or(inside));
    let leaves = bare.trim().is_empty()
        || bare == "."
        || bare == ".."
        || bare.chars().any(|c| matches!(c, '/' | '\\' | ':' | '\0'));
    if leaves {
        return Err(format!(
            "the local endpoint \"{name}\" is no name in {folder}; it is a name like xmip-node1"
        ));
    }
    Ok(PathBuf::from(format!("{folder}{bare}{suffix}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_is_placed_in_the_folder_and_its_place_is_taken_as_it() {
        let placed = place_in("/run/xmip/", ".sock", "xmip-n1").expect("a name");
        assert_eq!(placed, PathBuf::from("/run/xmip/xmip-n1.sock"));
        assert_eq!(
            place_in("/run/xmip/", ".sock", "/run/xmip/xmip-n1.sock"),
            Ok(placed)
        );
        assert_eq!(
            place_in(r"\\.\pipe\", "", r"\\.\pipe\xmip-n1"),
            Ok(PathBuf::from(r"\\.\pipe\xmip-n1"))
        );
        assert_eq!(
            place_in("/var/run/xmip/", ".sock", "xmip-n1"),
            Ok(PathBuf::from("/var/run/xmip/xmip-n1.sock"))
        );
    }

    #[test]
    fn a_name_that_would_leave_the_folder_is_refused() {
        for name in [
            "",
            "..",
            "../etc/x",
            "/tmp/xmip",
            r"a\b",
            "c:x",
            "/run/xmip/a/b",
        ] {
            assert!(place_in("/run/xmip/", ".sock", name).is_err(), "{name}");
        }
        assert!(place(" ").is_err());
        assert!(place("xmip-n1").is_ok());
    }
}
