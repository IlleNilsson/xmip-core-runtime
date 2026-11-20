//! The folders a node's local endpoint is in on Unix (ADR-0014, amendment
//! 2026-11-15): the node's folder, its account's, and above it the folder
//! of local endpoints, the superuser's or the node's account's.
//!
//! **Who makes them.** The system's folder and each node's folder in it are
//! the service manager's: the systemd unit's `RuntimeDirectory=xmip/<name>`,
//! the node's folder named as its endpoint is, which makes `/run/xmip`
//! root's and `/run/xmip/<name>` the unit's account's, and on macOS a
//! launchd daemon that does the same under `/var/run/xmip` at every boot
//! (`registration`). A node never makes them.
//! Under `XMIP_RUNTIME_DIRECTORY`, for a run no service manager started, the
//! node makes the folder the variable names and its own folder in it where
//! they are absent, each its account's and `0755`, and keeps them when it
//! stops, as the service manager keeps its own (`RuntimeDirectoryPreserve`).
//!
//! **What makes them fit** ([`guarded`]), both levels, as the node binds: the
//! node's folder is the node's account's, the folder above it the node's
//! account's or the superuser's, and neither may be written by anyone else,
//! or a stranger could put a socket of their own where a surface looks.

use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::Path;

/// Whose a folder must be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Owner {
    /// The node's account alone: its own folder.
    Node,
    /// The node's account or the superuser: the folder of local endpoints.
    NodeOrSuperuser,
}

/// The node's folder the socket at `socket` is placed in, and the folder of
/// local endpoints above it, ready to hold it: each made where
/// [`super::DIRECTORY_VARIABLE`] names their place and it is absent, then
/// both guarded.
///
/// # Errors
///
/// A folder that cannot be made, or one unfit ([`guarded`]), in words.
pub(super) fn readied(socket: &Path) -> Result<(), String> {
    let own = socket.parent().unwrap_or_else(|| Path::new("/"));
    let endpoints = own.parent().unwrap_or_else(|| Path::new("/"));
    if named(endpoints) {
        made(endpoints)?;
        made(own)?;
    }
    guarded(endpoints, Owner::NodeOrSuperuser)?;
    guarded(own, Owner::Node)
}

/// Whether `endpoints` is the folder the variable names in this process:
/// another than the system's, which the node never makes.
fn named(endpoints: &Path) -> bool {
    super::folder().is_ok_and(|folder| folder != super::FOLDER && Path::new(folder) == endpoints)
}

/// `folder` made, the node's account's and `0755`, where it is absent.
///
/// # Errors
///
/// What the system said, naming the folder and the variable.
pub(super) fn made(folder: &Path) -> Result<(), String> {
    let said = |error: &std::io::Error| {
        format!(
            "{}: {error}; {} names where this node makes it",
            folder.display(),
            super::DIRECTORY_VARIABLE
        )
    };
    match std::fs::DirBuilder::new().mode(0o755).create(folder) {
        // The mode exactly, whatever the process's umask took off it.
        Ok(()) => std::fs::set_permissions(folder, std::fs::Permissions::from_mode(0o755))
            .map_err(|error| said(&error)),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(said(&error)),
    }
}

/// Whether `folder` is fit to hold a node's endpoint: there, a folder,
/// `owner`'s, and writable by nobody else.
///
/// # Errors
///
/// What makes it unfit, in words.
pub(super) fn guarded(folder: &Path, owner: Owner) -> Result<(), String> {
    let shown = folder.display();
    let found = std::fs::metadata(folder).map_err(|error| {
        format!(
            "{shown}: {error}; the service manager makes it for the node's account, and {} \
             names another for a node no service manager starts",
            super::DIRECTORY_VARIABLE
        )
    })?;
    if !found.is_dir() {
        return Err(format!("{shown} is no folder"));
    }
    let node = nix::unistd::geteuid().as_raw();
    let whose = found.uid();
    match owner {
        Owner::Node if whose != node => {
            return Err(format!(
                "{shown} belongs to uid {whose}, not the node's account, whose folder it is"
            ));
        }
        Owner::NodeOrSuperuser if whose != node && whose != 0 => {
            return Err(format!(
                "{shown} belongs to uid {whose}, not the node's account or the superuser"
            ));
        }
        _ => {}
    }
    if found.mode() & 0o022 != 0 {
        return Err(format!(
            "{shown} may be written by others (mode {:o}); a local endpoint is made only in \
             folders only their owners write",
            found.mode() & 0o7777
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use file::temporary::Folder;

    /// A folder of its own for `test`, mode `mode`.
    fn folder(test: &str, mode: u32) -> Folder {
        let folder = Folder::new(&format!("runtime-local-{test}"));
        std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(mode)).expect("mode");
        folder
    }

    #[test]
    fn a_folder_others_may_write_is_unfit_at_either_level() {
        let open = folder("unfit", 0o777);
        for owner in [Owner::Node, Owner::NodeOrSuperuser] {
            let unfit = guarded(&open, owner).expect_err("open");
            assert!(unfit.contains("may be written by others"), "{unfit}");
        }
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755)).expect("shut");
        assert_eq!(guarded(&open, Owner::Node), Ok(()));
        assert_eq!(guarded(&open, Owner::NodeOrSuperuser), Ok(()));
    }

    /// Both levels held as the node binds: a node's folder fit in a folder
    /// of local endpoints others may write is refused, and so is a fit
    /// folder of local endpoints holding one others may write.
    #[test]
    fn both_levels_are_guarded_as_an_endpoint_is_readied() {
        let endpoints = folder("levels", 0o755);
        let own = endpoints.join("xmip-n1");
        made(&own).expect("made");
        let socket = own.join("xmip-n1.sock");
        assert_eq!(readied(&socket), Ok(()));

        std::fs::set_permissions(&endpoints, std::fs::Permissions::from_mode(0o777)).expect("open");
        let above = readied(&socket).expect_err("the folder above is open");
        assert!(
            above.starts_with(&endpoints.display().to_string()),
            "{above}"
        );
        std::fs::set_permissions(&endpoints, std::fs::Permissions::from_mode(0o755)).expect("shut");

        std::fs::set_permissions(&own, std::fs::Permissions::from_mode(0o775)).expect("open");
        let below = readied(&socket).expect_err("the node's folder is open");
        assert!(below.starts_with(&own.display().to_string()), "{below}");

        let missing = readied(&endpoints.join("xmip-n2").join("xmip-n2.sock")).expect_err("absent");
        assert!(
            missing.contains(super::super::DIRECTORY_VARIABLE),
            "{missing}"
        );
    }

    /// Decided while building, 2026-11-15: a node started under the variable
    /// makes its folder where it is absent, its own and `0755`.
    #[test]
    fn a_folder_the_node_made_is_its_own_and_0755() {
        let endpoints = folder("made", 0o755);
        let own = endpoints.join("xmip-n1");
        made(&own).expect("made");
        made(&own).expect("there already");
        let found = std::fs::metadata(&own).expect("there");
        assert_eq!(found.uid(), nix::unistd::geteuid().as_raw());
        assert_eq!(found.mode() & 0o7777, 0o755);
        let deep = made(&endpoints.join("a").join("b")).expect_err("no folder above");
        assert!(deep.contains(super::super::DIRECTORY_VARIABLE), "{deep}");
    }
}
