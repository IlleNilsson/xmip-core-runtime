//! A node's configuration written as its cluster's authority signs it, in
//! a folder with that authority beside it: what every test that starts a
//! node writes, since a node runs only a signed slice (`signed`; ADR-0031,
//! amendment 2026-11-06).

use std::path::{Path, PathBuf};

use crate::signed::{AUTHORITY, sign};

/// The configuration folder in a test's own `directory`, made: `config`,
/// as an install lays it out (ADR-0015 clause 10). A node keeps its
/// accepted slice in its default data directory, `../data` from its
/// configuration (`signed::kept_at`), so a configuration written here keeps
/// it in `directory`'s own `data`, never in one every test shares.
///
/// # Panics
/// The folder cannot be made.
#[must_use]
pub fn configuration_folder(directory: &Path) -> PathBuf {
    let folder = directory.join("config");
    std::fs::create_dir_all(&folder).expect("a configuration folder");
    folder
}

/// The node configuration at `path` as it reads before it was signed:
/// what a test changes and writes again with [`write_signed`].
///
/// # Panics
/// The file cannot be read, or its signature table does not read.
#[must_use]
pub fn unsigned(path: &Path) -> String {
    let file = std::fs::read_to_string(path).expect("reads the node");
    configure::signed::split(&file)
        .expect("reads")
        .0
        .to_string()
}

/// `configuration` written at `path`, signed by the authority beside it,
/// made there where none is kept yet.
///
/// # Panics
/// The folder has no parent, the authority cannot be made, or the file
/// cannot be written; or `path` is in a folder directly under the system's
/// temporary directory, where the node's default data directory, and the
/// accepted slice it keeps there, would be the one every test and every
/// run shares: a test writes its configuration in
/// [`configuration_folder`].
pub fn write_signed(path: &Path, configuration: &str) {
    let shared = std::env::temp_dir().join("any").join("node.xmip");
    assert_ne!(
        configure::service::data_directory(None, path),
        configure::service::data_directory(None, &shared),
        "{} would keep its accepted slice where every test does; write it in \
         fixture::configuration_folder",
        path.display()
    );
    let base = path.parent().expect("a folder");
    let authority = provision::Issuer::kept_or_made(
        &base.join(AUTHORITY),
        "xmip-test-cluster",
        0,
        3_153_600_000,
    )
    .expect("an authority");
    let file = sign(&authority, "", configuration).expect("signed");
    std::fs::write(path, file).expect("writes the node");
}
