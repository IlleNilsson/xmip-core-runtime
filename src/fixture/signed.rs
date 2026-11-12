//! A node's configuration written as its cluster's authority signs it, in
//! a folder with that authority beside it, and a node started by it as its
//! program starts one: what every test that starts a node writes and calls,
//! since a node runs only a signed slice and begins serving only once it is
//! activated (`signed`, `running::activation`; ADR-0031, amendments
//! 2026-11-06 and 2026-11-12).

use std::path::{Path, PathBuf};

use crate::linked::Linked;
use crate::running::{Refusal, Running, activation};
use crate::signed::{AUTHORITY, sign};

/// The configuration folder in a test's own `directory`, made: `config`,
/// as an install lays it out (ADR-0015 clause 10). A node keeps its pin and
/// its active configuration in its default data directory, `../data` from
/// its configuration (`configure::signed::pin_at`, `active_at`), so a
/// configuration written here keeps them in `directory`'s own `data`, never
/// in one every test shares.
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
/// pin and active configuration it keeps there, would be the ones every
/// test and every run shares: a test writes its configuration in
/// [`configuration_folder`].
pub fn write_signed(path: &Path, configuration: &str) {
    let shared = std::env::temp_dir().join("any").join("node.xmip");
    assert_ne!(
        configure::service::data_directory(None, path),
        configure::service::data_directory(None, &shared),
        "{} would keep its pin where every test does; write it in \
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

/// The node configured at `path` started as a program starts it, with what
/// `linked` gives each attempt and no steps of a program's own: its trust,
/// its candidate tried, then its active configuration where the candidate
/// is refused, and activated (`running::activation::started`).
///
/// # Errors
/// Nothing to run, as `activation::started` says.
pub fn started(path: &str, linked: impl FnMut() -> Linked) -> Result<Running, Refusal> {
    activation::started(path, linked, |_| Ok(())).map(|(running, ())| running)
}
