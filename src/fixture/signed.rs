//! A node's configuration written as its cluster's authority signs it, in
//! a folder with that authority beside it: what every test that starts a
//! node writes, since a node runs only a signed slice (`signed`; ADR-0031,
//! amendment 2026-11-06).

use std::path::Path;

use crate::signed::{AUTHORITY, sign};

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
/// cannot be written.
pub fn write_signed(path: &Path, configuration: &str) {
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
