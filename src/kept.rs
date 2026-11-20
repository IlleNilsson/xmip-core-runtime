//! A file a node keeps of its own in its default data directory, found from
//! its configuration's place alone: its pin and its active configuration
//! (`crate::signed`; ADR-0031, amendment 2026-11-12) and the number of its
//! latest start (`crate::membership::numbering`; ADR-0056, amendment
//! 2026-11-20). Each is a private file the node alone writes, whole or not
//! at all, and reads back here.

use std::io::ErrorKind;
use std::path::Path;

/// The file at `at`, the node's `what`; none where it is absent.
///
/// # Errors
/// Where it is there and cannot be read, in words.
pub(crate) fn held(at: &Path, what: &str) -> Result<Option<String>, String> {
    match std::fs::read_to_string(at) {
        Ok(text) => Ok(Some(text)),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!(
            "cannot read the node's {what} at {}: {error}",
            at.display()
        )),
    }
}

/// `bytes` kept at `at` as the node's `what`, a private file written whole
/// or not at all (`secret::private_file::replace`: written beside it,
/// synced, renamed, the directory synced), in a directory made private
/// where it is absent.
///
/// # Errors
/// Where the directory or the file cannot be written, in words; what was at
/// `at` is then as it was.
pub(crate) fn kept(at: &Path, bytes: &[u8], what: &str) -> Result<(), String> {
    let place = at.parent().unwrap_or_else(|| Path::new("."));
    secret::private_file::directory(place)
        .and_then(|()| secret::private_file::replace(at, bytes))
        .map_err(|error| format!("cannot keep the node's {what} at {}: {error}", at.display()))
}
