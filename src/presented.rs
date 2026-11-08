//! What a node presents and trusts over Xmip's mutual TLS on one of its
//! planes — its certificate chain, its key and the anchors the other end's
//! certificate must reach — read from the files its configuration names,
//! relative to the configuration file: once, for `[operate]` and
//! `[storage]` alike (ADR-0067, amendment 2026-10-13: *the sections shaped
//! the same*).
//!
//! A listener of that identity refuses a client its cluster's authority
//! revoked: the authority's revocation list, `authority.crl`, is read from
//! the folder the authority's certificate is kept in beside the
//! configuration ([`crate::signed::AUTHORITY`], the register's
//! `provision::register::LIST`), and read again as the register remakes it
//! (`tls::Revocation`). A list past its nextUpdate refuses every client; the
//! register remakes it before then (`provision::register::Register::list`).
//! Where no list is kept beside the configuration, nothing is revoked.

use std::path::{Path, PathBuf};
use std::sync::Arc;

/// The identity the files `certificate`, `key` and `anchors` name, each
/// relative to the configuration file at `configuration`, refusing as a
/// server a client the cluster's authority revoked ([`revocation`]).
///
/// # Errors
///
/// A file that cannot be read, three that do not make an identity, or a
/// revocation list kept that does not read, in words naming `section` and
/// the file.
pub fn identity(
    configuration: &Path,
    section: &str,
    [certificate, key, anchors]: [&str; 3],
) -> Result<tls::Identity, String> {
    let read = |path: &str| file(configuration, section, path);
    let identity = tls::Identity::from_pem(&read(certificate)?, &read(key)?, &read(anchors)?)
        .map_err(|failed| format!("[{section}] {}", failed.message))?;
    Ok(match revocation(configuration, section)? {
        Some(lists) => identity.revoking(lists),
        None => identity,
    })
}

/// Where the cluster's authority keeps its revocation list for the node
/// whose configuration is at `configuration`: beside the authority's
/// certificate, in [`crate::signed::AUTHORITY`].
#[must_use]
pub fn list_at(configuration: &Path) -> PathBuf {
    let base = configuration.parent().unwrap_or_else(|| Path::new("."));
    base.join(crate::signed::AUTHORITY)
        .join(provision::register::LIST)
}

/// The cluster authority's revocation list kept beside the configuration at
/// `configuration` ([`list_at`]), read again whenever it changes; `None`
/// where none is kept.
///
/// # Errors
///
/// A list kept that cannot be read or holds no list, in words naming
/// `section`.
pub fn revocation(
    configuration: &Path,
    section: &str,
) -> Result<Option<Arc<tls::Revocation>>, String> {
    let at = list_at(configuration);
    if !at.exists() {
        return Ok(None);
    }
    tls::Revocation::from_file(&at)
        .map(|lists| Some(Arc::new(lists)))
        .map_err(|failed| format!("[{section}] {}", failed.message))
}

/// The file `path` names, relative to the configuration file at
/// `configuration`.
///
/// # Errors
///
/// A file that cannot be read, in words naming `section` and the file.
pub fn file(configuration: &Path, section: &str, path: &str) -> Result<Vec<u8>, String> {
    let base = configuration.parent().unwrap_or_else(|| Path::new(""));
    let file = base.join(path);
    std::fs::read(&file).map_err(|error| format!("[{section}] {}: {error}", file.display()))
}
