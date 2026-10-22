//! What a node presents and trusts over Xmip's mutual TLS on one of its
//! planes — its certificate chain, its key and the anchors the other end's
//! certificate must reach — read from the files its configuration names,
//! relative to the configuration file: once, for `[operate]` and
//! `[storage]` alike (ADR-0067, amendment 2026-10-13: *the sections shaped
//! the same*).

use std::path::Path;

/// The identity the files `certificate`, `key` and `anchors` name, each
/// relative to the configuration file at `configuration`.
///
/// # Errors
///
/// A file that cannot be read, or three that do not make an identity, in
/// words naming `section` and the file.
pub fn identity(
    configuration: &Path,
    section: &str,
    [certificate, key, anchors]: [&str; 3],
) -> Result<tls::Identity, String> {
    let base = configuration.parent().unwrap_or_else(|| Path::new(""));
    let read = |path: &str| {
        let file = base.join(path);
        std::fs::read(&file).map_err(|error| format!("[{section}] {}: {error}", file.display()))
    };
    tls::Identity::from_pem(&read(certificate)?, &read(key)?, &read(anchors)?)
        .map_err(|failed| format!("[{section}] {}", failed.message))
}
