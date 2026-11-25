//! A node's slice signed by its cluster's authority, and a node trusting
//! only a slice that verifies (ADR-0031, amendments 2026-11-06, 2026-11-07
//! and 2026-11-12).
//!
//! The authority's certificate travels beside the node's configuration, in
//! [`AUTHORITY`], and is never read from the file it checks. What the node
//! trusts a slice by, and what it last ran, are held where whoever writes
//! the configuration folder does not write: its pin and its active
//! configuration, private files the node itself writes in the default data
//! directory beside the configuration folder ([`admission`]). Signing is
//! here; trusting is [`admission`]'s.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use configure::signed::{self, Signature};
use provision::Issuer;

mod admission;

pub use admission::{Admitted, Refused, Slice, Which, activated, admitted, checked};

/// The folder beside a node's configuration that holds its cluster
/// authority's certificate, and its key on the node that keeps it.
pub const AUTHORITY: &str = "authority";

/// `sha256:` and the hexadecimal SHA-256 of `bytes`.
fn digest(bytes: &[u8]) -> String {
    format!(
        "sha256:{}",
        codec::hex::encode(&codec::digest::sha256(bytes))
    )
}

/// The certificate PEM `pem` holds, as DER.
fn der(pem: &str) -> Result<Vec<u8>, String> {
    codec::pem::decode("CERTIFICATE", pem)
        .map_err(|error| error.to_string())?
        .into_iter()
        .next()
        .ok_or_else(|| "the authority's certificate holds no CERTIFICATE".to_string())
}

/// A fresh serial and the Unix second it was taken in: the clock's
/// nanoseconds, one above the last this process gave where the clock has
/// not moved (`xcore::clock::serial`), so two slices signed in a row never
/// share one.
fn serial() -> (u64, i64) {
    static LAST: AtomicU64 = AtomicU64::new(0);
    let now = i128::from(observe::now_unix_nanos());
    let last = LAST
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |last| {
            Some(xcore::clock::serial(last, now))
        })
        .unwrap_or_else(|last| last);
    let serial = xcore::clock::serial(last, now);
    (
        serial,
        i64::try_from(serial / 1_000_000_000).unwrap_or(i64::MAX),
    )
}

/// `slice`, sliced from the cluster's file `cluster`, signed by `authority`
/// for the node it names, under a fresh serial.
///
/// # Errors
/// The slice's signature table does not read, it names no node, or
/// signing fails.
pub fn sign(authority: &Issuer, cluster: &str, slice: &str) -> Result<String, String> {
    signed_as(authority, cluster, slice, serial())
}

/// [`sign`], under the serial and the time `(serial, issued)` give.
fn signed_as(
    authority: &Issuer,
    cluster: &str,
    slice: &str,
    (serial, issued): (u64, i64),
) -> Result<String, String> {
    let (text, _) = signed::split(slice)?;
    let node = signed::named(text)
        .ok_or("the slice names no node under [service], and a slice is signed for its node")?;
    let mut signature = Signature {
        cluster: digest(cluster.as_bytes()),
        node,
        serial,
        issued,
        by: digest(&der(authority.certificate())?),
        value: String::new(),
    };
    let value = authority
        .key()
        .sign(&signed::message(text, &signature))
        .map_err(|error| error.to_string())?;
    signature.value = codec::base64::encode(&value);
    Ok(signed::joined(text, &signature))
}

/// `slice`, sliced from the cluster's file `cluster`, signed by the
/// cluster's authority kept beside the configuration at `configuration`
/// ([`AUTHORITY`]), made there named `name` where none is kept yet: a
/// one-node install's, whose configuration is the machine's own, never a
/// cluster's file sliced for its nodes ([`sliced_signed`]).
///
/// # Errors
/// The authority cannot be read or made, or signing fails; in words.
pub fn signed_beside(
    configuration: &Path,
    name: &str,
    cluster: &str,
    slice: &str,
) -> Result<String, String> {
    let base = configuration.parent().unwrap_or_else(|| Path::new("."));
    signed_by_kept(&base.join(AUTHORITY), name, cluster, slice)
}

/// `slice`, sliced from the cluster's file `cluster`, signed by the
/// cluster's authority kept in `place`, made there named `name` where none
/// is kept yet: the machine deploying an environment signs every node's
/// slice with its own (ADR-0031, amendment 2026-11-06).
///
/// # Errors
/// The authority cannot be read or made, or signing fails; in words.
pub fn signed_by_kept(
    place: &Path,
    name: &str,
    cluster: &str,
    slice: &str,
) -> Result<String, String> {
    let authority = provision::host::authority(place, name, provision::now())
        .map_err(|error| error.to_string())?;
    sign(&authority, cluster, slice)
}

/// The node `node`'s document sliced from the cluster's file `cluster` and
/// signed, and the folder the authority that signed it is kept in: the one
/// slicing and signing every program and surface asks for a node
/// (`xmip-service --slice`, `xmip_cluster_signed_slice_v1`). Sliced as the
/// cluster `name` the environment gives where it gives one
/// (`configure::slice_named`), and as the file names it otherwise; signed by
/// the cluster's authority kept in `authority` where it is named, and in
/// this account's own folder on this machine otherwise ([`own_authority`]),
/// made there named for the cluster where none is kept ([`signed_by_kept`]).
/// Never beside the cluster's file, which may be in a repository: a slice
/// made a private key in one on 2026-11-24 (ADR-0031, amendment
/// 2026-11-25).
///
/// # Errors
/// The slicing refuses, the cluster has no name and no folder is named, or
/// the authority cannot be read or made, or signing fails; in words.
pub fn sliced_signed(
    cluster: &str,
    node: &str,
    name: Option<&str>,
    authority: Option<&Path>,
) -> Result<(String, PathBuf), String> {
    let (sliced, name) = match name {
        Some(name) => (
            configure::slice_named(cluster, node, name)?,
            name.to_string(),
        ),
        None => (
            configure::slice(cluster, node)?,
            configure::cluster::cluster_name(cluster)?.unwrap_or_default(),
        ),
    };
    let place = match authority {
        Some(place) => place.to_path_buf(),
        None => own_authority(&name)?,
    };
    let signed = signed_by_kept(&place, &name, cluster, &sliced)?;
    Ok((signed, place))
}

/// Where the cluster `name`'s authority is kept on this machine where no
/// folder is named for it: `authority/<name>` in this account's own Xmip
/// folder ([`own_folder`]), a private directory the authority makes, so a
/// machine signs every slice of a cluster with its own (ADR-0031,
/// amendments 2026-11-06 and 2026-11-25).
///
/// # Errors
/// The cluster has no name, or one that is no folder's, or this account
/// has no folder of its own; in words.
pub fn own_authority(name: &str) -> Result<PathBuf, String> {
    if name.is_empty() {
        return Err(
            "the cluster's file names no cluster and none was given, so no \
                    authority of it is kept on this machine: give the cluster's name, \
                    or the folder its authority is kept in"
                .to_string(),
        );
    }
    let mut parts = Path::new(name).components();
    if !matches!(
        (parts.next(), parts.next()),
        (Some(std::path::Component::Normal(_)), None)
    ) {
        return Err(format!(
            "the cluster's name {name:?} is no folder's, so no authority of it is kept \
             on this machine: give the folder its authority is kept in"
        ));
    }
    Ok(own_folder()?.join(AUTHORITY).join(name))
}

/// This account's own Xmip folder on this machine: `Xmip` in
/// `%LOCALAPPDATA%` on Windows; elsewhere `xmip` in `$XDG_STATE_HOME`, or
/// in `~/.local/state`, where the machine deploying an environment keeps
/// its private state too (`Get-XmipDeployStateFolder`).
fn own_folder() -> Result<PathBuf, String> {
    let named = |variable: &str| {
        std::env::var_os(variable)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
    };
    if cfg!(windows) {
        return named("LOCALAPPDATA")
            .map(|base| base.join("Xmip"))
            .ok_or_else(|| "LOCALAPPDATA names no folder of this account's".to_string());
    }
    named("XDG_STATE_HOME")
        .or_else(|| named("HOME").map(|home| home.join(".local").join("state")))
        .map(|base| base.join("xmip"))
        .ok_or_else(|| {
            "neither XDG_STATE_HOME nor HOME names a folder of this account's".to_string()
        })
}
/// `slice`, sliced from the cluster's file `cluster`, signed by `authority`
/// and written at `path`, with the authority's certificate beside it where
/// the node checks it ([`anchor`]): a slice placed on its node.
///
/// # Errors
/// Signing fails, or a file cannot be written; in words.
pub fn delivered(
    path: &Path,
    authority: &Issuer,
    cluster: &str,
    slice: &str,
) -> Result<(), String> {
    let signed = sign(authority, cluster, slice)?;
    let place = path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(AUTHORITY);
    let said = |at: &Path, error: std::io::Error| format!("{}: {error}", at.display());
    std::fs::create_dir_all(&place).map_err(|error| said(&place, error))?;
    let certificate = place.join(provision::issuer::CERTIFICATE);
    std::fs::write(&certificate, authority.certificate())
        .map_err(|error| said(&certificate, error))?;
    std::fs::write(path, signed).map_err(|error| said(path, error))
}
/// The text of `file` its cluster signed, and the signature, checked
/// against `anchor`, the authority's certificate as PEM.
///
/// # Errors
/// Why it does not verify, completing "the slice is refused: ".
pub fn verified<'a>(file: &'a str, anchor: &str) -> Result<(&'a str, Signature), String> {
    let (text, signature) = signed::split(file)?;
    let signature = signature.ok_or_else(|| "it is not signed".to_string())?;
    if signature.by != digest(&der(anchor)?) {
        return Err("it is signed by an authority other than this node's".to_string());
    }
    let value = codec::base64::decode(&signature.value)
        .map_err(|_| "its signature is not base64".to_string())?;
    let message = signed::message(text, &signature);
    let certificate =
        tls::certificate::Certificate::first(anchor).map_err(|error| error.to_string())?;
    if !certificate
        .verifies(&message, &value)
        .map_err(|error| error.to_string())?
    {
        return Err(
            "its signature does not verify: it was changed after it was signed".to_string(),
        );
    }
    if signed::named(text).as_deref() != Some(signature.node.as_str()) {
        return Err(format!(
            "it was signed for the node {} and names another",
            signature.node
        ));
    }
    Ok((text, signature))
}

/// The anchor beside the configuration at `path`.
///
/// # Errors
/// None is there, in words.
pub fn anchor(path: &Path) -> Result<String, String> {
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    let at = base.join(AUTHORITY).join(provision::issuer::CERTIFICATE);
    std::fs::read_to_string(&at).map_err(|error| {
        format!(
            "no cluster authority's certificate at {}: {error}; a node runs only a slice its \
             cluster's authority signed",
            at.display()
        )
    })
}

#[cfg(test)]
mod tests;
