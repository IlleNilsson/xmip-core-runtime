//! A node's slice signed by its cluster's authority, and a node running
//! only a slice that verifies (ADR-0031, amendments 2026-11-06 and
//! 2026-11-07).
//!
//! The authority's certificate travels beside the node's configuration, in
//! [`AUTHORITY`], and is never read from the file it checks. What the node
//! trusts it by is held where whoever writes the configuration folder does
//! not write: the node's accepted slice ([`kept_at`]), in the default data
//! directory beside the configuration folder, a private file the node
//! itself writes. Its signature pins the authority (`by`), the node
//! (`node`) and the last serial accepted (`serial`). A slice that verifies
//! against a certificate of that fingerprint, names that node and carries a
//! higher serial is kept in its place; any other is refused, and the node
//! runs its accepted slice instead. The first slice a node accepts pins all
//! three.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use configure::signed::{self, Signature};
use provision::Issuer;

/// The folder beside a node's configuration that holds its cluster
/// authority's certificate, and its key on the node that keeps it.
pub const AUTHORITY: &str = "authority";

/// The node's accepted slice, after its configuration file's stem in the
/// default data directory: the last one that verified.
pub const ACCEPTED: &str = "accepted.xmip";

/// `sha256:` and the hexadecimal SHA-256 of `bytes`.
fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", codec::hex::encode(&provision::sha256(bytes)))
}

/// The certificate PEM `pem` holds, as DER.
fn der(pem: &str) -> Result<Vec<u8>, String> {
    provision::pem::decode("CERTIFICATE", pem)
        .map_err(|error| error.to_string())?
        .into_iter()
        .next()
        .ok_or_else(|| "the authority's certificate holds no CERTIFICATE".to_string())
}

/// A fresh serial and the Unix second it was taken in: the clock's
/// nanoseconds, one above the last this process gave where the clock has
/// not moved, so two slices signed in a row never share one.
fn serial() -> (u64, i64) {
    static LAST: AtomicU64 = AtomicU64::new(0);
    let now = u64::try_from(observe::now_unix_nanos()).unwrap_or(0);
    let last = LAST
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |last| {
            Some(now.max(last + 1))
        })
        .unwrap_or_else(|last| last);
    let serial = now.max(last + 1);
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
    let (text, _) = signed::split(slice)?;
    let node = signed::named(text)
        .ok_or("the slice names no node under [service], and a slice is signed for its node")?;
    let (serial, issued) = serial();
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
/// one-node install's, and the program slicing for a node.
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
    let certificate = provision::Parsed::first(anchor).map_err(|error| error.to_string())?;
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

/// Where the node whose configuration is at `path` keeps its accepted
/// slice: `<stem>.accepted.xmip` in the default data directory, found from
/// the configuration's place alone and never from what a slice says.
#[must_use]
pub fn kept_at(path: &Path) -> PathBuf {
    let stem = path
        .file_stem()
        .map_or_else(|| "node".into(), |stem| stem.to_string_lossy());
    configure::service::data_directory(None, path).join(format!("{stem}.{ACCEPTED}"))
}

/// Whether a check keeps what it accepts: the running node does; a plan,
/// an install and a surface only read.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Keep {
    Yes,
    No,
}

/// The text a node whose configuration is at `path`, holding `file`, runs:
/// `file`'s own where it verifies, kept as the node's accepted slice; else
/// its accepted slice, and why `file` was refused.
///
/// # Errors
/// No anchor beside the configuration, one other than the node pinned, an
/// accepted slice that cannot be read or kept, or a refused file and no
/// accepted slice to run instead; each in words.
pub fn accepted(path: &Path, file: &str) -> Result<(String, Option<String>), String> {
    admitted(path, file, Keep::Yes)
}

/// [`accepted`], keeping nothing: what the node would run, for whoever
/// reads its configuration without running it. An accepted slice this
/// reader may not read pins nothing for it.
///
/// # Errors
/// As [`accepted`].
pub fn checked(path: &Path, file: &str) -> Result<(String, Option<String>), String> {
    admitted(path, file, Keep::No)
}

/// [`accepted`] and [`checked`], once.
fn admitted(path: &Path, file: &str, keep: Keep) -> Result<(String, Option<String>), String> {
    let at = kept_at(path);
    let kept = match std::fs::read_to_string(&at) {
        Ok(kept) => Some(kept),
        Err(error) if error.kind() == ErrorKind::NotFound || keep == Keep::No => None,
        Err(error) => {
            return Err(format!(
                "cannot read the accepted slice at {}: {error}",
                at.display()
            ));
        }
    };
    let pin = kept.as_deref().map(|kept| pinned(kept, &at)).transpose()?;
    let anchor = anchor(path)?;
    if let Some(pin) = &pin
        && pin.by != digest(&der(&anchor)?)
    {
        return Err(format!(
            "the cluster authority's certificate beside {} is not the one this node pinned, \
             {}, by its accepted slice at {}; where the authority was replaced, an \
             administrator removes that slice",
            path.display(),
            pin.by,
            at.display()
        ));
    }
    let admitted = verified(file, &anchor).and_then(|(text, signature)| {
        admits(pin.as_ref(), kept.as_deref(), file, &signature).map(|()| text)
    });
    match admitted {
        Ok(text) => {
            if keep == Keep::Yes && kept.as_deref() != Some(file) {
                kept_in(&at, file)?;
            }
            Ok((text.to_string(), None))
        }
        Err(why) => {
            let refused = format!("{} is refused: {why}", path.display());
            match kept
                .as_deref()
                .and_then(|kept| verified(kept, &anchor).ok())
            {
                Some((text, _)) => Ok((
                    text.to_string(),
                    Some(format!(
                        "{refused}; the node runs its accepted slice, {}",
                        at.display()
                    )),
                )),
                None => Err(format!(
                    "{refused}, and the node has no accepted slice to run"
                )),
            }
        }
    }
}

/// The signature of the accepted slice `kept`, kept at `at`: the node's pin.
fn pinned(kept: &str, at: &Path) -> Result<Signature, String> {
    match signed::split(kept) {
        Ok((_, Some(signature))) => Ok(signature),
        Ok((_, None)) => Err(format!(
            "the accepted slice at {} is not signed",
            at.display()
        )),
        Err(why) => Err(format!("the accepted slice at {}: {why}", at.display())),
    }
}

/// Whether a slice signed `signature`, the file `file`, may follow the
/// accepted slice `kept` the node pinned as `pin`: the same node, and a
/// higher serial, or the accepted slice itself again.
///
/// # Errors
/// Why not, completing "the slice is refused: ".
fn admits(
    pin: Option<&Signature>,
    kept: Option<&str>,
    file: &str,
    signature: &Signature,
) -> Result<(), String> {
    let Some(pin) = pin else {
        return Ok(());
    };
    if signature.node != pin.node {
        return Err(format!(
            "it is the slice of the node {}, and this node is {}",
            signature.node, pin.node
        ));
    }
    let again = signature.serial == pin.serial && kept == Some(file);
    if signature.serial <= pin.serial && !again {
        return Err(format!(
            "its serial {} is not above {}, the accepted slice's: it is older, or replayed",
            signature.serial, pin.serial
        ));
    }
    Ok(())
}

/// `file` kept at `at` as the node's accepted slice, a private file in a
/// directory made private where it is absent.
fn kept_in(at: &Path, file: &str) -> Result<(), String> {
    let place = at.parent().unwrap_or_else(|| Path::new("."));
    secret::private_file::directory(place)
        .and_then(|()| secret::private_file::replace(at, file.as_bytes()))
        .map_err(|error| {
            format!(
                "cannot keep the accepted slice at {}: {error}",
                at.display()
            )
        })
}

#[cfg(test)]
mod tests;
