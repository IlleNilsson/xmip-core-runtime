//! A node's slice signed by its cluster's authority, and a node running
//! only a slice that verifies (ADR-0031, amendment 2026-11-06).
//!
//! The authority's certificate is the anchor, read from the [`AUTHORITY`]
//! folder beside the node's configuration and never from the file it
//! checks, so an edit cannot name another. A slice that verifies is kept
//! as the node's accepted slice, [`ACCEPTED`] in its data directory; one
//! that does not is refused, and the node runs its accepted slice instead.

use std::path::{Path, PathBuf};

use configure::signed::{self, Signature};
use provision::Issuer;

/// The folder beside a node's configuration that holds its cluster
/// authority's certificate, and its key on the node that keeps it.
pub const AUTHORITY: &str = "authority";

/// The node's accepted slice, in its data directory after the node's
/// name: the last one that verified.
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

/// `slice`, sliced from the cluster's file `cluster`, signed by `authority`.
///
/// # Errors
/// The slice's signature table does not read, or signing fails.
pub fn sign(authority: &Issuer, cluster: &str, slice: &str) -> Result<String, String> {
    let (text, _) = signed::split(slice)?;
    let cluster = digest(cluster.as_bytes());
    let value = authority
        .key()
        .sign(&signed::message(text, &cluster))
        .map_err(|error| error.to_string())?;
    let signature = Signature {
        cluster,
        by: digest(&der(authority.certificate())?),
        value: codec::base64::encode(&value),
    };
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
    let authority = provision::host::authority(&base.join(AUTHORITY), name, provision::now())
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
    let message = signed::message(text, &signature.cluster);
    let certificate = provision::Parsed::first(anchor).map_err(|error| error.to_string())?;
    if certificate
        .verifies(&message, &value)
        .map_err(|error| error.to_string())?
    {
        Ok((text, signature))
    } else {
        Err("its signature does not verify: it was changed after it was signed".to_string())
    }
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

/// The node a slice's text names, and the data directory it gives the
/// node whose configuration is at `path`.
fn named(path: &Path, text: &str) -> (Option<String>, PathBuf) {
    let (node, data) = signed::named(text);
    (
        node,
        configure::service::data_directory(data.as_deref(), path),
    )
}

/// The text a node whose configuration is at `path`, holding `file`, runs:
/// `file`'s own where it verifies, kept as the node's accepted slice; else
/// its accepted slice, and why `file` was refused.
///
/// # Errors
/// No anchor beside the configuration, an accepted slice that cannot be
/// kept, or a refused file and no accepted slice to run instead; each in
/// words.
pub fn accepted(path: &Path, file: &str) -> Result<(String, Option<String>), String> {
    let anchor = anchor(path)?;
    let (node, data) = named(path, file);
    let kept_at = data.join(format!("{}.{ACCEPTED}", node.as_deref().unwrap_or("node")));
    let kept = std::fs::read_to_string(&kept_at).ok();
    match verified(file, &anchor) {
        Ok((text, _)) => {
            if kept.as_deref() != Some(file) {
                std::fs::create_dir_all(&data)
                    .and_then(|()| std::fs::write(&kept_at, file))
                    .map_err(|error| {
                        format!(
                            "cannot keep the accepted slice at {}: {error}",
                            kept_at.display()
                        )
                    })?;
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
                        kept_at.display()
                    )),
                )),
                None => Err(format!(
                    "{refused}, and the node has no accepted slice to run"
                )),
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    /// A configuration folder with an authority in it, and its issuer.
    fn folder(name: &str) -> (PathBuf, Issuer) {
        let base = std::env::temp_dir().join(format!("xmip-signed-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let issuer = Issuer::kept_or_made(&base.join(AUTHORITY), "xmip-cluster", 0, 3600)
            .expect("an authority");
        (base.join("node.xmip"), issuer)
    }

    fn slice(node: &str) -> String {
        format!("[service]\nnode_name = \"{node}\"\ndata = \"data\"\n")
    }

    #[test]
    fn a_signed_slice_runs_and_is_kept_and_an_edit_runs_the_kept_one_instead() {
        let (path, issuer) = folder("edit");
        let file = sign(&issuer, "cluster", &slice("r1")).expect("signed");
        assert_eq!(accepted(&path, &file).expect("runs"), (slice("r1"), None));

        let edited = file.replace("[service]\n", "[service]\nname = \"edited\"\n");
        let (text, refused) = accepted(&path, &edited).expect("the kept one runs");
        assert_eq!(text, slice("r1"));
        let refused = refused.expect("said");
        assert!(refused.contains("changed after it was signed"), "{refused}");
    }

    #[test]
    fn an_unsigned_slice_with_nothing_accepted_is_refused_in_words() {
        let (path, _) = folder("unsigned");
        let refused = accepted(&path, &slice("r1")).expect_err("unsigned");
        assert!(
            refused.contains("it is not signed, and the node has no accepted slice"),
            "{refused}"
        );
    }

    #[test]
    fn a_slice_another_authority_signed_is_refused() {
        let (path, _) = folder("other");
        let (_, stranger) = folder("stranger");
        let file = sign(&stranger, "cluster", &slice("r1")).expect("signed");
        let refused = accepted(&path, &file).expect_err("a stranger's");
        assert!(
            refused.contains("an authority other than this node's"),
            "{refused}"
        );
    }
}
