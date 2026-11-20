//! What a node trusts of its configuration as it starts, kept apart from what
//! it runs (ADR-0031, amendment 2026-11-12).
//!
//! The node is given a candidate, `node.xmip`, and never writes it; it is
//! read here, and nothing reads it before (ADR-0031, amendment 2026-11-19).
//! None of what the node trusts it by is found from it: the authority's
//! certificate is in the `authority` folder beside the configuration
//! ([`super::anchor`]), and the node keeps two private files of its own in
//! the default data directory (`configure::signed::pin_at`, `active_at`),
//! found from where the configuration is: its pin, the authority's
//! fingerprint, the node, the highest serial seen in a slice that verified
//! and that slice's digest, written as a candidate is admitted and before
//! anything reads it; and its active configuration, the signed file of the
//! last slice that ran, written by [`activated`] alone, as the node begins
//! to accept work (`running::activation`).
//!
//! A candidate is admitted where it verifies against the authority's
//! certificate beside the configuration, that certificate being the pinned
//! one, is signed for the pinned node, and carries a serial above the
//! pinned one, or the pinned serial and the pinned slice's digest: the same
//! candidate seen before and not yet run. Anything else is refused in words
//! and never runs; so is a candidate absent or unreadable, which the node
//! tries again at its next start. The active configuration is verified
//! again each start, and is what runs where the candidate is refused or
//! where there is none.

use std::path::Path;

use configure::signed::{self, Pin, Signature};

use super::{anchor, der, digest, verified};
use crate::kept::kept;

/// Why there is no active configuration to run, in words a refusal joins
/// with "and".
const NONE: &str = "the node has no active configuration to run";

/// A slice as the node holds it: its file, byte for byte, the text above
/// its signature, and the signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Slice {
    pub file: String,
    pub text: String,
    pub signature: Signature,
}

/// Which slice it is, as a node's records name it: its serial and the save
/// of `cluster.xmip` it was sliced from (ADR-0031, amendment 2026-11-06,
/// point 3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Which {
    pub serial: u64,
    pub save: String,
}

impl std::fmt::Display for Which {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "serial {} of save {}", self.serial, self.save)
    }
}

impl Slice {
    /// `file`, checked against `anchor`, the authority's certificate.
    fn verified(file: &str, anchor: &str) -> Result<Self, String> {
        let (text, signature) = verified(file, anchor)?;
        Ok(Self {
            file: file.to_string(),
            text: text.to_string(),
            signature,
        })
    }

    /// Which slice it is.
    #[must_use]
    pub fn which(&self) -> Which {
        Which {
            serial: self.signature.serial,
            save: self.signature.cluster.clone(),
        }
    }

    /// `sha256:` and the SHA-256 of its file: what a pin holds of it.
    #[must_use]
    pub fn digest(&self) -> String {
        digest(self.file.as_bytes())
    }
}

/// Why a candidate was refused, `<path> is refused: <why>`, and whether the
/// node tries it again at its next start: where it could not be read, a
/// cause that may pass, and never where trust refused what it read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refused {
    pub why: String,
    pub again: bool,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.why)
    }
}

/// What trust admits of a node's configuration as it starts.
#[derive(Debug)]
pub struct Admitted {
    /// The configuration file's slice, where trust admits it and it is not
    /// the active configuration: what the node tries first. `Ok(None)` where
    /// it is the active configuration, byte for byte; why it was refused
    /// otherwise, absent and unreadable among the reasons.
    pub candidate: Result<Option<Slice>, Refused>,
    /// The node's active configuration, verified again: what runs where the
    /// candidate is refused or where there is none; why there is none
    /// otherwise, in words that also follow "and".
    pub active: Result<Slice, String>,
}

impl Admitted {
    /// The slice the node tries first: the candidate, else its active
    /// configuration.
    ///
    /// # Errors
    /// Neither runs, both in words.
    pub fn first(&self) -> Result<&Slice, String> {
        match (&self.candidate, &self.active) {
            (Ok(Some(candidate)), _) => Ok(candidate),
            (_, Ok(active)) => Ok(active),
            (Ok(None), Err(none)) => Err(none.clone()),
            (Err(refused), Err(none)) => Err(format!("{refused}; and {none}")),
        }
    }
}

/// Whether a reading records what it saw: the running node does; a plan,
/// an install and a surface only read.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Keep {
    Yes,
    No,
}

/// What trust admits of the configuration at `path`, read here, as the
/// running node starts: the candidate pinned as seen where its serial is
/// above the pin's, or the first slice admitted where nothing is pinned,
/// before anything reads it.
///
/// # Errors
/// No anchor beside the configuration, one other than the node pinned, or a
/// pin or an active configuration that cannot be read, or a pin that cannot
/// be written; each in words. The node does not start. A candidate that
/// cannot be read is no error: it is refused, and the active configuration
/// runs.
pub fn admitted(path: &Path) -> Result<Admitted, String> {
    admission(path, Keep::Yes)
}

/// The text the node configured at `path` tries first, writing nothing: for
/// whoever reads a configuration without running it. A pin or an active
/// configuration this reader may not read pins nothing for it.
///
/// # Errors
/// As [`admitted`], and nothing to run, in words.
pub fn checked(path: &Path) -> Result<String, String> {
    let admitted = admission(path, Keep::No)?;
    admitted.first().map(|slice| slice.text.clone())
}

/// `slice` kept as the active configuration of the node configured at
/// `path`: what it runs from now, and runs again where a later candidate is
/// refused.
///
/// # Errors
/// It cannot be written, in words.
pub fn activated(path: &Path, slice: &Slice) -> Result<(), String> {
    kept(
        &signed::active_at(path),
        slice.file.as_bytes(),
        "active configuration",
    )
}

/// [`admitted`] and [`checked`], once.
fn admission(path: &Path, keep: Keep) -> Result<Admitted, String> {
    let pin_at = signed::pin_at(path);
    let pin = held(&pin_at, keep, "pin")?
        .map(|text| {
            Pin::read(&text).map_err(|why| format!("the pin at {}: {why}", pin_at.display()))
        })
        .transpose()?;
    let active_at = signed::active_at(path);
    let active = held(&active_at, keep, "active configuration")?;
    let anchor = anchor(path)?;
    let by = digest(&der(&anchor)?);
    if let Some(pin) = &pin
        && pin.by != by
    {
        return Err(format!(
            "the cluster authority's certificate beside {} is not the one this node pinned, \
             {}, in {}; where the authority was replaced, an administrator removes that pin",
            path.display(),
            pin.by,
            pin_at.display()
        ));
    }
    let candidate = candidate(path, &anchor, pin.as_ref(), active.as_deref());
    let node = pin.as_ref().map(|pin| pin.node.clone()).or_else(|| {
        let admitted = candidate.as_ref().ok().and_then(Option::as_ref);
        admitted.map(|slice| slice.signature.node.clone())
    });
    let active = active.map_or_else(
        || Err(NONE.to_string()),
        |held| {
            Slice::verified(&held, &anchor)
                .and_then(|slice| named(node.as_deref(), &slice).map(|()| slice))
                .map_err(|why| {
                    format!(
                        "the node's active configuration at {} is refused: {why}, so it has \
                         none to run",
                        active_at.display()
                    )
                })
        },
    );
    if keep == Keep::Yes {
        seen(&pin_at, pin.as_ref(), &by, (&candidate, &active))?;
    }
    Ok(Admitted { candidate, active })
}

/// The candidate at `path`, read here and nowhere before: none where it is
/// `active`, byte for byte; the slice where it verifies against `anchor`
/// and follows `pin`; refused otherwise, and tried again only where it
/// could not be read.
fn candidate(
    path: &Path,
    anchor: &str,
    pin: Option<&Pin>,
    active: Option<&str>,
) -> Result<Option<Slice>, Refused> {
    let refused = |why: String, again: bool| Refused {
        why: format!("{} is refused: {why}", path.display()),
        again,
    };
    let file = std::fs::read_to_string(path)
        .map_err(|error| refused(format!("it cannot be read: {error}"), true))?;
    if active == Some(file.as_str()) {
        return Ok(None);
    }
    Slice::verified(&file, anchor)
        .and_then(|slice| follows(pin, &slice).map(|()| Some(slice)))
        .map_err(|why| refused(why, false))
}

/// Whether `slice` may follow what `pin` holds: the same node, and a serial
/// above the pinned one, or the pinned serial and the pinned slice itself.
///
/// # Errors
/// Why not, completing "it is refused: ".
fn follows(pin: Option<&Pin>, slice: &Slice) -> Result<(), String> {
    let Some(pin) = pin else {
        return Ok(());
    };
    named(Some(&pin.node), slice)?;
    let serial = slice.signature.serial;
    if serial > pin.serial || (serial == pin.serial && slice.digest() == pin.slice) {
        return Ok(());
    }
    if serial == pin.serial {
        return Err(format!(
            "its serial {serial} is the one this node has seen, and this is not that slice"
        ));
    }
    Err(format!(
        "its serial {serial} is not above {}, the highest this node has seen: it is older, \
         or replayed",
        pin.serial
    ))
}

/// Whether `slice` is the slice of `node`, where a node is known.
fn named(node: Option<&str>, slice: &Slice) -> Result<(), String> {
    match node {
        Some(node) if slice.signature.node != node => Err(format!(
            "it is the slice of the node {}, and this node is {node}",
            slice.signature.node
        )),
        _ => Ok(()),
    }
}

/// The pin written at `at` where a slice admitted is above `pin`: the
/// candidate, or, where nothing is pinned, the first slice admitted, the
/// candidate or else the active configuration.
fn seen(
    at: &Path,
    pin: Option<&Pin>,
    by: &str,
    (candidate, active): (&Result<Option<Slice>, Refused>, &Result<Slice, String>),
) -> Result<(), String> {
    let first = match (candidate, active) {
        (Ok(Some(candidate)), _) => Some(candidate),
        (_, Ok(active)) if pin.is_none() => Some(active),
        _ => None,
    };
    let Some(slice) =
        first.filter(|slice| pin.is_none_or(|pin| slice.signature.serial > pin.serial))
    else {
        return Ok(());
    };
    let pin = Pin {
        by: by.to_string(),
        node: slice.signature.node.clone(),
        serial: slice.signature.serial,
        slice: slice.digest(),
    };
    kept(at, pin.written().as_bytes(), "pin")
}

/// The file at `at`, the node's `what` (`crate::kept::held`); none where it
/// is absent, or, for a reader that keeps nothing, where it may not be read.
fn held(at: &Path, keep: Keep, what: &str) -> Result<Option<String>, String> {
    crate::kept::held(at, what).or_else(|refused| match keep {
        Keep::No => Ok(None),
        Keep::Yes => Err(refused),
    })
}
