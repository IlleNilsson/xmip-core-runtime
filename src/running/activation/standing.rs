//! A node's configuration standing (ADR-0031, amendment 2026-11-12): which
//! slice it runs, and what of its candidate was refused, at
//! `<node>/configuration`. Fine where it runs what it was given; Stressed
//! where it serves and an operator must act — its candidate refused, or
//! not kept — as a certificate due for renewal is (`certificate_standing`).
//! The words are the runtime's, and no surface keeps its own: every surface
//! reads the snapshot, and `xmip-service --activation` reads them back
//! ([`activation`]).

use std::path::Path;

use observe::{Health, Publication};

use super::super::publication::{SNAPSHOT, location};
use crate::signed::Which;

/// The leaf beneath a node its configuration standing is published at.
pub const CONFIGURATION: &str = "configuration";

/// Which slice a node runs, and what of its candidate was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Standing {
    /// Nothing new was given: the active configuration runs.
    Active { runs: Which },
    /// The candidate runs, and is the active configuration now, replacing
    /// the one that ran before where there was one.
    Activated {
        runs: Which,
        replacing: Option<Which>,
    },
    /// The candidate was refused, in `candidate`'s words, and the active
    /// configuration runs; tried again at the next start where `again`.
    Refused {
        candidate: String,
        runs: Which,
        again: bool,
    },
    /// The candidate runs, and could not be kept as the active
    /// configuration, for `why`.
    Unkept { runs: Which, why: String },
}

impl Standing {
    /// Fine where the node runs what it was given, Stressed otherwise.
    #[must_use]
    pub const fn health(&self) -> Health {
        match self {
            Self::Active { .. } | Self::Activated { .. } => Health::Fine,
            Self::Refused { .. } | Self::Unkept { .. } => Health::Stressed,
        }
    }

    /// What it is, in the words its record says.
    #[must_use]
    pub fn said(&self) -> String {
        match self {
            Self::Active { runs } => format!("active: {runs}"),
            Self::Activated {
                runs,
                replacing: Some(replacing),
            } => format!("activated: {runs}, replacing {replacing}"),
            Self::Activated {
                runs,
                replacing: None,
            } => format!("activated: {runs}, the first this node ran"),
            Self::Refused {
                candidate,
                runs,
                again,
            } => format!(
                "candidate refused: {candidate}; the node runs its active configuration, \
                 {runs}{}",
                if *again {
                    ", and tries the candidate again when it starts again"
                } else {
                    ""
                }
            ),
            Self::Unkept { runs, why } => format!(
                "{runs} runs and is not kept as the active configuration: {why}; started \
                 again, the node tries it again"
            ),
        }
    }

    /// Whether `evidence`, a record's, says the node runs `which` as its
    /// active configuration: [`Standing::said`]'s words, read back by the
    /// one place that writes them.
    #[must_use]
    pub fn runs(evidence: &str, which: &Which) -> bool {
        let active = Self::Active {
            runs: which.clone(),
        };
        evidence == active.said() || evidence.starts_with(&format!("activated: {which},"))
    }

    /// Its record beneath `node`, handed to `record`.
    pub(crate) fn publish(&self, node: &str, record: &mut impl FnMut(String, Health, String)) {
        record(
            format!("{node}/{CONFIGURATION}"),
            self.health(),
            self.said(),
        );
    }
}

/// Whether the node configured at `path` runs the slice there as its active
/// configuration, as its last publication says (`<node>/configuration`): a
/// stopped node's says what ran. What a deployment asks after it restarts a
/// node (`xmip-service --activation`): a started service alone does not say
/// its slice took, since a slice the node cannot start is refused and the
/// node runs its active configuration.
///
/// # Errors
/// It does not, or it cannot be told; in the node's own words where it
/// published any.
pub fn activation(path: &str) -> Result<String, String> {
    let file =
        std::fs::read_to_string(path).map_err(|error| format!("cannot read {path}: {error}"))?;
    let signature = configure::signed::split(&file)
        .map_err(|why| format!("{path}: {why}"))?
        .1
        .ok_or_else(|| format!("{path} is not signed, and a node runs only a signed slice"))?;
    let which = Which {
        serial: signature.serial,
        save: signature.cluster,
    };
    let not = |why: String| format!("{path}, {which}, is not what the node runs: {why}");
    let (document, _, _) = crate::start::read(path).map_err(|unread| not(unread.reason))?;
    let service = &document.service;
    let snapshot = service.data_directory(Path::new(path)).join(SNAPSHOT);
    let scope = format!(
        "{}/{CONFIGURATION}",
        location(&service.cluster_name, &service.node_name)
    );
    let text = std::fs::read_to_string(&snapshot).map_err(|error| {
        not(format!(
            "it has published nothing at {}: {error}",
            snapshot.display()
        ))
    })?;
    let publication = Publication::read(&text)
        .map_err(|why| not(format!("{} does not read: {why}", snapshot.display())))?;
    let record = publication
        .records
        .iter()
        .find(|record| record.scope == scope)
        .ok_or_else(|| not(format!("{} says nothing at {scope}", snapshot.display())))?;
    if record.health == Health::Fine && Standing::runs(&record.evidence, &which) {
        Ok(record.evidence.clone())
    } else {
        Err(not(record.evidence.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn which(serial: u64) -> Which {
        Which {
            serial,
            save: "sha256:00".to_string(),
        }
    }

    #[test]
    fn a_record_says_it_runs_a_slice_only_where_that_slice_is_active() {
        let active = Standing::Active { runs: which(5) };
        let activated = Standing::Activated {
            runs: which(5),
            replacing: Some(which(4)),
        };
        let refused = Standing::Refused {
            candidate: "node.xmip, serial 6 of save sha256:00, refused at validate-startup: no \
                        transport for smb://"
                .to_string(),
            runs: which(5),
            again: true,
        };
        for runs in [&active, &activated] {
            assert_eq!(runs.health(), Health::Fine);
            assert!(Standing::runs(&runs.said(), &which(5)), "{}", runs.said());
            assert!(!Standing::runs(&runs.said(), &which(55)), "{}", runs.said());
        }
        assert!(
            !Standing::runs(&activated.said(), &which(4)),
            "the one replaced"
        );
        assert_eq!(refused.health(), Health::Stressed);
        assert!(!Standing::runs(&refused.said(), &which(5)));
        assert!(!Standing::runs(&refused.said(), &which(6)));
        let said = refused.said();
        assert!(
            said.starts_with("candidate refused: node.xmip, serial 6"),
            "{said}"
        );
        assert!(
            said.contains("active configuration, serial 5 of save"),
            "{said}"
        );
        assert!(
            said.ends_with("tries the candidate again when it starts again"),
            "{said}"
        );
    }

    #[test]
    fn a_candidate_that_runs_and_is_not_kept_is_stressed_saying_so() {
        let unkept = Standing::Unkept {
            runs: which(7),
            why: "the disk is full".to_string(),
        };
        assert_eq!(unkept.health(), Health::Stressed);
        assert!(!Standing::runs(&unkept.said(), &which(7)));
        assert!(
            unkept
                .said()
                .contains("not kept as the active configuration")
        );
    }
}
