//! A node trusts a slice before it runs it, and keeps the last one that ran
//! (ADR-0031, amendment 2026-11-12). Runtime startup owns the order:
//!
//! ```text
//! 1 trust      node.xmip read beside the pinned anchor; a candidate above
//!              the serial seen is pinned as seen before anything reads it
//!              (signed::admitted)
//! 2 attempt    the candidate: every startup phase (Running::start), then
//!              the program's own steps that can refuse, serving nothing
//! 3 activate   the active configuration replaced by the candidate's file,
//!              then serving begins (Running::activate)
//! 4 fallback   the candidate refused at any step of 1 or 2: the attempt let
//!              go, and the same attempt over the active configuration
//! 5 refused    nothing to run: the start refused with both refusals
//! ```
//!
//! A refusal refuses the attempt, not the node, whether the configuration
//! or the machine caused it; a refused candidate is never made active,
//! stays where it was given, and is tried again at the next start. Once a
//! node accepts work under a configuration nothing later demotes it. What
//! the node runs, and what was refused, is its record at
//! `<node>/configuration` ([`Standing`]).

use std::path::Path;
use std::sync::Arc;

use persist::storage::MemberRecord;

use super::serving::serve;
use super::{Refusal, Running};
use crate::linked::Linked;
use crate::membership::{self, Joined};
use crate::service::StartupPhase;
use crate::signed::{self, Admitted, Slice, Which};

mod standing;

pub use standing::{CONFIGURATION, Standing, activation};

/// What a slice is tried as.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Tried {
    /// The node's candidate, admitted by its trust, replacing the active
    /// configuration where the node has one.
    Candidate { replacing: Option<Which> },
    /// The node's active configuration, given no candidate.
    Active,
    /// The node's active configuration, its candidate refused for `why`;
    /// tried again at the next start where `again`, its refusal not trust's.
    Fallback { why: String, again: bool },
}

/// One attempt: the slice tried, and what it is tried as.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attempt {
    pub slice: Slice,
    pub tried: Tried,
}

impl Running {
    /// Begin accepting work: where the node runs its candidate, the active
    /// configuration is replaced by the candidate's file first, then the
    /// serving thread starts. Once only; a node already serving is left as
    /// it is.
    pub fn activate(&mut self) {
        let Some(served) = self.served.take() else {
            return;
        };
        let runs = self.attempt.slice.which();
        let standing = match &self.attempt.tried {
            Tried::Candidate { replacing } => {
                match signed::activated(&self.configuration, &self.attempt.slice) {
                    Ok(()) => Standing::Activated {
                        runs,
                        replacing: replacing.clone(),
                    },
                    Err(why) => Standing::Unkept { runs, why },
                }
            }
            Tried::Active => Standing::Active { runs },
            Tried::Fallback { why, again } => Standing::Refused {
                candidate: why.clone(),
                runs,
                again: *again,
            },
        };
        self.standing = Some(standing);
        let serving = serve(served, Arc::clone(&self.stopping), Arc::clone(&self.tally));
        self.serving = Some(serving);
        self.join();
        self.gather();
    }

    /// Its membership of the cluster begun: its row written to Xmip Storage
    /// once it is reached, and the members followed (`crate::membership`).
    /// A thread that does not start leaves it no member, said as the node's
    /// failure.
    fn join(&mut self) {
        let declared = node::Capability::of(&self.roles).with_online(self.online);
        let runs = self.attempt.slice.which();
        let row = MemberRecord {
            process: membership::process(),
            node: self.location(),
            roles: declared.words(),
            evidence: declared.evidence(),
            operate: self.operated.get().cloned(),
            sync: None,
            storage_place: None,
            save: runs.save,
            serial: runs.serial,
            started_unix_nanos: 0,
            stopped_unix_nanos: None,
            written: 0,
            latest: false,
        };
        let timings = (self.tuning.storage_wait, self.tuning.storage().pass_over);
        let storage = Arc::clone(self.storage.storage());
        match Joined::start(storage, (row, self.storage.placing()), timings) {
            Ok(joined) => self.membership = Some(joined),
            Err(problem) => self.tally.fail(&self.node, problem),
        }
    }

    /// What the node runs, and what of its candidate was refused: none
    /// until it is activated.
    #[must_use]
    pub const fn standing(&self) -> Option<&Standing> {
        self.standing.as_ref()
    }

    /// The slice the node runs, or tries to.
    #[must_use]
    pub const fn attempt(&self) -> &Attempt {
        &self.attempt
    }
}

/// The node configured at `path`, started by the slices its trust admits,
/// in order, and activated: its candidate first and, where the candidate is
/// refused at any step before it accepts work, its active configuration, in
/// the same process. `linked` gives what the program links, once for each
/// attempt; `program` takes each attempt's own steps that can refuse it,
/// the attempt started and serving nothing, and what it makes is the
/// program's while the node runs. A refused attempt is dropped, which lets
/// go of everything it opened, before the next.
///
/// # Errors
/// Nothing to run: the candidate's refusal, at its phase, and why the
/// active configuration did not run either. A pin or an anchor the node
/// cannot hold to refuses the start at once (`signed::admitted`).
pub fn started<T>(
    path: &str,
    mut linked: impl FnMut() -> Linked,
    mut program: impl FnMut(&Running) -> Result<T, Refusal>,
) -> Result<(Running, T), Refusal> {
    let mut attempted = |slice: Slice, tried: Tried| -> Result<(Running, T), Refusal> {
        let mut running = Running::start(path, Attempt { slice, tried }, linked())?;
        let made = program(&running)?;
        running.activate();
        Ok((running, made))
    };
    let unread = |reason: String| Refusal::at(StartupPhase::ReadConfiguration, vec![reason]);
    let file = std::fs::read_to_string(path)
        .map_err(|error| unread(format!("cannot read {path}: {error}")))?;
    let Admitted { candidate, active } =
        signed::admitted(Path::new(path), &file).map_err(unread)?;
    let refused = match candidate {
        Ok(None) => return attempted(active.map_err(unread)?, Tried::Active),
        Ok(Some(candidate)) => {
            let named = format!("{}, {}", file_name(path), candidate.which());
            let replacing = active.as_ref().ok().map(Slice::which);
            match attempted(candidate, Tried::Candidate { replacing }) {
                Ok(started) => return Ok(started),
                Err(refusal) => Candidate::Started(named, refusal),
            }
        }
        Err(why) => Candidate::Trusted(why),
    };
    let active = match active {
        Ok(active) => active,
        Err(none) => return Err(refused.and(&none)),
    };
    let runs = active.which();
    let (why, again) = refused.said();
    attempted(active, Tried::Fallback { why, again })
        .map_err(|fallback| refused.and(&format!("its active configuration, {runs}, {fallback}")))
}

/// How a candidate was refused: by trust, in its words, or at a step of its
/// attempt, named by its file and which slice it is.
enum Candidate {
    Trusted(String),
    Started(String, Refusal),
}

impl Candidate {
    /// What the node's record says of it, and whether the node tries it
    /// again at its next start for a reason that may have gone.
    fn said(&self) -> (String, bool) {
        match self {
            Self::Trusted(why) => (why.clone(), false),
            Self::Started(named, refusal) => (format!("{named}, {refusal}"), true),
        }
    }

    /// The start refused: the candidate's refusal, at its phase, and
    /// `none`, why nothing else ran.
    fn and(self, none: &str) -> Refusal {
        let mut refusal = match self {
            Self::Trusted(why) => Refusal::at(StartupPhase::ReadConfiguration, vec![why]),
            Self::Started(_, refusal) => refusal,
        };
        refusal.problems.push(format!("and {none}"));
        refusal
    }
}

/// The configuration file's name, as the node's record names a candidate.
fn file_name(path: &str) -> &str {
    Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(path)
}
