//! A node trusts a slice before it runs it, and keeps the last one that ran
//! (ADR-0031, amendment 2026-11-12). Runtime startup owns the order:
//!
//! ```text
//! 1 trust      node.xmip read by the trust alone, beside the pinned anchor,
//!              one absent or unreadable refused like any other; a
//!              candidate above the serial seen is pinned as seen before
//!              anything reads it (signed::admitted)
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
//! `<node>/configuration` ([`Standing`]); whether it runs it and its Xmip
//! Storage stands Fine is whether it is ready ([`readiness`]), what a
//! deployment asks before it restarts the next node.

use std::path::Path;
use std::sync::Arc;

use persist::storage::MemberRecord;
use xcore::SystemClock;

use super::serving::serve;
use super::{Refusal, Running};
use crate::linked::Linked;
use crate::membership::{self, Floor, Joined};
use crate::service::StartupPhase;
use crate::signed::{self, Admitted, Refused, Slice, Which};

mod published;
mod readiness;
mod standing;

pub use readiness::{awaited, readiness};
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
    /// tried again at the next start where `again`: it could not be read,
    /// or a step of its attempt refused it, not trust.
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

    /// Its membership of the cluster begun: its process, drawn as it
    /// started, and its start, numbered and kept as its process's first act
    /// ([`started`]) or here where it was started otherwise
    /// (`membership::numbering`), then its row written to Xmip Storage once
    /// it is reached, and the members followed (`crate::membership`). A
    /// start that cannot be numbered, or a thread that does not start,
    /// leaves it no member, said as the node's failure; a start is never
    /// numbered later, which could rank it above a start after it.
    fn join(&mut self) {
        let numbered = self
            .numbered
            .take()
            .unwrap_or_else(|| membership::numbering::numbered(&self.configuration, &*self.clock));
        let start = match numbered {
            Ok(start) => start,
            Err(problem) => {
                self.tally.fail(&self.node, problem);
                return;
            }
        };
        let declared = self.declaring(node::Capability::of(&self.roles));
        let runs = self.attempt.slice.which();
        let row = MemberRecord {
            process: self.process,
            start,
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
        let configuration = self.configuration.clone();
        let floor: Floor =
            Box::new(move |latest| membership::numbering::floored(&configuration, latest));
        match Joined::start(storage, (row, self.storage.placing(), floor), timings) {
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
/// The configuration is read by its trust alone (`signed::admitted`):
/// nothing reads it before, so one absent or unreadable is a candidate
/// refused, and the active configuration runs.
///
/// **Its start is numbered first**, before anything can refuse it
/// (`membership::numbering`), one number for both attempts: from that
/// moment a publication an earlier process of the node left says nothing of
/// whether it is ready, nor what it runs (`readiness`; open problem 137;
/// ADR-0056, amendment 2026-11-24). Until that day it was numbered as the
/// node began serving, and a start refused before then left its node's last
/// publication standing for it.
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
    let numbered = membership::numbering::numbered(Path::new(path), &SystemClock);
    let mut attempted = |slice: Slice, tried: Tried| -> Result<(Running, T), Refusal> {
        let mut running = Running::start(path, Attempt { slice, tried }, linked())?;
        running.numbered = Some(numbered.clone());
        let made = program(&running)?;
        running.activate();
        Ok((running, made))
    };
    let unread = |reason: String| Refusal::at(StartupPhase::ReadConfiguration, vec![reason]);
    let Admitted { candidate, active } = signed::admitted(Path::new(path)).map_err(unread)?;
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
        Err(refused) => Candidate::Admission(refused),
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

/// How a candidate was refused: by its admission, unread or by trust, in
/// its words, or at a step of its attempt, named by its file and which
/// slice it is.
enum Candidate {
    Admission(Refused),
    Started(String, Refusal),
}

impl Candidate {
    /// What the node's record says of it, and whether the node tries it
    /// again at its next start for a reason that may have gone.
    fn said(&self) -> (String, bool) {
        match self {
            Self::Admission(refused) => (refused.why.clone(), refused.again),
            Self::Started(named, refusal) => (format!("{named}, {refusal}"), true),
        }
    }

    /// The start refused: the candidate's refusal, at its phase, and
    /// `none`, why nothing else ran.
    fn and(self, none: &str) -> Refusal {
        let mut refusal = match self {
            Self::Admission(refused) => {
                Refusal::at(StartupPhase::ReadConfiguration, vec![refused.why])
            }
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
