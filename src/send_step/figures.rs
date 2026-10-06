//! What a node's send step counts per Send Port, the last Journey that
//! failed there with its reason, and every Journey that failed waiting in
//! its queue for an operator: what its snapshot publishes at the Port's
//! scope (`crate::running::publication`), so every surface shows it.
//!
//! **Now, and what was.** `failing`, `oldest_failing` and `blocked` are the
//! queue as it stands, from the Journeys a scan of the Ledger read Failed
//! in it; `sent`, `failed` and `last_failure` are history since the node
//! started. Until 2026-10-06 `last_failure` was filled from the queue where
//! the node had seen none fail, so history and now were one figure.

use std::collections::{BTreeMap, HashSet};
use std::time::Instant;

use observe::{FailedJourneys, LastFailure};
use xcore::{Clock, JourneyId, SystemClock};

use super::SendStep;

/// The most failed Journeys of one Send Port a publication carries, the
/// oldest first; the rest are read from Xmip Storage a page at a time
/// ([`super::SendStep::failed_journeys`]).
pub const PUBLISHED_FAILED: usize = 100;

/// One Send Port's figures.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PortFigures {
    /// Journeys sent since the node started: written Completed.
    pub sent: u64,
    /// Journeys whose every Send Location failed its tries since the node
    /// started: written Failed.
    pub failed: u64,
    /// Journeys waiting now for a retry's due time.
    pub waiting: u64,
    /// The last that failed here since the node started: its Journey and
    /// why, in words. History: it may since have been retried or dismissed.
    pub last_failure: Option<(String, String)>,
    /// How many Journeys that failed wait in its queue for an operator now,
    /// as the node's scans of the Ledger found them — those that failed
    /// before a restart, or on another node, among them.
    pub failing: u64,
    /// Whether one of them blocks its sequence now: a Sequential Send Port
    /// whose `on_failure` is `block`.
    pub blocked: bool,
    /// The oldest of them, at most [`PUBLISHED_FAILED`].
    pub oldest_failing: Vec<FailedJourney>,
    /// Claims of its Journeys this node holds whose renewal Xmip Storage
    /// has not answered, now: the Port is Done while any is.
    pub unconfirmed: u64,
    /// When the oldest of those renewals was asked, in nanoseconds since
    /// the Unix epoch: since when Xmip Storage has not answered.
    pub unanswered_since: Option<i128>,
    /// Journeys whose claim this node found another's, or presumed lapsed,
    /// since it started, and let go of without sending them further.
    pub lost: u64,
}

/// A Journey that failed, waiting in its Send Port's queue for an
/// operator's Retry or Dismiss.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FailedJourney {
    pub journey: JourneyId,
    /// Its place in its Send Port's queue: oldest lowest.
    pub place: u64,
    /// Why it failed, as its last entry says.
    pub reason: String,
}

impl PortFigures {
    /// The Port's state in one line, as its snapshot says it.
    #[must_use]
    pub fn evidence(&self) -> String {
        let mut said = format!(
            "sent {}, failed {}, waiting {}, failed in its queue {}",
            self.sent, self.failed, self.waiting, self.failing
        );
        if self.blocked {
            said.push_str(", its sequence blocked behind them");
        }
        if self.unconfirmed > 0 {
            said.push_str(&format!(
                ", Xmip Storage has not answered the renewal of its claims {}",
                self.unconfirmed
            ));
            if let Some(since) = self.unanswered_since {
                said.push_str(&format!(" since {}", codec::civil::rfc3339_nanos(since)));
            }
        }
        if self.lost > 0 {
            said.push_str(&format!(", claims lost to another holder {}", self.lost));
        }
        if let Some((journey, why)) = &self.last_failure {
            said.push_str(&format!("; the Journey {journey} failed: {why}"));
        }
        said
    }

    /// The last Journey that failed here since the node started, as every
    /// publication of it says it: history, apart from what fails now.
    #[must_use]
    pub fn last(&self) -> Option<LastFailure> {
        self.last_failure
            .as_ref()
            .map(|(journey, reason)| LastFailure {
                journey: journey.clone(),
                reason: reason.clone(),
            })
    }

    /// The Journeys that failed at the Send Port `port` of the node at
    /// `node`, as its snapshot publishes them: how many wait in its queue
    /// now — zero where none, so a surface says *none now* from the record
    /// rather than from its absence — whether they block its sequence, the
    /// oldest with why, and apart from them the last that failed there since
    /// the node started, as history. Until 2026-10-06 only a Port with some
    /// waiting was published.
    #[must_use]
    pub fn published(&self, node: &str, port: &str) -> FailedJourneys {
        FailedJourneys {
            node: node.to_string(),
            send_port: port.to_string(),
            count: self.failing,
            blocked: self.blocked,
            journeys: self
                .oldest_failing
                .iter()
                .map(FailedJourney::published)
                .collect(),
            last_failure: self.last(),
        }
    }
}

impl FailedJourney {
    /// The Journey as a publication, and every list of failed Journeys,
    /// says it.
    #[must_use]
    pub fn published(&self) -> observe::FailedJourney {
        observe::FailedJourney {
            journey: self.journey.to_string(),
            sequence: self.place,
            reason: self.reason.clone(),
        }
    }
}

impl SendStep {
    /// The figures of every Send Port this node sends or has sent through.
    #[must_use]
    pub fn figures(&self) -> BTreeMap<String, PortFigures> {
        let state = self.lock();
        let mut figures = state.figures.clone();
        for port in state.ports.keys() {
            figures.entry(port.clone()).or_default();
        }
        for (_, waiting) in &state.due {
            let port = waiting.to.name().to_string();
            figures.entry(port).or_default().waiting += 1;
        }
        let (now, wall) = (Instant::now(), SystemClock.unix_timestamp_nanos());
        for owned in state.owned.values() {
            if let Some(asked) = owned.standing.unanswered_since() {
                let ago = i128::try_from(now.saturating_duration_since(asked).as_nanos());
                let since = wall - ago.unwrap_or(0);
                let figures = figures.entry(owned.port.clone()).or_default();
                figures.unconfirmed += 1;
                figures.unanswered_since =
                    Some(figures.unanswered_since.map_or(since, |was| was.min(since)));
            }
        }
        for (port, failing) in &state.failing {
            let figures = figures.entry(port.clone()).or_default();
            figures.failing = failing.len() as u64;
            figures.oldest_failing = failing.values().take(PUBLISHED_FAILED).cloned().collect();
            figures.blocked = !failing.is_empty() && state.ports.get(port) == Some(&true);
        }
        figures
    }

    /// The Journey at `place` in `port`'s queue, read Failed with `reason`.
    pub(crate) fn found_failing(&self, port: &str, place: u64, journey: JourneyId, reason: String) {
        let mut state = self.lock();
        let failing = state.failing.entry(port.to_string()).or_default();
        failing.retain(|_, failed| failed.journey != journey);
        failing.insert(
            place,
            FailedJourney {
                journey,
                place,
                reason,
            },
        );
    }

    /// The Journey `journey` of `port`'s queue, read and found not Failed:
    /// sent again, finished, or not readable.
    pub(crate) fn not_failing(&self, port: &str, journey: JourneyId) {
        if let Some(failing) = self.lock().failing.get_mut(port) {
            failing.retain(|_, failed| failed.journey != journey);
        }
    }

    /// A whole read of `port`'s queue found only `present`, by Journey and
    /// place: what failed there and is gone — dismissed, or sent again, by
    /// another node — forgotten.
    pub(crate) fn read_whole(&self, port: &str, present: &HashSet<(JourneyId, u64)>) {
        if let Some(failing) = self.lock().failing.get_mut(port) {
            failing.retain(|place, failed| present.contains(&(failed.journey, *place)));
        }
    }
}
