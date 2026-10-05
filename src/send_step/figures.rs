//! What a node's send step counts per Send Port, the last Journey that
//! failed there with its reason, and every Journey that failed waiting in
//! its queue for an operator: what its snapshot publishes at the Port's
//! scope (`crate::running::publication`), so every surface shows it.

use std::collections::{BTreeMap, HashSet};

use xcore::JourneyId;

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
    /// The last that failed: its Journey and why, in words.
    pub last_failure: Option<(String, String)>,
    /// How many Journeys that failed wait in its queue for an operator, as
    /// the node's scans of the Ledger found them — those that failed before
    /// a restart, or on another node, among them.
    pub failing: u64,
    /// The oldest of them, at most [`PUBLISHED_FAILED`].
    pub oldest_failing: Vec<FailedJourney>,
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
        if let Some((journey, why)) = &self.last_failure {
            said.push_str(&format!("; the Journey {journey} failed: {why}"));
        }
        said
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
        for (port, failing) in &state.failing {
            let figures = figures.entry(port.clone()).or_default();
            figures.failing = failing.len() as u64;
            figures.oldest_failing = failing.values().take(PUBLISHED_FAILED).cloned().collect();
            if figures.last_failure.is_none()
                && let Some(newest) = failing.values().next_back()
            {
                let id = newest.journey.to_string();
                figures.last_failure = Some((id, newest.reason.clone()));
            }
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
