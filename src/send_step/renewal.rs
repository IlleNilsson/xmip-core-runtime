//! The claims of work in flight, renewed while it runs, and what a renewal
//! that does not succeed means (`runtime-model.md` section 10, *Corrected
//! 2026-10-06*; ADR-0018, amendment 2026-10-06).
//!
//! **Lost is lost.** A renewal Xmip Storage answers with no claim — the
//! claim lapsed and another node took it, or it ended — means the Journey
//! is another holder's: no Location is tried for it again from here, no
//! hand-on is written for it, its loss is counted at its Send Port and
//! audited once. A send already under way cannot be called back; it carries
//! the Journey's identifier, the key the far end deduplicates by (section
//! 15), so the other holder's send of it is the same delivery.
//!
//! **Xmip Storage not answering is a flat-out error.** A renewal it does not
//! answer leaves the claim unconfirmed, and its Send Port is Done from the
//! first, its evidence naming Xmip Storage as what did not answer and since
//! when (the owner, 2026-10-06: *Storage is not here is a flat-out error*);
//! until 2026-10-06 it was Stressed. **Attempts are bounded.** A claim is
//! surely held a lease from when the request that last
//! confirmed it was asked — a lease the Storage node counts from its own
//! later now — so this node goes on trying Locations only until then, on
//! its own clock, never comparing two. Past it the claim is presumed lost:
//! audited once, and no Location is tried from here until a renewal
//! answers again. Whatever this node writes after is conditional on the
//! claim in Xmip Storage, which decides. Until 2026-10-06 every renewal's
//! answer was dropped, and a node that had lost its claim went on sending.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use xcore::JourneyId;

use super::dispatch::run;
use super::{Departure, SendStep, Settled};
use crate::message_path::Runtime;
use crate::pool::Pool;

/// How long a renewal Xmip Storage did not answer waits before it is asked
/// again, for a Journey waiting for its due time.
const AGAIN: Duration = Duration::from_millis(250);

/// Where a claim this node owns stands.
#[derive(Clone, Copy, Debug)]
pub(super) struct Standing {
    /// Surely held until then, on this node's clock.
    until: Instant,
    /// Since when its renewal has not been answered.
    unconfirmed: Option<Instant>,
    /// A renewal found it another's.
    lost: bool,
    /// Its prolonged uncertainty was audited.
    said: bool,
}

impl Standing {
    /// A claim confirmed until `until`.
    pub(super) const fn confirmed(until: Instant) -> Self {
        Self {
            until,
            unconfirmed: None,
            lost: false,
            said: false,
        }
    }

    fn holds(&self, now: Instant) -> bool {
        !self.lost && now < self.until
    }

    /// Since when its renewal has been unanswered, if it is now: when the
    /// first renewal Xmip Storage did not answer was asked.
    pub(super) const fn unanswered_since(&self) -> Option<Instant> {
        self.unconfirmed
    }
}

/// What a renewal answered.
enum Renewed {
    Held(persist::storage::Claim),
    Lost,
    Unanswered(String),
}

impl SendStep {
    /// Whether the Journey `id` is surely this node's to send now: owned,
    /// its claim not found another's, and confirmed within a lease.
    #[must_use]
    pub fn holds(&self, id: JourneyId) -> bool {
        let now = Instant::now();
        self.lock()
            .owned
            .get(&id)
            .is_some_and(|owned| owned.standing.holds(now))
    }

    /// Whether a renewal found the claim on the Journey `id` another's.
    #[must_use]
    pub fn is_lost(&self, id: JourneyId) -> bool {
        self.lock()
            .owned
            .get(&id)
            .is_some_and(|owned| owned.standing.lost)
    }

    /// Renew the claim of every Journey in flight every third of a lease,
    /// until the step is closed and nothing is in flight: its own thread,
    /// so a send that takes longer than a lease, or one queued behind a
    /// long scan, is not taken up by another node meanwhile.
    pub(super) fn renewing(&self) {
        let mut next = Instant::now() + self.lease / 3;
        let mut state = self.lock();
        loop {
            if state.closed && state.owned.is_empty() {
                return;
            }
            let now = Instant::now();
            if next <= now {
                drop(state);
                self.renew();
                next = Instant::now() + self.lease / 3;
                state = self.lock();
                continue;
            }
            state = self
                .wake
                .wait_timeout(state, next - now)
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .0;
        }
    }

    /// Renew the claim of every Journey in flight that is not found lost,
    /// and keep where each stands.
    fn renew(&self) {
        let state = self.lock();
        let waiting: HashSet<_> = state
            .due
            .iter()
            .map(|(_, departure)| departure.work.journey.journey_id())
            .collect();
        let flying: Vec<_> = state
            .owned
            .iter()
            .filter(|(id, owned)| !waiting.contains(id) && !owned.standing.lost)
            .map(|(id, owned)| (*id, owned.claim.clone()))
            .collect();
        drop(state);
        for (id, claim) in flying {
            let asked = Instant::now();
            let renewed = match self.storage.renew(&claim, self.lease) {
                Ok(Some(claim)) => Renewed::Held(claim),
                Ok(None) => Renewed::Lost,
                Err(why) => Renewed::Unanswered(why.to_string()),
            };
            self.renewed(id, asked, renewed);
        }
    }

    /// Where the claim on `id`, renewed as asked at `asked`, stands now;
    /// a loss and a prolonged uncertainty each audited once.
    fn renewed(&self, id: JourneyId, asked: Instant, renewed: Renewed) {
        let mut state = self.lock();
        let Some(owned) = state.owned.get_mut(&id) else {
            return;
        };
        let standing = &mut owned.standing;
        let said = match renewed {
            Renewed::Held(claim) if claim.token == owned.claim.token => {
                owned.claim = claim;
                *standing = Standing::confirmed(asked + self.lease);
                None
            }
            Renewed::Held(_) => None,
            Renewed::Lost if standing.lost => None,
            Renewed::Lost => {
                standing.lost = true;
                Some(format!(
                    "the claim on the Journey {id} is another's now: no Location is tried \
                     for it again from here, and a send already under way carries its \
                     Journey's identifier for the far end to deduplicate"
                ))
            }
            Renewed::Unanswered(why) => {
                standing.unconfirmed.get_or_insert(asked);
                if standing.holds(Instant::now()) || standing.said {
                    None
                } else {
                    standing.said = true;
                    Some(format!(
                        "Xmip Storage has not confirmed the claim on the Journey {id} for \
                         longer than its lease, so it is presumed lost: no Location is tried \
                         for it from here until a renewal is answered ({why})"
                    ))
                }
            }
        };
        drop(state);
        if let Some(problem) = said {
            self.failed(&problem);
        }
    }

    /// The Journey of `departure` no longer this node's — found another's,
    /// or its claim presumed lapsed — let go of, counted at its Send Port,
    /// and, where it was not said before, audited with `why`.
    pub(super) fn lost(&self, departure: &Departure, why: &str) {
        let id = departure.work.journey.journey_id();
        let mut state = self.lock();
        let said = state
            .owned
            .get(&id)
            .is_some_and(|owned| owned.standing.lost || owned.standing.said);
        let port = departure.to.name().to_string();
        state.figures.entry(port).or_default().lost += 1;
        state.owned.remove(&id);
        state.freed();
        drop(state);
        self.wake.notify_all();
        if !said {
            self.failed(&format!("the Journey {id} to {}: {why}", departure.to));
        }
    }

    /// The claim of `departure`, waiting for its due time, confirmed until
    /// its `until`.
    pub(super) fn confirm(&self, departure: &Departure) {
        let id = departure.work.journey.journey_id();
        if let Some(owned) = self.lock().owned.get_mut(&id) {
            owned.claim = departure.claim.clone();
            owned.standing = Standing::confirmed(departure.until);
        }
    }
}

/// `departure`, due again: its claim renewed and sent; let go of where the
/// claim is another's now; due again shortly where Xmip Storage did not
/// answer, while its claim surely holds, and let go of as presumed lost
/// once it may not — another node, or this one, takes it up from its queue
/// once the claim has lapsed.
pub(super) fn resume<'env>(
    pool: &Pool<'_, 'env>,
    runtime: &'env Runtime<'env>,
    settled: Settled<'env>,
    mut departure: Departure,
) {
    let step = runtime.send;
    let asked = Instant::now();
    match step.storage.renew(&departure.claim, step.lease) {
        Ok(Some(claim)) => {
            departure.claim = claim;
            departure.until = asked + step.lease;
            step.confirm(&departure);
            run(pool, runtime, settled, departure);
        }
        Ok(None) => step.lost(&departure, "its claim is another's now"),
        Err(_) if Instant::now() < departure.until => {
            let id = departure.work.journey.journey_id();
            let mut state = step.lock();
            if let Some(owned) = state.owned.get_mut(&id) {
                owned.standing.unconfirmed.get_or_insert(asked);
            }
            state.due.push((Instant::now() + AGAIN, departure));
        }
        Err(why) => step.lost(
            &departure,
            &format!(
                "Xmip Storage has not confirmed its claim for longer than its lease, so it \
                 is presumed lost and left to lapse ({why})"
            ),
        ),
    }
}
