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
    /// counted from when the last round began, until the step is closed and
    /// nothing is in flight: its own thread, so a send that takes longer
    /// than a lease, or one queued behind a long scan, is not taken up by
    /// another node meanwhile. A round is one request for every claim, so
    /// an answer Xmip Storage is slow to give costs the round one wait, never
    /// one per claim, and a round always ends well inside a lease.
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
                next = now + self.lease / 3;
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
    /// in one request, and keep where each stands.
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
            .map(|(_, owned)| owned.claim.clone())
            .collect();
        drop(state);
        if flying.is_empty() {
            return;
        }
        let asked = Instant::now();
        let answered = self.storage.renew(&flying, self.lease);
        for claim in flying {
            let renewed = match &answered {
                Ok(held) => held
                    .iter()
                    .find(|held| held.journey == claim.journey && held.token == claim.token)
                    .map_or(Renewed::Lost, |held| Renewed::Held(held.clone())),
                Err(why) => Renewed::Unanswered(why.to_string()),
            };
            self.renewed(&claim, asked, renewed);
        }
    }

    /// Where `claim`, renewed as asked at `asked`, stands now; a loss and a
    /// prolonged uncertainty each audited once. An answer for a claim this
    /// node no longer holds the Journey by — the send ended and an operator's
    /// Retry claimed it again under a new token — says nothing of the new
    /// claim, and is dropped.
    fn renewed(&self, claim: &persist::storage::Claim, asked: Instant, renewed: Renewed) {
        let id = claim.journey;
        let mut state = self.lock();
        let Some(owned) = state.owned.get_mut(&id) else {
            return;
        };
        if owned.claim.token != claim.token {
            return;
        }
        let standing = &mut owned.standing;
        let said = match renewed {
            Renewed::Held(claim) => {
                owned.claim = claim;
                let until = standing.until.max(asked + self.lease);
                *standing = Standing::confirmed(until);
                None
            }
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
    let renewed = step
        .storage
        .renew(std::slice::from_ref(&departure.claim), step.lease)
        .map(|held| {
            held.into_iter()
                .find(|held| held.token == departure.claim.token)
        });
    match renewed {
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use persist::fixture::Memory;
    use persist::storage::{Claim, Embedded, XmipStorage};
    use secret::{Held, KekName};

    use super::*;
    use crate::send_step::admission::Owned;
    use crate::tuning::Tuning;

    fn step() -> SendStep {
        let keys = Held::new(secret::fixture::Memory::default());
        let kek = KekName::new("storage").expect("a name");
        let storage: Arc<dyn XmipStorage> = Arc::new(
            Embedded::open(Memory::default(), Memory::default(), &keys, &kek).expect("opened"),
        );
        let cluster = configure::fixture::test_cluster();
        let node = cluster.node_scope(0);
        SendStep::new((&cluster.scope(), &node), storage, &Tuning::default(), None)
    }

    fn claim(token: u128) -> Claim {
        Claim {
            journey: JourneyId::new(7),
            holder: configure::fixture::test_cluster().node_scope(0),
            token,
            until_unix_nanos: 0,
        }
    }

    /// The Journey owned under `claim`, confirmed a lease from now.
    fn owning(step: &SendStep, claim: Claim) {
        let owned = Owned {
            claim,
            queue: 1,
            sequence: None,
            port: "Out".to_string(),
            standing: Standing::confirmed(Instant::now() + step.lease),
        };
        step.lock().owned.insert(JourneyId::new(7), owned);
    }

    #[test]
    fn a_late_answer_for_an_earlier_claim_says_nothing_of_the_claim_held_now() {
        let step = step();
        let (old, new) = (claim(1), claim(2));
        // The renewal of `old` asked, then the send ended and an operator's
        // Retry claimed the Journey again under `new`, before it answered.
        owning(&step, new.clone());
        let asked = Instant::now() - step.lease * 2;

        step.renewed(&old, asked, Renewed::Lost);
        step.renewed(&old, asked, Renewed::Unanswered("late".to_string()));

        let id = JourneyId::new(7);
        assert!(!step.is_lost(id), "the new claim is not marked lost");
        assert!(step.holds(id), "the new claim still holds");
        let owned = step.lock().owned[&id].clone();
        assert_eq!(owned.standing.unanswered_since(), None, "nor unconfirmed");

        step.renewed(&new, Instant::now(), Renewed::Lost);
        assert!(step.is_lost(id), "an answer for the claim held now counts");
    }

    #[test]
    fn a_renewal_keeps_a_later_deadline_it_knew() {
        let step = step();
        let id = JourneyId::new(7);
        let kept = Instant::now() + step.lease * 10;
        owning(&step, claim(1));
        step.lock().owned.get_mut(&id).expect("owned").standing = Standing::confirmed(kept);

        step.renewed(&claim(1), Instant::now(), Renewed::Held(claim(1)));

        let owned = step.lock().owned[&id].clone();
        assert!(owned.standing.until >= kept, "not shortened to a lease");
    }
}
