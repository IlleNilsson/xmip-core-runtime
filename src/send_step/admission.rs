//! Admission to the Send pool: the one door every Journey this node sends
//! goes through, whether a Publication claims it in its own write, a
//! resumed Subscription moves it, or a scan finds it in its queue.
//!
//! **What the node holds is bounded by the pool's threads.** A Journey is
//! claimed and taken into memory only under a place the pool has room for:
//! its most threads, less every Journey this node owns — handed, queued,
//! sending, or waiting for a retry's due time — and every place admitted
//! and not yet owned. What has no place stays durable and unclaimed in its
//! queue, and its queue is read again the moment a place frees, so a slow
//! far end leaves its backlog in the Ledger, never in memory. Until
//! 2026-10-06 only a scan asked for room: a Publication claimed every
//! Journey it opened for a Port this node sends and handed it on, and the
//! pool queued whatever came, however much.
//!
//! **What it owns, it owns under a claim** ([`Owned`]): each Journey's
//! claim, its Send Port, and where the claim stands
//! ([`super::renewal`]). A Publication's claims are owned only where Xmip
//! Storage's answer says this node holds them ([`SendStep::confirmed`]).

use persist::storage::Claim;
use xcore::JourneyId;

use super::{Departure, LinedUp, SendStep, State, renewal};

/// A Journey this node holds claimed: in flight on the Send pool, or
/// waiting for its due time — its Send Port, and where its claim stands.
#[derive(Clone, Debug)]
pub(super) struct Owned {
    pub(super) claim: Claim,
    pub(super) queue: u128,
    pub(super) sequence: Option<String>,
    pub(super) port: String,
    pub(super) standing: renewal::Standing,
}

impl Owned {
    /// `departure`, owned: its claim confirmed until its `until`.
    pub(super) fn of(departure: &Departure) -> Self {
        Self {
            claim: departure.claim.clone(),
            queue: departure.queue,
            sequence: departure.sequence.clone(),
            port: departure.to.name().to_string(),
            standing: renewal::Standing::confirmed(departure.until),
        }
    }
}

impl SendStep {
    /// Places in the Send pool for up to `wanted` Journeys: as many as it
    /// has room for now, each held until the Journey it was taken for is
    /// owned ([`SendStep::own`]) or the place is given back
    /// ([`SendStep::withdraw`]).
    pub(crate) fn admit(&self, wanted: usize) -> usize {
        let mut state = self.lock();
        let admitted = wanted.min(self.room_in(&state));
        state.admitted += admitted;
        admitted
    }

    /// `places` admitted and not used: what a Publication or a move Xmip
    /// Storage did not take had them, or a scan claimed nothing with one.
    pub(crate) fn withdraw(&self, places: usize) {
        if places == 0 {
            return;
        }
        let mut state = self.lock();
        state.admitted = state.admitted.saturating_sub(places);
        state.freed();
        drop(state);
        self.wake.notify_all();
    }

    /// The places `lined` was admitted, given back: its Publication was not
    /// written, or nothing it claimed is to be sent here.
    pub(crate) fn withdrawn(&self, lined: &LinedUp) {
        self.withdraw(lined.admitted);
    }

    /// `lined` as its Publication's write answered: only the claims Xmip
    /// Storage says this node `holds` are sent from here, and the place of
    /// every other is given back. A Publication asked again after a lost
    /// answer holds none another node has taken up since, so a Journey sent
    /// meanwhile is never sent a second time from here.
    pub(crate) fn confirmed(&self, lined: &mut LinedUp, holds: &[Claim]) {
        let held = |claim: &Claim| {
            holds
                .iter()
                .any(|kept| kept.journey == claim.journey && kept.token == claim.token)
        };
        let before = lined.claimed.len();
        lined.claimed.retain(|(_, _, _, claim)| held(claim));
        lined.claims.retain(held);
        let gone = before - lined.claimed.len();
        lined.admitted = lined.admitted.saturating_sub(gone);
        self.withdraw(gone);
    }

    /// How many more Journeys the Send pool can take now: its most threads,
    /// less every Journey this node owns and every place admitted for one.
    pub(crate) fn room(&self) -> usize {
        self.room_in(&self.lock())
    }

    fn room_in(&self, state: &State) -> usize {
        let held = state.owned.len() + state.admitted;
        self.limits.most.max(1).saturating_sub(held)
    }

    /// The Journey `id`, claimed under a place admitted for it, owned now.
    pub(super) fn own(&self, id: JourneyId, owned: Owned) {
        let mut state = self.lock();
        state.admitted = state.admitted.saturating_sub(1);
        state.taking.remove(&id);
        state.owned.insert(id, owned);
    }

    /// The Journey `id`, found by a scan and not claimed by this node after
    /// all — another holds it, it is not to be sent, or Xmip Storage did not
    /// answer — and its place given back.
    pub(super) fn untake(&self, id: JourneyId) {
        let mut state = self.lock();
        if state.taking.remove(&id) {
            state.admitted = state.admitted.saturating_sub(1);
        }
        state.freed();
        drop(state);
        self.wake.notify_all();
    }

    /// `queue` holds Journeys the pool had no room for: read again as soon
    /// as a place frees.
    pub(super) fn starve(&self, queue: u128) {
        let mut state = self.lock();
        if !state.starved.contains(&queue) {
            state.starved.push(queue);
        }
    }
}

impl State {
    /// A place in the Send pool freed: every queue that had Journeys
    /// waiting for one is read now.
    pub(super) fn freed(&mut self) {
        for queue in std::mem::take(&mut self.starved) {
            if !self.asked.contains(&queue) {
                self.asked.push(queue);
            }
        }
    }
}
