//! What the node picks up of what its Subscriptions hold, oldest first, and
//! what it says of each once it is done with it: delivered and released,
//! kept Failed, passed over, or read again (`runtime-model.md` section 9:
//! *the held ones are picked up oldest first*).

use std::time::{Duration, Instant};

use journey::Journey;
use persist::PersistError;
use persist::storage::{Held, JourneyRecord};
use route::Subscriber;

use super::{AGAIN, Pickup};
use crate::pickup::state::Entry;

/// A held Journey let go of to the node to pick up.
#[derive(Clone, Debug)]
pub struct Released {
    /// The Subscription that held it.
    pub subscription: String,
    /// Where it leads.
    pub destination: Subscriber,
    /// Its place, its Journey and what the holder kept beside it.
    pub held: Held,
    /// Whether a resume's sweep tries it again, should it have failed.
    pub retry: bool,
}

impl Pickup {
    /// Up to `max` held Journeys the node is to pick up now, oldest first
    /// in each queue, waiting up to `timeout` for a queue to read. Each is
    /// the node's until it says it is [`Pickup::delivered`],
    /// [`Pickup::kept`], [`Pickup::passed`] or to be read [`Pickup::again`].
    /// A queue that could not be read is audited and read again, from where
    /// it was, after a while.
    pub fn released(&self, timeout: Duration, max: usize) -> Vec<Released> {
        let mut state = self.lock();
        if !state.ready() && !timeout.is_zero() {
            state = self
                .wake
                .wait_timeout_while(state, timeout, |state| !state.ready())
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .0;
        }
        let now = Instant::now();
        let asks: Vec<(usize, u128, u64)> = state
            .entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.ready(now))
            .map(|(index, entry)| (index, entry.queue, entry.cursor))
            .collect();
        drop(state);
        let most = u32::try_from(max.max(1)).unwrap_or(u32::MAX);
        let mut taken = Vec::new();
        for (index, queue, from) in asks {
            let read = self.storage.read_held(queue, from, most);
            let mut state = self.lock();
            let entry = &mut state.entries[index];
            if entry.standing.paused || entry.cursor != from {
                continue;
            }
            let read = match read {
                Ok(read) => read,
                Err(error) => {
                    entry.not_before = Some(Instant::now() + AGAIN);
                    drop(state);
                    self.failed("subscription.pickup", &error.to_string());
                    continue;
                }
            };
            entry.not_before = None;
            let ended = read.held.len() < most as usize;
            for held in read.held {
                entry.cursor = held.sequence + 1;
                if entry.taken.insert(held.sequence) {
                    taken.push(Released {
                        subscription: entry.configured.name().to_string(),
                        destination: entry.configured.subscription.destination.clone(),
                        held,
                        retry: entry.retrying,
                    });
                }
            }
            if ended {
                (entry.pending, entry.retrying) = (false, false);
            }
        }
        taken
    }

    /// `released` was delivered: written as `journey` left it and released
    /// from its queue, in one write.
    ///
    /// # Errors
    /// Xmip Storage did not take it, in words: it is still held, and the
    /// node reads it again ([`Pickup::again`]).
    pub fn delivered(&self, released: &Released, journey: &Journey) -> Result<(), String> {
        let queue = released.held.hold.queue;
        self.storage
            .release_held(queue, released.held.sequence, &record(journey))
            .map_err(|error| self.unwritten(released, &error))?;
        self.settle(released, |entry| {
            entry.held = entry.held.saturating_sub(1);
            entry.picked_up += 1;
        });
        Ok(())
    }

    /// `released` did not depart: written as `journey` left it, Failed, and
    /// still held, its Message with it.
    ///
    /// # Errors
    /// As [`Pickup::delivered`].
    pub fn kept(&self, released: &Released, journey: &Journey) -> Result<(), String> {
        self.storage
            .write_journey(&record(journey))
            .map_err(|error| self.unwritten(released, &error))?;
        self.settle(released, |_| {});
        Ok(())
    }

    /// `released` is passed over as it is: still held, not tried now.
    pub fn passed(&self, released: &Released) {
        self.settle(released, |_| {});
    }

    /// `released` cannot be picked up for what the Ledger holds of it, said
    /// in `why`: audited, and passed over, still held, for an operator.
    pub fn unreadable(&self, released: &Released, why: &str) {
        self.failed(
            "subscription.pickup",
            &format!(
                "the Journey {} held by '{}' is not picked up: {why}",
                released.held.hold.journey, released.subscription
            ),
        );
        self.passed(released);
    }

    /// `released` could not be picked up for a fault that passes — Xmip
    /// Storage did not answer — so it and everything after it in its queue
    /// is read again, after a while, from its place.
    pub fn again(&self, released: &Released) {
        let mut state = self.lock();
        let Some(index) = state.index(&released.subscription) else {
            return;
        };
        let entry = &mut state.entries[index];
        let sequence = released.held.sequence;
        entry.taken.remove(&sequence);
        if sequence < entry.cursor {
            entry.cursor = sequence;
            entry.retrying |= released.retry;
        }
        entry.pending = true;
        entry.not_before = Some(Instant::now() + AGAIN);
    }

    fn settle(&self, released: &Released, done: impl FnOnce(&mut Entry)) {
        let mut state = self.lock();
        if let Some(index) = state.index(&released.subscription) {
            let entry = &mut state.entries[index];
            entry.taken.remove(&released.held.sequence);
            done(entry);
        }
    }

    fn unwritten(&self, released: &Released, error: &PersistError) -> String {
        self.failed("subscription.pickup", &error.to_string());
        format!(
            "Xmip Storage did not take the Journey {} held by '{}': {error}",
            released.held.hold.journey, released.subscription
        )
    }
}

/// A Journey as Xmip Storage keeps it.
fn record(journey: &Journey) -> JourneyRecord {
    JourneyRecord {
        journey: journey.journey_id(),
        body: journey.record(),
    }
}
