//! What a node's pickup keeps under its one lock: each Subscription's
//! standing, what a resume let go of and the node has not taken, and what
//! is held in memory where the node was given no store (ADR-0013, amendment
//! 2026-09-30).

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use observe::{PauseState, Subscription as Published, now_unix_nanos};
use persist::{HeldMessage, SubscriptionHold};

use crate::configured_subscription::ConfiguredSubscription;

pub(super) struct State {
    pub(super) entries: Vec<Entry>,
    /// What a resume let go of and the node has not taken yet, oldest
    /// first: an entry's index and a held Message's number.
    pub(super) released: VecDeque<(usize, u64)>,
    /// Held Messages, where the node was given no store.
    pub(super) memory: BTreeMap<(usize, u64), HeldMessage>,
}

pub(super) struct Entry {
    pub(super) configured: ConfiguredSubscription,
    pub(super) hold: SubscriptionHold,
    pub(super) picked_up: u64,
    /// Taken to be picked up, not yet picked up.
    pub(super) taken: BTreeSet<u64>,
    /// Picked up ahead of an older one still taken.
    pub(super) done: BTreeSet<u64>,
}

impl Entry {
    /// The held Message numbered `sequence` is done with: the range it
    /// holds moves past every one done, oldest first.
    pub(super) fn settle(&mut self, sequence: u64) {
        self.done.insert(sequence);
        while self.done.remove(&self.hold.first_held) {
            self.hold.first_held += 1;
        }
    }
}

impl State {
    pub(super) fn index(&self, name: &str) -> Option<usize> {
        self.entries
            .iter()
            .position(|entry| entry.hold.subscription == name)
    }

    pub(super) fn set(&mut self, index: usize, paused: bool, who: &str) {
        let hold = &mut self.entries[index].hold;
        hold.paused = paused;
        hold.by = if paused {
            who.to_string()
        } else {
            String::new()
        };
        hold.since_unix_nanos = now_unix_nanos();
    }

    /// Every Subscription as the node at `node` publishes it, in the order
    /// routing asks them.
    pub(super) fn standing(&self, node: &str) -> Vec<Published> {
        self.entries
            .iter()
            .map(|entry| Published {
                node: node.to_string(),
                name: entry.hold.subscription.clone(),
                application: entry.configured.application.clone(),
                filter: entry.configured.subscription.filter.text().to_string(),
                destination: entry.configured.destination(),
                file: entry.configured.file.clone(),
                configuration: entry.configured.entry.clone(),
                state: if entry.hold.paused {
                    PauseState::Paused
                } else {
                    PauseState::Active
                },
                by: entry.hold.by.clone(),
                picked_up: entry.picked_up,
                held: entry.hold.held(),
                since_unix_nanos: entry.hold.since_unix_nanos,
            })
            .collect()
    }
}
