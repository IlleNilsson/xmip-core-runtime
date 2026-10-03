//! Which of a Publication's Journeys a Subscription holds, decided before
//! the Publication is written and counted once it is durable: what the
//! Publication's one write keeps at the end of each queue
//! (`persist::storage::Hold`), so a refused write holds nothing anywhere.

use journey::Journey;
use persist::storage::Hold;
use route::Routing;

use super::Pickup;

/// Which of a Publication's Journeys a Subscription holds: what the
/// Publication's write keeps, and what the node counts once it is durable.
#[derive(Debug, Default)]
pub struct Holding {
    holds: Vec<Hold>,
    held: Vec<(usize, String)>,
    picked: Vec<usize>,
}

impl Holding {
    /// What the Publication keeps, one per Journey held.
    #[must_use]
    pub fn holds(&self) -> &[Hold] {
        &self.holds
    }

    /// `routing` without what is held: where the Message departs now.
    #[must_use]
    pub fn picked(&self, routing: &Routing) -> Routing {
        let held = |name: &str| self.held.iter().any(|(_, held)| held == name);
        Routing {
            evaluations: routing
                .evaluations
                .iter()
                .filter(|evaluation| !(evaluation.matched() && held(&evaluation.subscription_id)))
                .cloned()
                .collect(),
        }
    }
}

impl Pickup {
    /// Which of `journeys`, the Journeys a Publication opens — one for each
    /// Subscription `routing` matched, in its order — a Subscription holds:
    /// one that is paused, or whose queue holds anything still. What the
    /// holder keeps beside each is `body`'s, asked once, where one is held.
    pub fn holding(
        &self,
        routing: &Routing,
        journeys: &[Journey],
        body: impl FnOnce() -> Vec<u8>,
    ) -> Holding {
        self.held(routing, journeys, body, false)
    }

    /// Which of `journeys` its Subscription holds — as [`Pickup::holding`]
    /// decides, or, where `every` says, all of them: what a Replay from the
    /// Dead Message Queue opens has no receive cycle to depart from, so each
    /// is held and picked up from its queue as a resume picks up.
    pub(super) fn held(
        &self,
        routing: &Routing,
        journeys: &[Journey],
        body: impl FnOnce() -> Vec<u8>,
        every: bool,
    ) -> Holding {
        let state = self.lock();
        let mut holding = Holding::default();
        let mut body = Some(body);
        let mut kept = Vec::new();
        let matched = routing.evaluations.iter().filter(|e| e.matched());
        for (evaluation, journey) in matched.zip(journeys) {
            let name = evaluation.subscription_id.as_str();
            let Some(index) = state.index(name) else {
                continue;
            };
            let entry = &state.entries[index];
            if !every && !entry.standing.paused && entry.held == 0 {
                holding.picked.push(index);
                continue;
            }
            if let Some(body) = body.take() {
                kept = body();
            }
            holding.holds.push(Hold {
                queue: entry.queue,
                journey: journey.journey_id(),
                body: kept.clone(),
            });
            holding.held.push((index, name.to_string()));
        }
        holding
    }

    /// The Publication `holding` was decided for is durable: count what
    /// each Subscription picked up and holds, and wake the node for what an
    /// active one holds.
    pub fn published(&self, holding: &Holding) {
        let mut state = self.lock();
        for index in &holding.picked {
            state.entries[*index].picked_up += 1;
        }
        let mut woken = false;
        for (index, _) in &holding.held {
            let entry = &mut state.entries[*index];
            entry.held += 1;
            if !entry.standing.paused {
                entry.pending = true;
                woken = true;
            }
        }
        if woken {
            self.wake.notify_all();
        }
    }
}
