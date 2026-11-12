//! What a running node counts at each Receive Location it starts and along
//! each (Location, Subscription) it routes by: the names resolved once, as
//! the node starts, and an atomic add per Stream (the millisecond rule;
//! ADR-0018, amendment 2026-11-11). A Subscription is found by the id its
//! evaluation names, never by where it stands in a list, so what a
//! Location fed is drawn to the Subscription that took it.

use std::sync::atomic::{AtomicU64, Ordering};

use route::Routing;

/// The Streams each Receive Location took, and the Streams routed along
/// each (Location, Subscription) that routed any, by name.
pub(crate) type PlacedCounts = (Vec<(String, u64)>, Vec<(String, String, u64)>);

/// The counters, resolved as the node starts.
#[derive(Default)]
pub(super) struct Placed {
    locations: Vec<(String, AtomicU64)>,
    subscriptions: Vec<String>,
    /// One per (Location, Subscription), Location by Location.
    routes: Vec<AtomicU64>,
}

impl Placed {
    /// Counters for the Receive Locations `locations` and the
    /// Subscriptions `subscriptions`, each by its name.
    pub(super) fn of(locations: Vec<String>, subscriptions: Vec<String>) -> Self {
        let routes = (0..locations.len() * subscriptions.len())
            .map(|_| AtomicU64::default())
            .collect();
        Self {
            locations: locations
                .into_iter()
                .map(|name| (name, AtomicU64::default()))
                .collect(),
            subscriptions,
            routes,
        }
    }

    /// The place of the Receive Location `name`: resolved once, as its
    /// serving thread starts.
    pub(super) fn place(&self, name: &str) -> Option<usize> {
        self.locations.iter().position(|(placed, _)| placed == name)
    }

    /// One Stream taken off the Receive Location at `place`, and `routed`
    /// along each Subscription its routing matched.
    pub(super) fn record(&self, place: usize, routed: Option<&Routing>) {
        let count = |counter: &AtomicU64| {
            counter.fetch_add(1, Ordering::Relaxed);
        };
        if let Some((_, at)) = self.locations.get(place) {
            count(at);
        }
        let Some(routing) = routed else {
            return;
        };
        let width = self.subscriptions.len();
        for evaluation in routing.evaluations.iter().filter(|one| one.matched()) {
            let Some(index) = self
                .subscriptions
                .iter()
                .position(|id| *id == evaluation.subscription_id)
            else {
                continue;
            };
            if let Some(route) = self.routes.get(place * width + index) {
                count(route);
            }
        }
    }

    /// What was counted: each Location's Streams, and each (Location,
    /// Subscription) that routed any, with how many.
    pub(super) fn counts(&self) -> PlacedCounts {
        let read = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        let locations = self
            .locations
            .iter()
            .map(|(name, at)| (name.clone(), read(at)))
            .collect();
        let width = self.subscriptions.len().max(1);
        let routes = self
            .routes
            .iter()
            .enumerate()
            .filter(|(_, route)| read(route) > 0)
            .filter_map(|(at, route)| {
                let (location, _) = self.locations.get(at / width)?;
                let subscription = self.subscriptions.get(at % width)?;
                Some((location.clone(), subscription.clone(), read(route)))
            })
            .collect();
        (locations, routes)
    }
}

#[cfg(test)]
mod tests {
    use path::expression::Expression;
    use route::{Promoted, Subscriber, Subscription, publish};

    use super::*;

    fn subscription(id: &str, filter: &str) -> Subscription {
        Subscription::new(
            id,
            Subscriber::SendPort(format!("{id} out")),
            Expression::parse(filter).expect("compiles"),
        )
    }

    #[test]
    fn a_stream_routed_at_the_second_location_by_the_third_subscription_counts_there_alone() {
        let names = |all: &[&str]| all.iter().map(ToString::to_string).collect::<Vec<_>>();
        let placed = Placed::of(
            names(&["first", "second"]),
            names(&["orders", "invoices", "dispatch advices"]),
        );
        let subscriptions = [
            subscription("orders", "kind = 'ORDERS'"),
            subscription("invoices", "kind = 'INVOIC'"),
            subscription("dispatch advices", "kind = 'DESADV'"),
        ];
        let routing = publish(&Promoted::new().set("kind", "DESADV"), &subscriptions);
        let place = placed.place("second").expect("placed");

        placed.record(place, Some(&routing));

        let (locations, routes) = placed.counts();
        assert_eq!(
            locations,
            [("first".to_string(), 0), ("second".to_string(), 1)]
        );
        assert_eq!(
            routes,
            [("second".to_string(), "dispatch advices".to_string(), 1)]
        );
    }

    #[test]
    fn a_subscription_is_found_by_its_id_whatever_order_routing_asked_in() {
        let placed = Placed::of(vec!["L".into()], vec!["A".into(), "B".into()]);
        // Routing asked B before A: the count still lands on B.
        let subscriptions = [subscription("B", "true"), subscription("A", "false")];
        let routing = publish(&Promoted::new(), &subscriptions);
        placed.record(0, Some(&routing));
        placed.record(0, None);
        let (locations, routes) = placed.counts();
        assert_eq!(locations, [("L".to_string(), 2)], "unrouted, still taken");
        assert_eq!(routes, [("L".to_string(), "B".to_string(), 1)]);
    }
}
