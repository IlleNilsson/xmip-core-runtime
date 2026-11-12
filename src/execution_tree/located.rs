//! Where a Location the tree knows is published beneath its node's stage,
//! and which it knows and does not start.

use node::Stage;

use super::ExecutionTree;

impl ExecutionTree {
    /// Each Location the node knows and does not start, by the stage it
    /// would serve — `receive` or `send` — and where it is published
    /// beneath that stage ([`ExecutionTree::beneath`]).
    #[must_use]
    pub fn not_started(&self) -> Vec<(&'static str, String)> {
        let at = |stage: Stage, names: &[String]| {
            names
                .iter()
                .map(move |name| (stage.name(), self.beneath(stage, name)))
                .collect::<Vec<_>>()
        };
        let mut known = at(Stage::Receive, &self.receive_locations_not_started);
        known.extend(at(Stage::Send, &self.send_locations_not_started));
        known
    }

    /// Where the Location `name` of `stage` is published beneath its
    /// node's stage: a Send Location tried for a Send Port named apart from
    /// it beneath that Port, `<Port>/<Location>`, so the send stage's
    /// children are its Send Ports, as a Subscription routes to a Send Port
    /// and never to a Send Location (ADR-0027, amendment 2026-11-11); every
    /// other Location, and one a Port shares its name with, by its name.
    #[must_use]
    pub fn beneath(&self, stage: Stage, name: &str) -> String {
        let port = (stage == Stage::Send)
            .then(|| {
                self.designed_send_ports.iter().find(|port| {
                    port.name != name && port.send_locations.iter().any(|one| one == name)
                })
            })
            .flatten();
        port.map_or_else(|| name.to_string(), |port| format!("{}/{name}", port.name))
    }
}
