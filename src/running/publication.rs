//! What a running node says of itself: its snapshot — health, figures and
//! Subscriptions — and its publication, the snapshot with the node drawn as
//! a topology, which the program running it writes where a surface reads it
//! (`observe::Publication::write`; ADR-0018, amendment 2026-09-30).
//!
//! **Where each record sits**, beneath the node's location
//! `xmip:///<cluster>/node/<name>`:
//!
//! ```text
//! <node>                     running: what it loaded and started
//! <node>/system-process      alive, and the process it runs in (ADR-0053)
//! <node>/capability          the stages it declares (ADR-0056)
//! <node>/module/<module>     each capability loaded, and how
//! <node>/receive/<Location>  each Receive Location: Fine while it serves,
//! <node>/send/<Port>         Done with the reason once it stopped
//! <node>/process/<name>      each Subscription: Fine, or Paused by whom
//! ```
//!
//! **The figures** are what [`crate::outcome::Tally`] counted, at the stage
//! that counts each kind (`observe::Counted::at`): Streams received at
//! `receive`, Journeys opened at `process`, Messages sent at `send`, and at
//! the node what failed — refused at a gate, or a departure that did not
//! leave.
//!
//! **The topology** is `observe::topology::draw`'s and `party`'s, the one
//! drawing every publisher calls: the cluster, the node, its stages with an
//! endpoint per Location, and the Party on each side (ADR-0052, amendment
//! 2026-09-29). A node's configuration names no Party yet (`configure`'s
//! `Accept` refuses a `party` list), so whoever its Receive Locations accept
//! and its Send Ports deliver to is drawn as one Party per side,
//! [`ANY_PARTY`].

use node::{Capability, Stage};
use observe::topology::{draw, party};
use observe::{
    Count, Counted, Health, HealthRecord, PauseState, Publication, Snapshot, Topology,
    now_unix_nanos,
};

use super::Running;
use crate::capability_registry::Load;

/// The Party a node draws on each side while its configuration can name
/// none.
pub const ANY_PARTY: &str = "any-party";

/// The location of the node `node` of `cluster`: the scope it declares and
/// publishes beneath (ADR-0027 clause 4, ADR-0053).
pub(crate) fn location(cluster: &str, node: &str) -> String {
    format!("xmip:///{cluster}/node/{node}")
}

impl Running {
    /// The node's location, `xmip:///<cluster>/node/<name>`.
    #[must_use]
    pub fn location(&self) -> String {
        location(&self.cluster, &self.node)
    }

    /// What the node says of itself now: itself, the process it runs in,
    /// what it declares, each capability loaded, each Location with what it
    /// is doing, each Subscription with its standing, and what it counted.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        let now = now_unix_nanos();
        let node = self.location();
        let failures = self.tally.failures();
        let mut snapshot = Snapshot::new();
        let mut record = |scope: String, health: Health, evidence: String| {
            snapshot.record_health(HealthRecord {
                scope,
                health,
                severity: match health {
                    Health::Fine => 0,
                    Health::Paused => 30,
                    _ => 90,
                },
                evidence,
                observed_unix_nanos: now,
            });
        };

        record(
            node.clone(),
            Health::Fine,
            format!(
                "running: {} capability(ies) loaded, {} Location(s) started",
                self.capabilities.capabilities().count(),
                self.locations.len()
            ),
        );
        record(
            draw::system_process(&node),
            Health::Fine,
            format!("{}: process {}", draw::ALIVE, std::process::id()),
        );
        record(
            observe::capability::scope(&node),
            Health::Fine,
            self.declared().evidence(),
        );
        for capability in self.capabilities.capabilities() {
            let how = match &capability.load {
                Load::Linked => "linked".to_string(),
                Load::Library(path) => format!("from {}", path.display()),
            };
            record(
                format!("{node}/module/{}", capability.module),
                Health::Fine,
                format!("loaded ({how}), serving {}", capability.capability),
            );
        }
        for (stage, location) in &self.locations {
            let scope = format!("{node}/{stage}/{}", location.name);
            match failures.iter().find(|(name, _)| name == &location.name) {
                Some((_, why)) => record(scope, Health::Done, why.clone()),
                None => record(
                    scope,
                    Health::Fine,
                    format!("started; {} at {}", location.transport, location.address),
                ),
            }
        }
        let subscriptions = self.pickup.standing();
        for subscription in &subscriptions {
            let scope = format!("{node}/{}/{}", Stage::Process.name(), subscription.name);
            match subscription.state {
                PauseState::Paused => record(
                    scope,
                    Health::Paused,
                    format!(
                        "paused by {}; holds {} Message(s)",
                        subscription.by, subscription.held
                    ),
                ),
                PauseState::Active => record(
                    scope,
                    Health::Fine,
                    format!("active; picked up {}", subscription.picked_up),
                ),
            }
        }
        for subscription in subscriptions {
            snapshot.record_subscription(subscription);
        }
        self.count(&mut snapshot, &node, now);
        snapshot
    }

    /// The node's publication, as `source` publishes it: its
    /// [`Running::snapshot`] at its location, with the node drawn.
    #[must_use]
    pub fn publication(&self, source: &str) -> Publication {
        let snapshot = self.snapshot();
        let topology = self.topology(&snapshot);
        Publication::whole(source, &self.location(), &snapshot).with_topology(Some(topology))
    }

    /// The stages the node serves — receive where a Receive Location starts,
    /// process where a Subscription routes, send where a Send Port starts —
    /// and whether its configuration says it is online (ADR-0045).
    fn declared(&self) -> Capability {
        let serves = |stage: &str| self.locations.iter().any(|(at, _)| *at == stage);
        let stages: Vec<Stage> = [
            (Stage::Receive, serves(Stage::Receive.name())),
            (Stage::Process, !self.pickup.standing().is_empty()),
            (Stage::Send, serves(Stage::Send.name())),
        ]
        .into_iter()
        .filter_map(|(stage, served)| served.then_some(stage))
        .collect();
        Capability::of(&stages).with_online(self.online)
    }

    /// What the tally counted, each kind at the stage that counts it.
    fn count(&self, snapshot: &mut Snapshot, node: &str, now: i64) {
        let outcomes = self.tally.outcomes();
        for (scope, counted, value) in [
            (Some(Stage::Receive), Counted::Streams, outcomes.received),
            (Some(Stage::Process), Counted::Journeys, outcomes.routed),
            (Some(Stage::Send), Counted::Messages, outcomes.sent),
            (None, Counted::Failed, outcomes.refused + outcomes.not_sent),
        ] {
            snapshot.record_count(Count {
                scope: scope.map_or_else(|| node.to_string(), |at| format!("{node}/{}", at.name())),
                counted,
                value,
                window_start_unix_nanos: now,
                window_end_unix_nanos: now,
                observed_unix_nanos: now,
            });
        }
    }

    /// The node drawn from `snapshot`.
    fn topology(&self, snapshot: &Snapshot) -> Topology {
        drawn(&self.cluster, &self.node, snapshot)
    }
}

/// The node `node` of `cluster` drawn from `snapshot`: its cluster, itself,
/// its stages and their endpoints, and [`ANY_PARTY`] on each side a stage
/// faces.
fn drawn(cluster: &str, node: &str, snapshot: &Snapshot) -> Topology {
    let root = format!("xmip:///{cluster}");
    let names = [node];
    let mut topology = Topology {
        source: format!("{root} — node {node}"),
        observed_unix_nanos: now_unix_nanos(),
        nodes: draw::members(snapshot, &root, &names),
        links: Vec::new(),
    };
    party::draw(snapshot, &root, &names, ANY_PARTY, &mut topology);
    topology
}

/// What the node `node` of `cluster` leaves published once it has stopped:
/// `last`, its last publication while it ran, with the node, its System
/// Process, its modules and its Locations Done — the node saying `said`,
/// the rest that they stopped with it — and drawn again. What it declared
/// and its Subscriptions' standing stay as they were: a pause outlives the
/// stop (ADR-0013, amendment 2026-09-30). A surface over the file shows a
/// stopped node, never a running one that went quiet.
#[must_use]
pub fn stopped(cluster: &str, node: &str, last: &Publication, said: &str) -> Publication {
    let at = location(cluster, node);
    let kept = [
        observe::capability::scope(&at),
        format!("{at}/{}/", Stage::Process.name()),
    ];
    let now = now_unix_nanos();
    let mut snapshot = last.snapshot();
    for record in &last.records {
        if kept
            .iter()
            .any(|kept| record.scope.starts_with(kept.as_str()))
        {
            continue;
        }
        let evidence = if record.scope == at {
            said.to_string()
        } else {
            "stopped with the node".to_string()
        };
        snapshot.record_health(HealthRecord {
            scope: record.scope.clone(),
            health: Health::Done,
            severity: 0,
            evidence,
            observed_unix_nanos: now,
        });
    }
    let topology = drawn(cluster, node, &snapshot);
    Publication::whole(&last.source, &last.node, &snapshot)
        .with_orders(last.orders.clone())
        .with_topology(Some(topology))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(scope: &str, health: Health) -> HealthRecord {
        HealthRecord {
            scope: scope.to_string(),
            health,
            severity: 0,
            evidence: "said".to_string(),
            observed_unix_nanos: 1,
        }
    }

    #[test]
    fn a_node_is_located_beneath_its_cluster() {
        assert_eq!(location("C1", "R1"), "xmip:///C1/node/R1");
    }

    #[test]
    fn a_stopped_node_is_done_and_keeps_what_it_declared_and_its_pauses() {
        let at = "xmip:///C1/node/R1";
        let mut snapshot = Snapshot::new();
        for (leaf, health) in [
            ("", Health::Fine),
            ("/system-process", Health::Fine),
            ("/capability", Health::Fine),
            ("/receive/In", Health::Fine),
            ("/process/onward", Health::Paused),
        ] {
            snapshot.record_health(record(&format!("{at}{leaf}"), health));
        }
        let last = Publication::whole("xmip-service", at, &snapshot).with_orders("orders");

        let left = stopped("C1", "R1", &last, "stopped by the console");
        let moods: Vec<(&str, Health)> = left
            .records
            .iter()
            .map(|record| (record.scope.as_str(), record.health))
            .collect();
        for (scope, health) in [
            (at, Health::Done),
            ("xmip:///C1/node/R1/system-process", Health::Done),
            ("xmip:///C1/node/R1/receive/In", Health::Done),
            ("xmip:///C1/node/R1/capability", Health::Fine),
            ("xmip:///C1/node/R1/process/onward", Health::Paused),
        ] {
            assert!(moods.contains(&(scope, health)), "{scope}: {moods:?}");
        }
        let node = left.records.iter().find(|record| record.scope == at);
        assert_eq!(
            node.map(|record| record.evidence.as_str()),
            Some("stopped by the console")
        );
        assert_eq!(left.orders, "orders");
        let drawn = left.topology.expect("drawn again");
        assert!(drawn.nodes.iter().any(|node| node.id == "node/R1"));
        assert!(
            (drawn.nodes[0].activity).abs() < f64::EPSILON,
            "no process alive"
        );
    }
}
