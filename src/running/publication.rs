//! What a running node says of itself: its snapshot — health, figures,
//! Subscriptions and the oldest of its Dead Message Queue — and its
//! publication, the snapshot with the node drawn as
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
//! <node>/send/<Location>     Done with the reason once it stopped
//! <node>/send/<Port>         each Send Port this node sends, apart from its
//!                            Send Locations: what it sent, what failed — the
//!                            last Journey that did, and why — what waits,
//!                            and how many failed wait in its queue
//! <node>/process/<name>      each Subscription: Fine, or Paused by whom
//! ```
//!
//! **The Journeys that failed** at each Send Port with any waiting in its
//! queue are published beside the records (`observe::FailedJourneys`):
//! how many, and the oldest hundred with why, so a surface offers Retry and
//! Dismiss on each at the Port's scope; the rest are read from Xmip Storage
//! a page at a time (`xmip_failed_journeys_v1`).
//!
//! **The figures** are what [`crate::outcome::Tally`] counted, at the stage
//! that counts each kind (`observe::Counted::at`): Streams received at
//! `receive`, Journeys opened at `process`, Messages sent at `send`, and at
//! the node what failed — refused at a gate, or a Journey written Failed.
//! At each Send Port, `send/<Port>`, what the send step counted there
//! (`crate::send_step::PortFigures`): Messages sent, Journeys failed, and
//! those retrying — waiting for their due time.
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
    Count, Counted, FailedJourney, FailedJourneys, Health, HealthRecord, PauseState, Publication,
    Snapshot, Topology, now_unix_nanos,
};

use std::collections::BTreeMap;

use super::Running;
use crate::capability_registry::Load;
use crate::pickup::PUBLISHED;
use crate::send_step::PortFigures;

/// The Party a node draws on each side while its configuration can name
/// none.
pub const ANY_PARTY: &str = "any-party";

/// The location of the node `node` of `cluster`: the scope it declares and
/// publishes beneath (ADR-0027 clause 4, ADR-0053).
pub(crate) fn location(cluster: &str, node: &str) -> String {
    format!("{}/node/{node}", cluster_location(cluster))
}

/// The location of the cluster `cluster`: `xmip:///<cluster>`.
pub fn cluster_location(cluster: &str) -> String {
    format!("xmip:///{cluster}")
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
        let figures = self.send.figures();
        for (scope, health, evidence) in stage_records(&node, &self.locations, &failures, &figures)
        {
            record(scope, health, evidence);
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
        // The oldest of its Dead Message Queue; one that cannot be read now
        // is published at the next look.
        if let Ok((_, dead)) = self.pickup.dead_messages(PUBLISHED) {
            for entry in dead {
                snapshot.record_dead_message(entry);
            }
        }
        for failed in failed_journeys(&node, &figures) {
            snapshot.record_failed_journeys(failed);
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

    /// The roles the node's configuration gives it — receiving where a
    /// Receive Location starts, processing where a Subscription routes,
    /// sending where a Send Port starts, executing where all three do — and
    /// whether its configuration says it is online (ADR-0045; ADR-0056,
    /// amendment 2026-10-01).
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
        Capability::serving(&stages).with_online(self.online)
    }

    /// What the tally counted, each kind at the stage that counts it, and
    /// what the send step counted at each Send Port: sent, failed, and
    /// waiting for a retry's due time.
    fn count(&self, snapshot: &mut Snapshot, node: &str, now: i64) {
        let outcomes = self.tally.outcomes();
        let at = |stage: Stage| format!("{node}/{}", stage.name());
        let mut counts = vec![
            (at(Stage::Receive), Counted::Streams, outcomes.received),
            (at(Stage::Process), Counted::Journeys, outcomes.routed),
            (at(Stage::Send), Counted::Messages, outcomes.sent),
            (
                node.to_string(),
                Counted::Failed,
                outcomes.refused + outcomes.failed + outcomes.not_sent,
            ),
        ];
        for (port, figures) in self.send.figures() {
            let scope = format!("{}/{port}", at(Stage::Send));
            counts.push((scope.clone(), Counted::Messages, figures.sent));
            counts.push((scope.clone(), Counted::Failed, figures.failed));
            counts.push((scope, Counted::Retrying, figures.waiting));
        }
        for (scope, counted, value) in counts {
            snapshot.record_count(Count {
                scope,
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

/// The record of each Location the node started, at
/// `<node>/<stage>/<Location>` — Fine while it serves, Done with why once
/// it stopped, as `failures` says — and of each Send Port it sends, at
/// `<node>/send/<Port>`, with what `figures` counted there. A Send Port is
/// named apart from its Send Locations, so its figures are published at its
/// own scope however many Locations it has; one that shares its name with
/// a Send Location adds to that Location's record. Until 2026-10-05 the
/// figures were looked up by each Send Location's name, so a Port of
/// several Locations had none published.
fn stage_records(
    node: &str,
    locations: &[(&'static str, configure::ConfiguredLocation)],
    failures: &[(String, String)],
    figures: &BTreeMap<String, PortFigures>,
) -> Vec<(String, Health, String)> {
    let mut records: Vec<(String, Health, String)> = locations
        .iter()
        .map(|(stage, location)| {
            let scope = format!("{node}/{stage}/{}", location.name);
            match failures.iter().find(|(name, _)| name == &location.name) {
                Some((_, why)) => (scope, Health::Done, why.clone()),
                None => (
                    scope,
                    Health::Fine,
                    format!("started; {} at {}", location.transport, location.address),
                ),
            }
        })
        .collect();
    for (port, sent) in figures {
        let scope = format!("{node}/{}/{port}", Stage::Send.name());
        match records.iter_mut().find(|(at, _, _)| *at == scope) {
            Some((_, Health::Fine, evidence)) => {
                evidence.push_str(&format!("; {}", sent.evidence()));
            }
            Some(_) => {}
            None => records.push((
                scope,
                Health::Fine,
                format!("Send Port; {}", sent.evidence()),
            )),
        }
    }
    records
}

/// The Journeys that failed at each Send Port of `figures` that has any
/// waiting in its queue: how many, and the oldest with why — what a surface
/// lists at `<node>/send/<Port>` with Retry and Dismiss on each.
fn failed_journeys(node: &str, figures: &BTreeMap<String, PortFigures>) -> Vec<FailedJourneys> {
    figures
        .iter()
        .filter(|(_, figures)| figures.failing > 0)
        .map(|(port, figures)| FailedJourneys {
            node: node.to_string(),
            send_port: port.clone(),
            count: figures.failing,
            journeys: figures
                .oldest_failing
                .iter()
                .map(|failed| FailedJourney {
                    journey: failed.journey.to_string(),
                    sequence: failed.place,
                    reason: failed.reason.clone(),
                })
                .collect(),
        })
        .collect()
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
    fn a_send_port_of_several_locations_publishes_its_figures_at_its_own_scope() {
        let cluster = configure::fixture::test_cluster();
        let node = cluster.node_scope(0);
        let location = |name: &str| configure::ConfiguredLocation {
            name: name.to_string(),
            start: true,
            transport: "file".to_string(),
            address: "out".to_string(),
            credentials: None,
            contract: None,
            settings: configure::LocationSettings::default(),
            contract_settings: configure::LocationSettings::default(),
            accept: configure::Accept::default(),
        };
        let locations = [("send", location("Primary")), ("send", location("Backup"))];
        let figures = BTreeMap::from([(
            "Out".to_string(),
            PortFigures {
                failed: 2,
                failing: 2,
                last_failure: Some(("j-2".to_string(), "refused".to_string())),
                ..PortFigures::default()
            },
        )]);

        let records = stage_records(&node, &locations, &[], &figures);

        let port = format!("{node}/send/Out");
        let (_, health, evidence) = records
            .iter()
            .find(|(scope, _, _)| *scope == port)
            .expect("the Port's own record");
        assert_eq!(*health, Health::Fine);
        assert!(evidence.contains("failed in its queue 2"), "{evidence}");
        assert!(
            evidence.contains("the Journey j-2 failed: refused"),
            "{evidence}"
        );
        assert_eq!(records.len(), 3, "each Location, and the Port");
    }

    #[test]
    fn a_node_is_located_beneath_its_cluster() {
        let cluster = configure::fixture::test_cluster();
        assert_eq!(
            location(&cluster.name, &cluster.node(0).name),
            cluster.node_scope(0)
        );
    }

    #[test]
    fn a_stopped_node_is_done_and_keeps_what_it_declared_and_its_pauses() {
        let cluster = configure::fixture::test_cluster();
        let (name, node) = (&cluster.name, &cluster.node(0).name);
        let at = cluster.node_scope(0);
        let at = at.as_str();
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

        let left = stopped(name, node, &last, "stopped by the console");
        let moods: Vec<(&str, Health)> = left
            .records
            .iter()
            .map(|record| (record.scope.as_str(), record.health))
            .collect();
        for (leaf, health) in [
            ("", Health::Done),
            ("/system-process", Health::Done),
            ("/receive/In", Health::Done),
            ("/capability", Health::Fine),
            ("/process/onward", Health::Paused),
        ] {
            let scope = format!("{at}{leaf}");
            assert!(
                moods.contains(&(scope.as_str(), health)),
                "{scope}: {moods:?}"
            );
        }
        let record = left.records.iter().find(|record| record.scope == at);
        assert_eq!(
            record.map(|record| record.evidence.as_str()),
            Some("stopped by the console")
        );
        assert_eq!(left.orders, "orders");
        let drawn = left.topology.expect("drawn again");
        let id = format!("node/{node}");
        assert!(drawn.nodes.iter().any(|drawn| drawn.id == id));
        assert!(
            (drawn.nodes[0].activity).abs() < f64::EPSILON,
            "no process alive"
        );
    }
}
