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
//!                            and how many failed wait in its queue: Done
//!                            while any does, Fine once none does
//! <node>/process/<name>      each Subscription: Fine, or Paused by whom
//! ```
//!
//! **The Journeys that failed** at every Send Port the node sends are
//! published beside the records (`observe::FailedJourneys`): how many wait
//! in its queue now — zero where none — whether they block its sequence,
//! and the oldest hundred with why, so a surface offers Retry and Dismiss
//! on each at the Port's scope; apart from them, the last that failed there
//! since the node started, as history. The rest are read from Xmip Storage
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
    Count, Counted, FailedJourneys, Health, HealthRecord, PauseState, Publication, Snapshot,
    Topology, now_unix_nanos,
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
                severity: severity(health),
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
        let staged = stage_records(&node, &self.locations, &failures, &figures);
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
        for (scope, (health, severity), evidence) in staged {
            snapshot.record_health(HealthRecord {
                scope,
                health,
                severity,
                evidence,
                observed_unix_nanos: now,
            });
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
///
/// **A Port with failed Journeys waiting in its queue now is Done** —
/// blocked or failed, the pain an operator's Retry or Dismiss solves — and
/// one whose sequence is blocked behind them the most severe; what failed
/// before and was acted on since is history in its figures and leaves it
/// Fine. Until 2026-10-06 a Port was Fine whatever waited in its queue, so
/// a surface's list of what needs attention left it out.
fn stage_records(
    node: &str,
    locations: &[(&'static str, configure::ConfiguredLocation)],
    failures: &[(String, String)],
    figures: &BTreeMap<String, PortFigures>,
) -> Vec<StageRecord> {
    let fine = (Health::Fine, severity(Health::Fine));
    let mut records: Vec<StageRecord> = locations
        .iter()
        .map(|(stage, location)| {
            let scope = format!("{node}/{stage}/{}", location.name);
            match failures.iter().find(|(name, _)| name == &location.name) {
                Some((_, why)) => (scope, (Health::Done, severity(Health::Done)), why.clone()),
                None => (
                    scope,
                    fine,
                    format!("started; {} at {}", location.transport, location.address),
                ),
            }
        })
        .collect();
    for (port, sent) in figures {
        let scope = format!("{node}/{}/{port}", Stage::Send.name());
        let mood = match (sent.failing, sent.blocked) {
            (0, _) => fine,
            (_, true) => (Health::Done, BLOCKED_SEVERITY),
            (_, false) => (Health::Done, severity(Health::Done)),
        };
        match records.iter_mut().find(|(at, _, _)| *at == scope) {
            Some((_, standing, evidence)) if *standing == fine => {
                *standing = mood;
                evidence.push_str(&format!("; {}", sent.evidence()));
            }
            Some(_) => {}
            None => records.push((scope, mood, format!("Send Port; {}", sent.evidence()))),
        }
    }
    records
}

/// The severity a record of `health` carries: none while Fine, a deliberate
/// hold's, and the pain's.
const fn severity(health: Health) -> u8 {
    match health {
        Health::Fine => 0,
        Health::Paused => 30,
        _ => 90,
    }
}

/// The severity of a Send Port whose sequence is blocked behind a Journey
/// that failed: above every other Done, since nothing more of that order
/// key goes until an operator acts.
const BLOCKED_SEVERITY: u8 = 95;

/// One stage record: its scope, its mood with its severity, its evidence.
type StageRecord = (String, (Health, u8), String);

/// The Journeys that failed at every Send Port of `figures`, each as
/// [`PortFigures::published`] says it — a Port with none now among them.
fn failed_journeys(node: &str, figures: &BTreeMap<String, PortFigures>) -> Vec<FailedJourneys> {
    let published = figures
        .iter()
        .map(|(port, figures)| figures.published(node, port));
    published.collect()
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

    fn configured(name: &str) -> configure::ConfiguredLocation {
        configure::ConfiguredLocation {
            name: name.to_string(),
            start: true,
            transport: "file".to_string(),
            address: "out".to_string(),
            credentials: None,
            contract: None,
            settings: configure::LocationSettings::default(),
            contract_settings: configure::LocationSettings::default(),
            accept: configure::Accept::default(),
        }
    }

    /// The mood and severity of the Port `Out`'s own record, figured
    /// `figures`, and its evidence.
    fn out_standing(figures: PortFigures) -> ((Health, u8), String) {
        let node = configure::fixture::test_cluster().node_scope(0);
        let figures = BTreeMap::from([("Out".to_string(), figures)]);
        let port = format!("{node}/send/Out");
        stage_records(&node, &[], &[], &figures)
            .into_iter()
            .find(|(scope, _, _)| *scope == port)
            .map(|(_, standing, evidence)| (standing, evidence))
            .expect("the Port's own record")
    }

    #[test]
    fn a_send_port_with_failed_journeys_waiting_now_is_done_and_blocked_the_worst() {
        let history = PortFigures {
            failed: 3,
            last_failure: Some(("j-1".to_string(), "refused".to_string())),
            ..PortFigures::default()
        };
        let (standing, evidence) = out_standing(history.clone());
        assert_eq!(standing, (Health::Fine, 0), "history alone: {evidence}");

        let failing = PortFigures {
            failing: 1,
            ..history.clone()
        };
        let (standing, _) = out_standing(failing);
        assert_eq!(standing, (Health::Done, 90), "waiting for an operator");

        let blocked = PortFigures {
            failing: 1,
            blocked: true,
            ..history
        };
        let (standing, evidence) = out_standing(blocked);
        assert_eq!(standing, (Health::Done, BLOCKED_SEVERITY));
        assert!(evidence.contains("blocked behind them"), "{evidence}");
        assert!(BLOCKED_SEVERITY > severity(Health::Done), "the worst first");
    }

    #[test]
    fn every_send_port_publishes_its_failed_journeys_now_apart_from_its_last() {
        let node = configure::fixture::test_cluster().node_scope(0);
        let figures = BTreeMap::from([(
            "Out".to_string(),
            PortFigures {
                failed: 1,
                last_failure: Some(("j-1".to_string(), "refused".to_string())),
                ..PortFigures::default()
            },
        )]);

        let published = failed_journeys(&node, &figures);

        assert_eq!(published.len(), 1, "none now is published too");
        let out = &published[0];
        assert_eq!((out.count, out.blocked), (0, false), "none now");
        assert!(out.journeys.is_empty());
        let last = out.last_failure.as_ref().expect("history kept apart");
        assert_eq!(
            (last.journey.as_str(), last.reason.as_str()),
            ("j-1", "refused")
        );
    }

    #[test]
    fn a_send_port_of_several_locations_publishes_its_figures_at_its_own_scope() {
        let cluster = configure::fixture::test_cluster();
        let node = cluster.node_scope(0);
        let locations = [
            ("send", configured("Primary")),
            ("send", configured("Backup")),
        ];
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
        let (_, standing, evidence) = records
            .iter()
            .find(|(scope, _, _)| *scope == port)
            .expect("the Port's own record");
        assert_eq!(standing.0, Health::Done, "two wait for an operator");
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
