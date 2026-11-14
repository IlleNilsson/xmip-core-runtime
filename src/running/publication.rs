//! What a running node says of itself: its snapshot — health, figures,
//! Subscriptions and the oldest of its Dead Message Queue — and its
//! publication, the snapshot with the node drawn as a topology, which the
//! program running it writes where a surface reads it
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
//! <node>/storage             its Storage: Fine, Working while a standby is
//!                            not ready yet, or Done where none answers
//! <node>/storage/<domain>    each database it keeps: its schema version
//! <node>/configuration       which slice it runs: Fine, or Stressed with
//!                            why its candidate was refused (`activation`)
//! <node>/membership          its membership: Working until its row is in
//!                            Xmip Storage, Stressed where its save is not
//!                            its peers' (`crate::membership`)
//! <node>/certificate/<use>  each certificate it presents: renewal due, Stressed
//! <node>/receive/<Location>  each Receive Location: Fine while it serves,
//! <node>/send/<Location>     Done with the reason once it stopped, and
//!                            Done saying `configure::NOT_STARTED` where its
//!                            configuration does not say `start = true`
//! <node>/send/<Port>         each Send Port this node sends, apart from its
//!                            Send Locations: what it sent, what failed — the
//!                            last Message that did, and why — what waits,
//!                            and how many failed wait in its queue: Done
//!                            while any does, Fine once none does
//! <node>/process/<name>      each Subscription: Fine, or Paused by whom
//! ```
//!
//! **The Messages that failed** at every Send Port the node sends are
//! published beside the records (`observe::FailedMessages`): how many wait
//! in its queue now — zero where none — whether they block its sequence,
//! and the oldest with why — `[tuning] failed_window` of them, a hundred
//! by default — so a surface offers Retry and Dismiss
//! on each at the Port's scope; apart from them, the last that failed there
//! since the node started, as history. The rest are read from Xmip Storage
//! a page at a time (`xmip_failed_messages_v1`).
//!
//! **The figures** are what [`crate::outcome::Tally`] counted, at the stage
//! that counts each kind (`observe::Counted::at`): Streams received at
//! `receive`, Journeys opened at `process`, Messages sent at `send`, and at
//! the node what failed — refused at a gate, or a Message written Failed.
//! At each Send Port, `send/<Port>`, what the send step counted there
//! (`crate::send_step::PortFigures`): Messages sent, Messages failed, and
//! those retrying; the stage and the node keep only what no Port counted.
//!
//! **The topology** is `observe::topology::draw`'s and `party`'s, the one
//! drawing every publisher calls: the cluster, the node — saying the roles
//! its configuration declares, what it is related, stands and is for by
//! (ADR-0052 and ADR-0056, amendments 2026-11-13) — its stages with an
//! endpoint per Location, and the Party on each side (ADR-0052, amendment
//! 2026-09-29). A node's configuration names its Parties (`[[parties]]`),
//! and a Receive Location the Parties it takes (`accept.party`), but its
//! publication does not yet say which a Location takes, so whoever its
//! Receive Locations accept and its Send Ports deliver to is drawn as the
//! one Party facing the node on each side, over every endpoint,
//! `observe::topology::party::facing`'s `TX-Party 1` and `RX-Party 1` (open
//! problem 33), each link saying the transport its Locations' addresses
//! chose, never a Location's name (ADR-0018, amendment 2026-11-11); a
//! cluster's drawing numbers them across its nodes. Its own publication
//! relates it to no other node: relations are the cluster's
//! (`observe::topology::relate`); a Storage node draws the traffic it
//! measured, named as the relation it crosses. What moved over it — each
//! link's rate, each drawn thing's activity — is stated by the window its
//! publisher keeps (`observe::topology::window`; ADR-0018, amendment
//! 2026-11-10); a stopped node is drawn still.

use node::{Capability, Stage};
use observe::topology::draw;
use observe::topology::window::Window;
use observe::{
    Count, FailedMessages, Health, HealthRecord, PauseState, Publication, Snapshot, now_unix_nanos,
};

use std::collections::BTreeMap;

use super::Running;

mod drawn;
mod stopped;

use crate::{capability_registry::Load, pickup::PUBLISHED, send_step::PortFigures};
use drawn::{Seen, counts, drawn};
pub use stopped::stopped;

/// The file a node's program writes its publication to, in the node's data
/// directory, where a surface reads it, and where `--activation` reads what
/// the node runs (`activation::activation`).
pub const SNAPSHOT: &str = "snapshot.xmip";

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
        self.storage.publish(&node, &mut record);
        if let Some(standing) = &self.standing {
            standing.publish(&node, &mut record);
        }
        if let Some(membership) = &self.membership {
            membership.followed().publish(&node, &mut record);
        }
        self.certificates.publish(&node, now, &mut record);
        let figures = self.send.figures();
        let staged = not_started_records(&node, &self.not_started)
            .into_iter()
            .chain(stage_records(&node, &self.locations, &failures, &figures));
        // Its Subscriptions: none where it routes by none
        // (`Pickup::routing_none`; ADR-0018, amendment 2026-11-11).
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
        // is published in the next publication.
        if let Ok((_, dead)) = self.pickup.dead_messages(PUBLISHED) {
            for entry in dead {
                snapshot.record_dead_message(entry);
            }
        }
        for failed in failed_messages(&node, &figures) {
            snapshot.record_failed_messages(failed);
        }
        self.count(&mut snapshot, &node, now);
        snapshot
    }

    /// The node's publication, as `source` publishes it: its
    /// [`Running::snapshot`] at its location, with the node drawn and what
    /// moved over it stated by `window`, the one its publisher keeps.
    #[must_use]
    pub fn publication(&self, source: &str, window: &mut Window) -> Publication {
        let snapshot = self.snapshot();
        let placed = self.tally.placed_counts();
        let peers = self.storage.peers();
        let copied = self.storage.followers();
        // Each Location by the endpoint it is drawn as — a Send Location
        // beneath its Port, as its Port — and the transport its address
        // chose: what its Party's link says it runs over.
        let transports: Vec<(String, String)> = self
            .locations
            .iter()
            .map(|(_, beneath, configured)| {
                let endpoint = beneath.split('/').next().unwrap_or(beneath);
                (endpoint.to_string(), configured.scheme())
            })
            .collect();
        let seen = Seen {
            placed: Some(&placed),
            peers: &peers,
            bound: &self.bound,
            copied: &copied,
            transports: &transports,
            roles: &self.roles,
        };
        let mut topology = drawn(&self.cluster, &self.node, &snapshot, seen);
        window.state(&mut topology, &snapshot);
        Publication::whole(source, &self.location(), &snapshot).with_topology(Some(topology))
    }

    /// The roles the node's configuration gives it — receiving where a
    /// Receive Location starts, processing where it routes, sending where a
    /// Send Port starts, executing where all three do — and whether its
    /// configuration says it is online (ADR-0045; ADR-0056, amendment
    /// 2026-10-01).
    fn declared(&self) -> Capability {
        let serves = |stage: Stage| self.locations.iter().any(|(at, ..)| *at == stage);
        let stages: Vec<Stage> = [
            (Stage::Receive, serves(Stage::Receive)),
            (Stage::Process, self.routes),
            (Stage::Send, serves(Stage::Send)),
        ]
        .into_iter()
        .filter_map(|(stage, served)| served.then_some(stage))
        .collect();
        Capability::serving(&stages).with_online(self.online)
    }

    /// What [`counts`] says the node counted, recorded at `now`.
    fn count(&self, snapshot: &mut Snapshot, node: &str, now: i64) {
        let figures = self.send.figures();
        let placed = self.tally.placed_counts();
        for (scope, counted, value) in counts(node, self.tally.outcomes(), figures, &placed) {
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
/// **A Port with failed Messages waiting in its queue now is Done** —
/// blocked or failed, the pain an operator's Retry or Dismiss solves — and
/// one whose sequence is blocked behind them the most severe; what failed
/// before and was acted on since is history in its figures and leaves it
/// Fine. Until 2026-10-06 a Port was Fine whatever waited in its queue, so
/// a surface's list of what needs attention left it out. **A Port with a
/// claim whose renewal Xmip Storage has not answered is Done** from the
/// first, its evidence naming Xmip Storage, how many and since when — the
/// owner, 2026-10-06: *Storage is not here is a flat-out error*. Its sends
/// go on only while each claim surely holds, a lease from its last
/// confirmation, and stop once it may not (`crate::send_step`); that window
/// bounds attempts and softens nothing. Until 2026-10-06 it was Stressed.
/// **A Port whose queue Xmip Storage does not answer a read of is Done**
/// too, its evidence saying since when and Xmip Storage's answer: what
/// waits in it cannot be found, so nothing says it is empty. Until
/// 2026-10-08 a failed read left such a Port Fine.
fn stage_records(
    node: &str,
    locations: &[(Stage, String, configure::ConfiguredLocation)],
    failures: &[(String, String)],
    figures: &BTreeMap<String, PortFigures>,
) -> Vec<StageRecord> {
    let fine = (Health::Fine, severity(Health::Fine));
    let mut records: Vec<StageRecord> = locations
        .iter()
        .map(|(stage, beneath, location)| {
            // A Send Location tried for a Port named apart from it is
            // beneath that Port (`ExecutionTree::beneath`).
            let scope = format!("{node}/{}/{beneath}", stage.name());
            match failures.iter().find(|(name, _)| name == &location.name) {
                Some((_, why)) => (scope, (Health::Done, severity(Health::Done)), why.clone()),
                None => (scope, fine, format!("started at {}", location.address)),
            }
        })
        .collect();
    for (port, sent) in figures {
        let scope = format!("{node}/{}/{port}", Stage::Send.name());
        let unread = sent.unread.is_some();
        let mood = match (sent.failing, sent.blocked, sent.unconfirmed) {
            (0, _, 0) if !unread => fine,
            (0, _, _) | (_, false, _) => (Health::Done, severity(Health::Done)),
            (_, true, _) => (Health::Done, BLOCKED_SEVERITY),
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

/// The record of each Location the node knows and did not start, at
/// `<node>/<stage>/<Location>`: Done, as a stopped one is, with no
/// severity, saying [`configure::NOT_STARTED`] (the owner, 2026-10-13).
fn not_started_records(node: &str, known: &[(&'static str, String)]) -> Vec<StageRecord> {
    let said = configure::NOT_STARTED.to_string();
    let record = |(stage, name): &(&str, String)| {
        (
            format!("{node}/{stage}/{name}"),
            (Health::Done, 0),
            said.clone(),
        )
    };
    known.iter().map(record).collect()
}

/// The severity a record of `health` carries: none while Fine, a start's
/// under way — a standby copying or catching up — a deliberate hold's, and
/// the pain's.
const fn severity(health: Health) -> u8 {
    match health {
        Health::Fine => 0,
        Health::Working => 20,
        Health::Paused => 30,
        _ => 90,
    }
}

/// The severity of a Send Port whose sequence is blocked behind a Message
/// that failed: above every other Done, since nothing more of that order
/// key goes until an operator acts.
const BLOCKED_SEVERITY: u8 = 95;

/// One stage record: its scope, its mood with its severity, its evidence.
type StageRecord = (String, (Health, u8), String);

/// The Messages that failed at every Send Port of `figures`, each as
/// [`PortFigures::published`] says it — a Port with none now among them.
fn failed_messages(node: &str, figures: &BTreeMap<String, PortFigures>) -> Vec<FailedMessages> {
    let published = figures
        .iter()
        .map(|(port, figures)| figures.published(node, port));
    published.collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outcome::Outcomes;
    use observe::topology::link_id;
    use observe::{Counted, FailedMessage, Relation, Topology};

    #[test]
    fn one_message_sent_through_a_send_port_measures_one_at_the_node() {
        let node = configure::fixture::test_cluster().node_scope(0);
        let outcomes = Outcomes {
            received: 1,
            routed: 1,
            sent: 1,
            not_sent: 1,
            ..Outcomes::default()
        };
        let figures = PortFigures {
            sent: 1,
            failed: 1,
            ..PortFigures::default()
        };
        let mut snapshot = Snapshot::new();
        for (scope, counted, value) in counts(
            &node,
            outcomes,
            [("Out".into(), figures)].into(),
            &Default::default(),
        ) {
            snapshot.record_count(Count {
                scope,
                counted,
                value,
                window_start_unix_nanos: 0,
                window_end_unix_nanos: 0,
                observed_unix_nanos: 0,
            });
        }
        for counted in [
            Counted::Streams,
            Counted::Journeys,
            Counted::Messages,
            Counted::Failed,
        ] {
            let measured = snapshot.measure(&node, counted).expect("counted");
            assert_eq!(measured.value, 1, "{counted:?} at the node");
        }
    }

    /// A Location started at `stage`, published beneath it by its name.
    fn at(stage: Stage, name: &str) -> (Stage, String, configure::ConfiguredLocation) {
        (stage, name.to_string(), configured(name))
    }

    fn configured(name: &str) -> configure::ConfiguredLocation {
        configure::ConfiguredLocation {
            name: name.to_string(),
            start: true,
            address: "out".to_string(),
            secret: None,
            contract: None,
            settings: configure::LocationSettings::default(),
            contract_settings: configure::LocationSettings::default(),
            accept: configure::Accept::default(),
            prepare: Vec::new(),
            transform: None,
            promote: None,
            demote: None,
            debatch: None,
            correlation: None,
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
    fn a_send_port_whose_queue_storage_does_not_read_is_done_with_since_and_why() {
        let unread = PortFigures {
            unread: Some((1_000_000_000, "not reached".to_string())),
            ..PortFigures::default()
        };
        let (standing, evidence) = out_standing(unread);
        assert_eq!(standing, (Health::Done, 90), "{evidence}");
        assert!(
            evidence.contains("has not answered a read of its queue since 1970-01-01T00:00:01"),
            "{evidence}"
        );
        assert!(evidence.contains("not reached"), "{evidence}");
    }

    #[test]
    fn a_send_port_with_failed_messages_waiting_now_is_done_and_blocked_the_worst() {
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
    fn a_send_port_whose_renewal_storage_does_not_answer_is_done_naming_storage_since_when() {
        let unconfirmed = PortFigures {
            unconfirmed: 2,
            unanswered_since: Some(1_800_000_000_000_000_000),
            lost: 1,
            ..PortFigures::default()
        };
        let (standing, evidence) = out_standing(unconfirmed.clone());
        assert_eq!(
            standing,
            (Health::Done, severity(Health::Done)),
            "a flat-out error"
        );
        assert!(
            evidence.contains("Xmip Storage has not answered the renewal of its claims 2"),
            "{evidence}"
        );
        assert!(
            evidence.contains("since 2027-01-15T08:00:00.000000000Z"),
            "{evidence}"
        );
        assert!(evidence.contains("lost to another holder 1"), "{evidence}");

        let blocked = PortFigures {
            failing: 1,
            blocked: true,
            ..unconfirmed
        };
        let (standing, _) = out_standing(blocked);
        assert_eq!(
            standing,
            (Health::Done, BLOCKED_SEVERITY),
            "the worst first"
        );

        let lost_before = PortFigures {
            lost: 1,
            ..PortFigures::default()
        };
        let (standing, _) = out_standing(lost_before);
        assert_eq!(standing.0, Health::Fine, "a loss is history");
    }

    #[test]
    fn every_send_port_publishes_its_failed_messages_now_apart_from_its_last() {
        let node = configure::fixture::test_cluster().node_scope(0);
        let figures = BTreeMap::from([(
            "Out".to_string(),
            PortFigures {
                failed: 1,
                last_failure: Some(("j-1".to_string(), "refused".to_string())),
                ..PortFigures::default()
            },
        )]);

        let published = failed_messages(&node, &figures);

        assert_eq!(published.len(), 1, "none now is published too");
        let out = &published[0];
        assert_eq!((out.count, out.blocked), (0, false), "none now");
        assert_eq!(out.messages, [] as [FailedMessage; 0]);
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
        let locations = [at(Stage::Send, "Primary"), at(Stage::Send, "Backup")];
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
            evidence.contains("the Message of the Journey j-2 failed: refused"),
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

    /// A Location the configuration does not say `true` to is published
    /// at its stage, saying so, apart from what started.
    #[test]
    fn a_location_not_started_is_published_saying_the_configuration_does_not_say_true() {
        let node = configure::fixture::test_cluster().node_scope(0);
        let locations = [at(Stage::Receive, "In")];
        let not_started = [("receive", "Off".to_string()), ("send", "Out".to_string())];

        let records = not_started_records(&node, &not_started)
            .into_iter()
            .chain(stage_records(&node, &locations, &[], &BTreeMap::new()))
            .collect::<Vec<_>>();

        for (scope, ended) in [
            ("receive/Off", true),
            ("send/Out", true),
            ("receive/In", false),
        ] {
            let scope = format!("{node}/{scope}");
            let (_, standing, evidence) = records
                .iter()
                .find(|(at, _, _)| *at == scope)
                .expect("published");
            assert_eq!(
                evidence == configure::NOT_STARTED,
                ended,
                "{scope}: {evidence}"
            );
            assert_eq!(standing.0 == Health::Done, ended, "{scope}");
        }
    }

    /// What the node counted at `second`, receiving over `In` and sending
    /// through the Port `Out`, drawn as it publishes itself: `received`
    /// Streams routed, and `sent` Messages.
    fn drawn_at(second: i64, received: u64, sent: u64) -> (Topology, Snapshot) {
        let cluster = configure::fixture::test_cluster();
        let (name, node) = (&cluster.node(0).name, cluster.node_scope(0));
        let locations = [at(Stage::Receive, "In"), at(Stage::Send, "Out")];
        let mut snapshot = Snapshot::new();
        for (scope, (health, severity), evidence) in
            stage_records(&node, &locations, &[], &BTreeMap::new())
        {
            snapshot.record_health(HealthRecord {
                scope,
                health,
                severity,
                evidence,
                observed_unix_nanos: 0,
            });
        }
        let outcomes = Outcomes {
            received,
            routed: received,
            ..Outcomes::default()
        };
        let figures = PortFigures {
            sent,
            ..PortFigures::default()
        };
        for (scope, counted, value) in counts(
            &node,
            outcomes,
            [("Out".into(), figures)].into(),
            &Default::default(),
        ) {
            snapshot.record_count(Count {
                scope,
                counted,
                value,
                window_start_unix_nanos: 0,
                window_end_unix_nanos: 0,
                observed_unix_nanos: 0,
            });
        }
        let mut topology = drawn(&cluster.name, name, &snapshot, Seen::default());
        topology.observed_unix_nanos = second * 1_000_000_000;
        (topology, snapshot)
    }

    /// The owner, 2026-11-10: motion follows traffic. What the node counted
    /// moves its own drawing, stated by the window its publisher keeps: the
    /// Party sending in at what it received, the one delivered to at what
    /// the Port sent; drawn without one, nothing moves. That
    /// `Running::publication` states it through the window is held by the
    /// running tests (`tests/running`), over a node started as a program
    /// starts it.
    #[test]
    fn what_the_node_counted_moves_its_drawing_over_the_window_its_publisher_keeps() {
        let name = configure::fixture::test_cluster().node(0).name.clone();
        let mut window = Window::new();
        let (mut first, snapshot) = drawn_at(0, 0, 0);
        window.state(&mut first, &snapshot);
        let (mut later, snapshot) = drawn_at(2, 8, 4);
        let still = later.clone();
        window.state(&mut later, &snapshot);

        let rate = |topology: &Topology, id: &str| {
            topology
                .links
                .iter()
                .find(|link| link.id == id)
                .map(|link| link.rate)
        };
        let activity = |topology: &Topology, id: &str| {
            topology
                .nodes
                .iter()
                .find(|node| node.id == id)
                .map(|node| node.activity)
        };
        let (node, receive, send) = (
            format!("node/{name}"),
            format!("node/{name}/receive"),
            format!("node/{name}/send"),
        );
        let into = link_id(
            &format!("party/sending/{node}"),
            &receive,
            Relation::Traffic,
        );
        let out = link_id(&send, &format!("party/receiving/{node}"), Relation::Traffic);
        assert_eq!(
            rate(&later, &into),
            Some(4.0),
            "eight received in two seconds"
        );
        assert_eq!(rate(&later, &out), Some(2.0), "four sent through Out");
        assert_eq!(activity(&later, &format!("node/{name}")), Some(4.0));
        assert_eq!(rate(&still, &into), Some(0.0), "drawn, not yet stated");
        assert!(
            still
                .nodes
                .iter()
                .all(|node| node.activity.abs() < f64::EPSILON),
            "{:?}",
            still.nodes
        );
    }
}
