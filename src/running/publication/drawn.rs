//! A running node drawn, and what it counted, each at the scope that counts
//! it: the drawing and the figures its publication carries (ADR-0018,
//! amendments 2026-09-30 and 2026-11-11).
//!
//! **Inside the node**, each Receive Location is linked to each Subscription
//! it routed by, carrying the Streams routed along it, so a person sees
//! which Location feeds which Subscription and how much (the owner,
//! 2026-11-10: *from and to in every observation*). **Outside it**, the
//! Parties (`party::ANY_PARTY` while a publication cannot say which a Location
//! takes; open problem 33), each link saying the transport its Locations'
//! addresses chose. **Between nodes**, where it serves Xmip Storage, what
//! each node the cluster's bindings name wrote into it and took from it;
//! and, while it is the primary of several, what it copies to each standby
//! (ADR-0052 and ADR-0056, amendments 2026-11-13).

use std::collections::BTreeMap;

use node::Stage;
use observe::topology::draw::node_id;
use observe::topology::{XMIP_STORAGE, draw, party};
use observe::{Counted, Health, Origin, Pattern, Snapshot, Topology, TopologyLink, now_unix_nanos};
use persist::storage::standby::Follower;

use crate::outcome::Outcomes;
use crate::send_step::PortFigures;

pub(super) use crate::outcome::PlacedCounts as Placed;

/// A node that called the Storage node this node serves, with the
/// Publications it wrote and the Journeys it took on (`storage::Reached::peers`).
pub(super) type Peered = (String, u64, u64);

/// The relation a primary's link to each of its standbys says it is.
const COPIES_TO: &str = "copies to";

/// What a node's drawing is drawn from beside its snapshot: what it counted
/// at each Receive Location and along each Subscription, the nodes that
/// crossed the Storage node it serves, the nodes the cluster's bindings
/// name, each standby that Storage node hands its writes to while it is
/// the primary (`storage::Reached::followers`), and the transport each of
/// its Locations is reached over, by the endpoint it is drawn as.
#[derive(Clone, Copy, Default)]
pub(super) struct Seen<'a> {
    pub(super) placed: Option<&'a Placed>,
    pub(super) peers: &'a [Peered],
    pub(super) bound: &'a [String],
    pub(super) copied: &'a [Follower],
    pub(super) transports: &'a [(String, String)],
}

/// The node `node` of `cluster` drawn from `snapshot`: its cluster, itself,
/// its stages and their endpoints, each Receive Location linked to the
/// Subscriptions it routed by as `seen` counted, the traffic between nodes
/// its Storage node measured and what it copies to each standby, and
/// `party::ANY_PARTY` on each side a stage faces, over the transports its
/// Locations are reached over.
pub(super) fn drawn(cluster: &str, node: &str, snapshot: &Snapshot, seen: Seen<'_>) -> Topology {
    let root = format!("xmip:///{cluster}");
    let names = [node];
    let mut topology = Topology {
        source: format!("{root} — node {node}"),
        observed_unix_nanos: now_unix_nanos(),
        nodes: draw::members(snapshot, &root, &names),
        links: Vec::new(),
    };
    if let Some((_, routed)) = seen.placed {
        topology.links.extend(routes(&topology, node, routed));
    }
    topology.links.extend(crossed(node, seen.peers, seen.bound));
    topology.links.extend(copied(node, seen.copied));
    let parties = [party::Party::over_locations(
        party::ANY_PARTY,
        seen.transports,
    )];
    party::draw(snapshot, &root, &names, &parties, &mut topology);
    topology
}

/// A link from each Receive Location drawn to each Subscription drawn that
/// it routed by, carrying the Streams routed along it: publish → consume,
/// configured and observed. A Stream a Send Port Group's Subscription
/// routed counts once here, however many Journeys it opened.
fn routes(topology: &Topology, node: &str, routed: &[(String, String, u64)]) -> Vec<TopologyLink> {
    let at = |stage: Stage, name: &str| format!("{}/{}/{name}", node_id(node), stage.name());
    let drawn = |id: &str| topology.nodes.iter().any(|one| one.id == id);
    routed
        .iter()
        .map(|(location, subscription, volume)| {
            (
                at(Stage::Receive, location),
                at(Stage::Process, subscription),
                location,
                subscription,
                *volume,
            )
        })
        .filter(|(from, to, ..)| drawn(from) && drawn(to))
        .map(|(from, to, location, subscription, volume)| TopologyLink {
            id: format!("{from}→{to}"),
            from,
            to,
            pattern: Pattern::PublishConsume,
            origin: Origin::Both,
            protocol: String::new(),
            state: Health::Fine,
            volume,
            rate: 0.0,
            latency_ms: 0.0,
            progress: 0.0,
            attempts: 0,
            evidence: format!("from {location} → to {subscription}: {volume} routed"),
        })
        .collect()
}

/// The traffic between nodes, measured where it passes: from each node
/// that wrote a Publication into the Storage node this node serves, and to
/// each that took a Journey on from it, publish → consume over Xmip
/// Storage, carrying what it counted (ADR-0052, amendment 2026-11-11). Only
/// a node of `bound`, one the cluster's bindings place a Location on, is
/// drawn: a certificate of node standing naming any other — one an
/// authority another cluster shares issued, a host name from an outside
/// authority — draws nothing. A direction nothing crossed is not drawn.
fn crossed(node: &str, peers: &[Peered], bound: &[String]) -> Vec<TopologyLink> {
    let here = node_id(node);
    let link = |(from, to): (String, String), volume: u64, what: &str| TopologyLink {
        id: format!("{from}→{to}"),
        evidence: format!("{volume} {what} over {XMIP_STORAGE}"),
        from,
        to,
        pattern: Pattern::PublishConsume,
        origin: Origin::Observed,
        protocol: XMIP_STORAGE.to_string(),
        state: Health::Fine,
        volume,
        rate: 0.0,
        latency_ms: 0.0,
        progress: 0.0,
        attempts: 0,
    };
    let configured = |peer: &String| peer != node && bound.contains(peer);
    let mut links = Vec::new();
    for (peer, published, taken) in peers.iter().filter(|(peer, ..)| configured(peer)) {
        let there = node_id(peer);
        if *published > 0 {
            links.push(link(
                (there.clone(), here.clone()),
                *published,
                "Publication(s) written",
            ));
        }
        if *taken > 0 {
            links.push(link((here.clone(), there), *taken, "Journey(s) taken on"));
        }
    }
    links
}

/// What the Storage node this node serves, the primary, copies to each
/// standby it hands its writes to (ADR-0052 and ADR-0056, amendments
/// 2026-11-13): a link `node/<self> → node/<standby>`, the relation *copies
/// to*, streaming over Xmip Storage, observed, its volume what was copied —
/// each write, and each entry of a whole copy — so the window states the rate
/// it copies at, and its evidence the writes, the entries copied whole, the
/// bytes and how far behind the standby is. The standby is the node its
/// certificate names, the one the primary measured, never where it
/// connected from; one whose certificate names no node, or this node, draws
/// nothing, and a standby not following now is not handed in.
fn copied(node: &str, followers: &[Follower]) -> Vec<TopologyLink> {
    let here = node_id(node);
    followers
        .iter()
        .filter_map(|follower| {
            let standby = follower
                .node
                .as_deref()
                .filter(|standby| *standby != node)?;
            let there = node_id(standby);
            let whole = match follower.entries {
                0 => String::new(),
                entries => format!(", {entries} entries copied whole"),
            };
            Some(TopologyLink {
                id: format!("{here}→{there} {COPIES_TO}"),
                evidence: format!(
                    "{COPIES_TO}: {} write(s) copied{whole}, {}; {} write(s) behind; \
                     the standby connected from {}",
                    follower.writes,
                    size(follower.bytes),
                    follower.behind,
                    follower.address
                ),
                from: here.clone(),
                to: there,
                pattern: Pattern::Streaming,
                origin: Origin::Observed,
                protocol: XMIP_STORAGE.to_string(),
                state: Health::Fine,
                volume: follower.writes.saturating_add(follower.entries),
                rate: 0.0,
                latency_ms: 0.0,
                progress: 0.0,
                attempts: 0,
            })
        })
        .collect()
}

/// `bytes` as a person reads a size: whole MiB from one up, KiB below.
fn size(bytes: u64) -> String {
    const MIB: u64 = 1024 * 1024;
    if bytes >= MIB {
        format!("{} MiB", bytes / MIB)
    } else {
        format!("{} KiB", bytes.div_ceil(1024))
    }
}

/// What the tally counted, each kind at the scope that counts it: Streams
/// at each Receive Location, Journeys at each Subscription, Messages,
/// failures and retries at each Send Port, and at each stage and the node
/// only what none of those counted, since a scope's measure is the sum of
/// every count within it: one file sent is one Message, never two.
pub(super) fn counts(
    node: &str,
    outcomes: Outcomes,
    ports: BTreeMap<String, PortFigures>,
    (locations, opened): &Placed,
) -> Vec<(String, Counted, u64)> {
    let sent = outcomes
        .sent
        .saturating_sub(ports.values().map(|port| port.sent).sum());
    let failed = (outcomes.refused + outcomes.failed + outcomes.not_sent)
        .saturating_sub(ports.values().map(|port| port.failed).sum());
    let mut journeys: BTreeMap<&str, u64> = BTreeMap::new();
    for (_, subscription, routed) in opened {
        *journeys.entry(subscription.as_str()).or_default() += routed;
    }
    let received = outcomes
        .received
        .saturating_sub(locations.iter().map(|(_, taken)| taken).sum());
    let unplaced = outcomes.routed.saturating_sub(journeys.values().sum());
    let at = |stage: Stage| format!("{node}/{}", stage.name());
    let mut counts = vec![
        (at(Stage::Receive), Counted::Streams, received),
        (at(Stage::Process), Counted::Journeys, unplaced),
        (at(Stage::Send), Counted::Messages, sent),
        (node.to_string(), Counted::Failed, failed),
    ];
    for (location, taken) in locations {
        let scope = format!("{}/{location}", at(Stage::Receive));
        counts.push((scope, Counted::Streams, *taken));
    }
    for (subscription, routed) in journeys {
        let scope = format!("{}/{subscription}", at(Stage::Process));
        counts.push((scope, Counted::Journeys, routed));
    }
    for (port, figures) in ports {
        let scope = format!("{}/{port}", at(Stage::Send));
        counts.push((scope.clone(), Counted::Messages, figures.sent));
        counts.push((scope.clone(), Counted::Failed, figures.failed));
        counts.push((scope, Counted::Retrying, figures.waiting));
    }
    counts
}

#[cfg(test)]
mod tests {
    use super::*;
    use observe::Count;

    fn measured(placed: &Placed, outcomes: Outcomes) -> Snapshot {
        let node = configure::fixture::test_cluster().node_scope(0);
        let mut snapshot = Snapshot::new();
        for (scope, counted, value) in counts(&node, outcomes, BTreeMap::new(), placed) {
            snapshot.record_count(Count {
                scope,
                counted,
                value,
                window_start_unix_nanos: 0,
                window_end_unix_nanos: 0,
                observed_unix_nanos: 0,
            });
        }
        snapshot
    }

    #[test]
    fn a_stream_received_at_a_location_measures_one_at_the_stage_never_two() {
        let node = configure::fixture::test_cluster().node_scope(0);
        let placed: Placed = (
            vec![("Sales orders from Party-A".into(), 1)],
            vec![("Sales orders from Party-A".into(), "Sales orders".into(), 1)],
        );
        let outcomes = Outcomes {
            received: 1,
            routed: 1,
            ..Outcomes::default()
        };
        let snapshot = measured(&placed, outcomes);
        let value = |scope: &str, counted| {
            snapshot
                .measure(scope, counted)
                .map_or(0, |count| count.value)
        };
        assert_eq!(value(&format!("{node}/receive"), Counted::Streams), 1);
        assert_eq!(
            value(
                &format!("{node}/receive/Sales orders from Party-A"),
                Counted::Streams
            ),
            1
        );
        assert_eq!(value(&format!("{node}/process"), Counted::Journeys), 1);
        assert_eq!(
            value(&format!("{node}/process/Sales orders"), Counted::Journeys),
            1
        );
    }

    #[test]
    fn a_storage_node_draws_the_traffic_from_and_to_each_node_the_cluster_binds() {
        let test = configure::fixture::test_cluster();
        let [storing, writing, taking, idle] = [0, 1, 2, 3].map(|at| test.node(at).name.clone());
        // A certificate of node standing the cluster does not configure: an
        // authority shared with another cluster, an outside one's host name.
        let outsider = "edge.elsewhere.example".to_string();
        let peers: Vec<Peered> = vec![
            (writing.clone(), 4, 0),
            (taking.clone(), 0, 3),
            (idle.clone(), 0, 0),
            (storing.clone(), 9, 9),
            (outsider, 5, 5),
        ];
        let bound = [writing.clone(), taking.clone(), idle, storing.clone()];
        let links = crossed(&storing, &peers, &bound);
        let drawn: Vec<(String, String, u64)> = links
            .iter()
            .map(|link| (link.from.clone(), link.to.clone(), link.volume))
            .collect();
        let id = |name: &str| format!("node/{name}");
        assert_eq!(
            drawn,
            [
                (id(&writing), id(&storing), 4),
                (id(&storing), id(&taking), 3)
            ],
            "nothing crossed, nothing drawn; never itself, never a node the cluster does not bind"
        );
        assert!(links.iter().all(|link| link.protocol == XMIP_STORAGE));
        assert!(
            crossed(&storing, &peers, &[]).is_empty(),
            "a cluster that binds none draws none"
        );
    }

    /// A standby `standby` of the primary, having been handed `writes`.
    fn follower(standby: Option<&str>, writes: u64) -> Follower {
        Follower {
            node: standby.map(str::to_string),
            address: "127.0.0.1:50000".into(),
            writes,
            entries: 300,
            bytes: 2 * 1024 * 1024 + 7,
            behind: 3,
        }
    }

    #[test]
    fn a_primary_draws_what_it_copies_to_each_standby_by_its_node_moving_at_its_rate() {
        let test = configure::fixture::test_cluster();
        let [primary, standby] = [0, 1].map(|at| test.node(at).name.clone());
        let at = |second: i64, writes: u64| {
            // One whose certificate names no node, and one naming this node,
            // draw nothing.
            let followers = [
                follower(Some(&standby), writes),
                follower(None, writes),
                follower(Some(&primary), writes),
            ];
            let seen = Seen {
                copied: &followers,
                ..Seen::default()
            };
            let mut topology = drawn(&test.name, &primary, &Snapshot::new(), seen);
            topology.observed_unix_nanos = second * 1_000_000_000;
            topology
        };
        // The window the primary's publisher keeps states the rate.
        let mut window = observe::topology::window::Window::new();
        let mut first = at(0, 120);
        window.state(&mut first, &Snapshot::new());
        let mut later = at(2, 220);
        window.state(&mut later, &Snapshot::new());

        let copies: Vec<&TopologyLink> = later
            .links
            .iter()
            .filter(|link| link.pattern == Pattern::Streaming)
            .collect();
        assert_eq!(copies.len(), 1, "{copies:?}");
        let link = copies[0];
        let id = |name: &str| format!("node/{name}");
        assert_eq!((&link.from, &link.to), (&id(&primary), &id(&standby)));
        assert_eq!(
            link.id,
            format!("{}→{} copies to", id(&primary), id(&standby))
        );
        assert_eq!(
            (link.protocol.as_str(), link.origin),
            (XMIP_STORAGE, Origin::Observed)
        );
        assert_eq!(link.volume, 520, "each write and each entry copied whole");
        assert!((link.rate - 50.0).abs() < 1e-9, "a hundred in two seconds");
        assert_eq!(
            link.evidence,
            "copies to: 220 write(s) copied, 300 entries copied whole, 2 MiB; \
             3 write(s) behind; the standby connected from 127.0.0.1:50000"
        );
        assert!(
            copied(&primary, &[]).is_empty(),
            "no standby following, no link"
        );
    }

    #[test]
    fn a_routed_stream_draws_its_location_to_its_subscription_with_its_volume() {
        let cluster = configure::fixture::test_cluster();
        let (node, scope) = (cluster.node(0).name.clone(), cluster.node_scope(0));
        let mut snapshot = Snapshot::new();
        for leaf in ["receive/In", "process/onward"] {
            snapshot.record_health(observe::HealthRecord {
                scope: format!("{scope}/{leaf}"),
                health: Health::Fine,
                severity: 0,
                evidence: String::new(),
                observed_unix_nanos: 1,
            });
        }
        let placed: Placed = (
            vec![("In".into(), 3)],
            vec![("In".into(), "onward".into(), 3)],
        );
        snapshot.record_subscription(observe::Subscription {
            node: scope.clone(),
            name: "onward".into(),
            ..observe::Subscription::default()
        });
        let transports = [("In".to_string(), "tcp".to_string())];
        let seen = Seen {
            placed: Some(&placed),
            transports: &transports,
            ..Seen::default()
        };
        let topology = drawn(&cluster.name, &node, &snapshot, seen);
        let link = topology
            .links
            .iter()
            .find(|link| link.pattern == Pattern::PublishConsume)
            .expect("the Location feeds its Subscription");
        assert_eq!(link.from, format!("node/{node}/receive/In"));
        assert_eq!(link.to, format!("node/{node}/process/onward"));
        assert_eq!(link.volume, 3);
        let party = topology
            .links
            .iter()
            .find(|link| link.from.starts_with("party/"))
            .expect("a Party sends into it");
        assert_eq!(
            party.protocol, "tcp",
            "its Location's transport, never its name"
        );
    }
}
