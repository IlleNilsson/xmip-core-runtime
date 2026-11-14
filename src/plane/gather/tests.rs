//! What a gatherer states of what it heard, held without a node: each
//! member's `<node>/reached`, what it heard merged into a caller's view, and
//! the cluster's view assembled — merged, rolled up, drawn by role with what
//! each member drew of itself, and what moved stated over its one window.
//! Following members over their operate listeners is `tests/plane`'s
//! (`gathered.rs`), and an assembly's cost the timing program's.

use std::sync::Arc;

use configure::fixture::test_cluster;
use node::{Capability, NodeRole};
use observe::snapshot::PAUSED_SEVERITY;
use observe::topology::relate::Member as Drawn;
use observe::topology::window::Window;
use observe::topology::{XMIP_STORAGE, link_id};
use observe::{
    Health, HealthRecord, NodeKind, Origin, Pattern, Relation, Snapshot, Topology, TopologyLink,
    TopologyNode,
};

use super::{Gathered, Heard, Said, reached};

/// Where the members are reached, as the Essentials' roll says it.
const AT: &str = "real, at the local endpoint";

/// 2026-11-13 at midnight, in unix nanoseconds.
const MIDNIGHT: u64 = 1_794_528_000_000_000_000;

fn record(scope: String, health: Health, evidence: &str) -> HealthRecord {
    HealthRecord {
        scope,
        health,
        severity: 0,
        evidence: evidence.to_string(),
        observed_unix_nanos: 7,
    }
}

fn heard(place: usize, said: Said) -> Arc<Heard> {
    Arc::new(Heard {
        node: test_cluster().node(place).name.clone(),
        at: AT.to_string(),
        said,
    })
}

/// What the test cluster's node at `place` publishes, declaring `role`:
/// its capability, a Location beneath its receive stage, and its own
/// drawing of that Location and of what it wrote into the node at
/// `storage`, `wrote` Publications.
fn published(place: usize, role: NodeRole, (storage, wrote): (usize, u64)) -> Said {
    let cluster = test_cluster();
    let scope = cluster.node_scope(place);
    let name = &cluster.node(place).name;
    let mut snapshot = Snapshot::new();
    let declares = Capability::of(&[role]).evidence();
    let capability = observe::capability::scope(&scope);
    snapshot.record_health(record(capability, Health::Fine, &declares));
    let location = format!("{scope}/receive/Orders");
    snapshot.record_health(record(location.clone(), Health::Fine, "started"));
    let (from, to) = (
        format!("node/{name}"),
        format!("node/{}", cluster.node(storage).name),
    );
    let drawing = Topology {
        nodes: vec![TopologyNode {
            id: format!("node/{name}/receive/Orders"),
            parent: format!("node/{name}/receive"),
            label: "Orders".to_string(),
            kind: NodeKind::Endpoint,
            scope: location,
            state: Health::Fine,
            origin: Origin::Both,
            load: 0.0,
            activity: 0.0,
            evidence: "its own".to_string(),
            roles: String::new(),
            place: None,
        }],
        links: vec![TopologyLink {
            id: link_id(&from, &to, Relation::WritesInto),
            from,
            to,
            pattern: Pattern::PublishConsume,
            origin: Origin::Observed,
            relation: Relation::WritesInto,
            protocol: XMIP_STORAGE.to_string(),
            state: Health::Fine,
            volume: wrote,
            rate: 0.0,
            latency_ms: 0.0,
            progress: 0.0,
            attempts: 0,
            evidence: "measured".to_string(),
        }],
        ..Topology::default()
    };
    Said::Published {
        snapshot: Box::new(snapshot),
        drawing: Some(drawing),
    }
}

/// The test cluster's first two nodes, receiving and the one Storage node.
fn members() -> Vec<Drawn> {
    let cluster = test_cluster();
    vec![
        Drawn::new(&cluster.node(0).name, &[NodeRole::Receiving], None),
        Drawn::new(&cluster.node(1).name, &[NodeRole::Storage], Some(0)),
    ]
}

#[test]
fn reached_says_where_a_member_answered_why_it_did_not_and_when_it_stopped() {
    let cluster = test_cluster();
    let root = cluster.scope();
    let at = format!("{}/reached", cluster.node_scope(0));

    let answered = reached(
        &root,
        &heard(0, published(0, NodeRole::Receiving, (1, 0))),
        9,
    );
    assert_eq!(answered.scope, at);
    assert_eq!(
        (
            answered.health,
            answered.severity,
            answered.evidence.as_str()
        ),
        (Health::Fine, 0, AT)
    );
    assert_eq!(answered.observed_unix_nanos, 9, "stated when it is stated");

    let silent = reached(&root, &heard(0, Said::Nothing("gone".to_string())), 9);
    assert_eq!((silent.health, silent.severity), (Health::Exhausted, 0));
    assert_eq!(silent.evidence, format!("{AT}, did not answer: gone"));

    let stopped = reached(&root, &heard(0, Said::Stopped(MIDNIGHT)), 9);
    assert_eq!(
        (stopped.health, stopped.severity),
        (Health::Paused, PAUSED_SEVERITY),
        "a deliberate stop"
    );
    assert_eq!(
        stopped.evidence,
        format!("{AT}, stopped in order at 2026-11-13T00:00:00Z")
    );
}

/// What the Essentials' roll states each round into a view of its own: each
/// member's snapshot and `<node>/reached`, in order, nothing of its own
/// replaced, no rollup, and what each drew of itself by its name.
#[test]
fn what_was_heard_merges_into_a_callers_view_with_what_each_drew() {
    let cluster = test_cluster();
    let root = cluster.scope();
    let gathered = Gathered {
        root: root.clone(),
        heard: vec![
            heard(0, published(0, NodeRole::Receiving, (1, 0))),
            heard(1, Said::Nothing("gone".to_string())),
        ],
        ..Gathered::default()
    };
    let mut view = Snapshot::new();
    let own = format!("{root}/round-trip/tcp");
    view.record_health(record(own.clone(), Health::Fine, "the caller's"));

    let drawings = gathered.merged(&mut view, 9);

    let scopes: Vec<&str> = view
        .health_records()
        .map(|one| one.scope.as_str())
        .collect();
    let (first, second) = (cluster.node_scope(0), cluster.node_scope(1));
    assert_eq!(
        scopes,
        [
            format!("{first}/capability"),
            format!("{first}/reached"),
            format!("{first}/receive/Orders"),
            format!("{second}/reached"),
            own,
        ]
    );
    let silent = view.health(&format!("{second}/reached")).remove(0).evidence;
    assert_eq!(silent, format!("{AT}, did not answer: gone"));
    let names: Vec<&str> = drawings.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(names, [cluster.node(0).name.as_str()], "one drew itself");
}

/// The cluster's view: every member merged, reached and rolled up, drawn
/// by role, what each drew of itself merged in by its name, and the
/// source saying how many answered.
#[test]
fn the_view_is_every_member_merged_rolled_up_and_drawn_by_role() {
    let cluster = test_cluster();
    let root = cluster.scope();
    let (receiving, storage) = (&cluster.node(0).name, &cluster.node(1).name);
    let members = members();
    let heard_all = vec![
        heard(0, published(0, NodeRole::Receiving, (1, 0))),
        heard(1, published(1, NodeRole::Storage, (0, 0))),
    ];
    let view = Gathered::assembled(
        (&root, None, &members),
        heard_all,
        1,
        (9, &mut Window::new()),
    );

    let rollup = view
        .snapshot
        .health_records()
        .find(|one| one.scope == format!("{root}/node"))
        .expect("the rollup at <cluster>/node");
    assert_eq!(rollup.evidence, "2 nodes, all 6 leaves fine");
    assert_eq!(
        view.topology.source,
        format!("{}, gathered: 2 of 2 nodes reached", cluster.name)
    );
    let node = |id: String| {
        view.topology
            .nodes
            .iter()
            .find(|one| one.id == id)
            .unwrap_or_else(|| panic!("{id} drawn"))
    };
    assert_eq!(node("cluster".to_string()).kind, NodeKind::Cluster);
    assert_eq!(node(format!("node/{storage}")).place, Some(0));
    let own = node(format!("node/{receiving}/receive/Orders"));
    assert_eq!(own.evidence, "its own", "the member's own drawing merged");
    let writes = link_id(
        &format!("node/{receiving}"),
        &format!("node/{storage}"),
        Relation::WritesInto,
    );
    let link = view
        .topology
        .links
        .iter()
        .find(|one| one.id == writes)
        .expect("related by role");
    assert_eq!(link.origin, Origin::Both, "configured and observed, joined");

    // The receiving member silent: it draws nothing of itself, and the
    // line it is configured to write into Storage by says why. Gathered by
    // a node, which the source names.
    let by = cluster.node_scope(2);
    let silent = Gathered::assembled(
        (&root, Some(by.as_str()), &members),
        vec![
            heard(0, Said::Nothing("gone".to_string())),
            heard(1, published(1, NodeRole::Storage, (0, 0))),
        ],
        2,
        (9, &mut Window::new()),
    );
    assert_eq!(
        silent.topology.source,
        format!(
            "{}, gathered by {}: 1 of 2 nodes reached",
            cluster.name,
            cluster.node(2).name
        )
    );
    let troubled = silent
        .topology
        .links
        .iter()
        .find(|one| one.id == writes)
        .expect("still related");
    assert_eq!(troubled.state, Health::Exhausted, "{}", troubled.evidence);
    assert!(
        troubled
            .evidence
            .ends_with(&format!("{AT}, did not answer: gone")),
        "{}",
        troubled.evidence
    );
    assert_eq!(silent.revision, 2);
}

/// The owner, 2026-11-10: motion follows traffic. What a member measured
/// moves at the rate the gatherer's one window states over its views.
#[test]
fn what_moved_between_views_is_stated_by_the_gatherers_one_window() {
    let cluster = test_cluster();
    let root = cluster.scope();
    let (receiving, storage) = (&cluster.node(0).name, &cluster.node(1).name);
    let members = members();
    let mut window = Window::new();
    let mut view = |wrote, at| {
        let heard_all = vec![
            heard(0, published(0, NodeRole::Receiving, (1, wrote))),
            heard(1, published(1, NodeRole::Storage, (0, 0))),
        ];
        Gathered::assembled((&root, None, &members), heard_all, 1, (at, &mut window))
    };
    let (_, later) = (view(0, 1_000_000_000), view(4, 3_000_000_000));
    let writes = link_id(
        &format!("node/{receiving}"),
        &format!("node/{storage}"),
        Relation::WritesInto,
    );
    let link = later
        .topology
        .links
        .iter()
        .find(|one| one.id == writes)
        .expect("drawn");
    assert!((link.rate - 2.0).abs() < f64::EPSILON, "{link:?}");
}
