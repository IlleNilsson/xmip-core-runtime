//! What a gatherer pays to assemble a cluster's view, by the millisecond
//! rule (`plane::gather`; ADR-0052, amendment 2026-11-13): every member's
//! snapshot merged with its `<node>/reached`, the rollup, the cluster drawn
//! by role with what each member drew of itself, and what moved stated by
//! the gatherer's one window — within a millisecond for a view drawing as
//! many things as the 176-node publication `SnapshotReadCostTest` reads,
//! drawn as that one is and drawn by a cluster related by role. What is
//! held is the processor time the assembling thread ran
//! (`xcore::processor_time`): the work, which no other program's turn on
//! the processors reaches; the wall clock is printed beside it. On
//! 2026-11-13 the first build took 5.6 ms for the second shape: observe's
//! drawing asked the snapshot about one scope at a time, each a pass over
//! every record that copied and sorted what it found
//! (`observe::snapshot::Beneath`), and wrote about 6,400 strings an
//! assembly, each grown several times by `format!`
//! (`observe::topology::draw::joined`).

use std::sync::Arc;
use std::time::{Duration, Instant};

use xcore::processor_time::ProcessorTime;

use configure::fixture::test_cluster;
use node::{Capability, NodeRole};
use observe::topology::relate::Member as Drawn;
use observe::topology::window::Window;
use observe::topology::{XMIP_STORAGE, link_id};
use observe::{
    Count, Counted, Health, HealthRecord, NodeKind, Origin, Pattern, Relation, Snapshot, Topology,
    TopologyLink, TopologyNode,
};
use xmip_core_runtime::plane::gather::{Gathered, Heard, Said};

/// How many things the view draws, as `SnapshotReadCostTest` draws them.
const DRAWN: usize = 176;

/// A quarter of a second, in nanoseconds: how often `xmip-service`
/// publishes, and so how often a gatherer hears each member.
const QUARTER: i64 = 250_000_000;

/// The Locations beneath each member's stages, where it declares them.
const LOCATIONS: [&str; 3] = ["receive/Orders", "receive/Returns", "send/Invoices"];

fn thing(id: String, parent: String, kind: NodeKind, scope: String) -> TopologyNode {
    TopologyNode {
        id,
        parent,
        label: String::new(),
        kind,
        scope,
        state: Health::Fine,
        origin: Origin::Both,
        load: 0.0,
        activity: 0.0,
        evidence: String::new(),
        roles: String::new(),
        place: None,
    }
}

fn writes(from: String, to: String, volume: u64) -> TopologyLink {
    TopologyLink {
        id: link_id(&from, &to, Relation::WritesInto),
        from,
        to,
        pattern: Pattern::PublishConsume,
        origin: Origin::Observed,
        relation: Relation::WritesInto,
        protocol: XMIP_STORAGE.to_string(),
        state: Health::Fine,
        volume,
        rate: 0.0,
        latency_ms: 0.0,
        progress: 0.0,
        attempts: 0,
        evidence: String::new(),
    }
}

/// The member at `place`, called after the test cluster's node of that
/// place among nine.
fn named(place: usize, roles: &[NodeRole], storage_place: Option<u32>) -> Drawn {
    let name = format!("{}-{place}", test_cluster().node(place % 9).name);
    Drawn::new(&name, roles, storage_place)
}

/// The member at `place` of a cluster related by role: executing, the
/// first also the Storage node `[storage] nodes` lists and the second
/// operational and monitoring, so every member relates to the others.
fn related(place: usize) -> Drawn {
    match place {
        0 => named(place, &[NodeRole::Executing, NodeRole::Storage], Some(0)),
        1 => named(
            place,
            &[
                NodeRole::Executing,
                NodeRole::Operational,
                NodeRole::Monitoring,
            ],
            None,
        ),
        _ => named(place, &[NodeRole::Executing], None),
    }
}

/// What `member` published by its `round`: its capability, and for each
/// stage it declares a record and a count beneath each Location; its own
/// drawing of its node, its stages and Locations, and what it wrote into
/// the Storage node `primary`, where one is listed.
fn heard(member: &Drawn, primary: Option<&str>, round: u64) -> Arc<Heard> {
    let root = test_cluster().scope();
    let (scope, id) = (
        format!("{root}/node/{}", member.node),
        format!("node/{}", member.node),
    );
    let mut snapshot = Snapshot::new();
    let record = |scope: String, evidence: String| HealthRecord {
        scope,
        health: Health::Fine,
        severity: 0,
        evidence,
        observed_unix_nanos: 7,
    };
    let declares = Capability::of(&member.roles).evidence();
    snapshot.record_health(record(observe::capability::scope(&scope), declares));
    let mut nodes = vec![thing(
        id.clone(),
        "cluster".to_string(),
        NodeKind::Node,
        scope.clone(),
    )];
    let staged = member.declares(NodeRole::Executing);
    for stage in ["receive", "process", "send"]
        .into_iter()
        .filter(|_| staged)
    {
        let at = format!("{id}/{stage}");
        let within = format!("{scope}/{stage}");
        nodes.push(thing(at, id.clone(), NodeKind::Stage, within));
    }
    for location in LOCATIONS.into_iter().filter(|_| staged) {
        let (stage, _) = location.split_once('/').expect("a stage and a Location");
        let within = format!("{scope}/{location}");
        snapshot.record_health(record(within.clone(), "started".to_string()));
        let counted = if stage == "send" {
            Counted::Messages
        } else {
            Counted::Streams
        };
        snapshot.record_count(Count {
            scope: within.clone(),
            counted,
            value: round,
            window_start_unix_nanos: 0,
            window_end_unix_nanos: 0,
            observed_unix_nanos: 0,
        });
        let parent = format!("{id}/{stage}");
        nodes.push(thing(
            format!("{id}/{location}"),
            parent,
            NodeKind::Endpoint,
            within,
        ));
    }
    let links = primary
        .map(|primary| format!("node/{primary}"))
        .filter(|primary| *primary != id)
        .map(|primary| writes(id, primary, round))
        .into_iter()
        .collect();
    let drawing = Topology {
        nodes,
        links,
        ..Topology::default()
    };
    Arc::new(Heard {
        node: member.node.clone(),
        at: "at its operate listener".to_string(),
        said: Said::Published {
            snapshot: Box::new(snapshot),
            drawing: Some(drawing),
        },
    })
}

/// The fastest of five of fifty assemblies of `members`' view, each round
/// hearing them anew, held to the millisecond of processor time; `moved`
/// holds each view measured.
fn timed(what: &str, members: &[Drawn], moved: impl Fn(&Gathered) -> bool) {
    ProcessorTime::calibrate();
    let root = test_cluster().scope();
    let primary = members
        .iter()
        .find(|member| member.declares(NodeRole::Storage))
        .map(|member| member.node.as_str());
    let mut window = Window::new();
    let (mut worked, mut took) = (Vec::new(), Vec::new());
    // Past the half minute first, so the window holds what it holds as a
    // gatherer runs: about thirty readings of each figure.
    for round in 0..200_u64 {
        let latest: Vec<Arc<Heard>> = members
            .iter()
            .map(|member| heard(member, primary, round))
            .collect();
        let at = i64::try_from(round).expect("small") * QUARTER;
        let (began, started) = (ProcessorTime::thread(), Instant::now());
        let view = Gathered::assembled((&root, None, members), latest, round, (at, &mut window));
        let (ran, waited) = (began.elapsed(), started.elapsed());
        assert_eq!(view.topology.nodes.len(), DRAWN, "{what}");
        if round >= 150 {
            worked.push(ran);
            took.push(waited);
            assert!(moved(&view), "{what}");
        }
    }
    // Printed, and held by nothing: the wall clock counts other programs'
    // turns on the processors too.
    let _ = xcore::latency::spread(&format!("{what}, by the wall clock"), took);
    let spread = xcore::latency::spread(&format!("{what}, processor time"), worked);
    assert!(
        spread.fastest_of_five < Duration::from_millis(1),
        "{spread:?}"
    );
}

/// The publication `SnapshotReadCostTest` reads, as far as its drawing
/// goes: the cluster and 175 nodes beneath it, none declaring a role.
#[test]
fn a_view_of_175_members_declaring_no_role_is_assembled_within_a_millisecond() {
    let members: Vec<Drawn> = (0..DRAWN - 1)
        .map(|place| named(place, &[], None))
        .collect();
    timed(
        "a view of 175 members declaring no role, assembled",
        &members,
        |view| view.topology.links.is_empty(),
    );
}

/// 25 members, each drawing seven things: every member related by role to
/// the others, and what each wrote into Storage moving.
#[test]
fn a_view_of_a_cluster_related_by_role_drawing_as_many_is_assembled_within_a_millisecond() {
    let members: Vec<Drawn> = (0..(DRAWN - 1) / 7).map(related).collect();
    timed(
        "a view of 25 members related by role, drawing 176 things, assembled",
        &members,
        |view| {
            view.topology
                .links
                .iter()
                .filter(|one| one.relation == Relation::WritesInto)
                .all(|one| one.rate > 0.0)
        },
    );
}
