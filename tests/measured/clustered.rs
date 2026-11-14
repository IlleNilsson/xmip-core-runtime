//! Answering `Cluster` from the gathered view, by the millisecond rule
//! (ADR-0027 decision 8, amendment 2026-11-13): a monitoring node posts
//! each view its gatherer assembles, once, as the text a publication file
//! holds (`plane::monitoring::written`), so answering a surface reads that
//! text and writes it, as answering the node's own publication does. Held
//! over loopback TLS, a cluster of nine members, each round beside a plain
//! wake (`plane.rs`'s `Rounds`): from the call to the answer read is under the
//! millisecond plus three plain wakes, and the process's processor time
//! across it under the millisecond plus a plain wake's. The node's own
//! publication of the same text is read the same way and printed beside
//! it, so what `Cluster` adds beyond the text it carries shows. Writing a
//! view, which each assembly pays once and no call does, is held under the
//! millisecond of processor time too, each step printed beside it.

use std::sync::Arc;
use std::time::Instant;

use configure::fixture::test_cluster;
use node::Capability;
use observe::topology::relate::Member as Drawn;
use observe::topology::window::Window;
use observe::{Health, HealthRecord, Publication, Snapshot, now_unix_nanos};
use xcore::latency::spread;
use xcore::processor_time::ProcessorTime;
use xmip_core_runtime::fixture::Authority;
use xmip_core_runtime::plane::gather::{Gathered, Heard, Said};
use xmip_core_runtime::plane::monitoring::written;
use xmip_core_runtime::plane::remote::Clustered;
use xmip_core_runtime::plane::{Board, Published, Role};

use super::plane::Rounds;
use super::{certified, endpoint};

/// The bound: about a millisecond.
const BOUND: std::time::Duration = std::time::Duration::from_millis(1);

/// The Locations beneath each member, each said Fine and counted.
const LOCATIONS: [&str; 4] = [
    "receive/Orders",
    "receive/Returns",
    "process/Matching",
    "send/Invoices",
];

/// The test cluster's nine members as a monitoring node gathers them: each
/// its capability and a record beneath each of its Locations, assembled by
/// the gatherer's one assembly.
fn nine() -> Gathered {
    let cluster = test_cluster();
    let root = cluster.scope();
    let mut drawn = Vec::new();
    let mut heard = Vec::new();
    let mut by = None;
    for (place, one) in cluster.nodes.iter().enumerate() {
        let roles = Capability::parse(&one.roles.join(",")).expect("its roles");
        let scope = cluster.node_scope(place);
        // Gathered by the node declaring the monitoring role, by its role.
        if roles.gathers() && by.is_none() {
            by = Some(scope.clone());
        }
        let mut snapshot = Snapshot::new();
        let record = |scope: String, evidence: String| HealthRecord {
            scope,
            health: Health::Fine,
            severity: 0,
            evidence,
            observed_unix_nanos: 7,
        };
        snapshot.record_health(record(observe::capability::scope(&scope), roles.evidence()));
        for location in LOCATIONS {
            snapshot.record_health(record(format!("{scope}/{location}"), "running".to_string()));
        }
        drawn.push(Drawn::new(&one.name, roles.roles(), None));
        heard.push(Arc::new(Heard {
            node: one.name.clone(),
            at: format!("at member {place}"),
            said: Said::Published {
                snapshot: Box::new(snapshot),
                drawing: None,
            },
        }));
    }
    Gathered::assembled(
        (&root, by.as_deref(), &drawn),
        heard,
        1,
        (now_unix_nanos(), &mut Window::new()),
    )
}

#[test]
fn a_monitoring_node_answers_the_cluster_from_its_gathered_view_within_the_millisecond() {
    let text = written(&nine());
    println!("the view of nine members: {} bytes", text.len());

    let authority = Authority::new();
    let own = Arc::new(Board::default());
    own.post(text.clone());
    let watching = endpoint::listing(Role::Observer, &["CN=surface"]);
    let (listener, _) = certified::node(&authority, &own, watching);
    let cluster = Arc::new(Board::default());
    cluster.post(text.clone());
    listener.gathers(Arc::clone(&cluster) as Arc<dyn Published>);
    let surface = certified::remote(&authority, &listener);
    assert_eq!(
        surface.cluster().expect("it answers"),
        Clustered::Gathered(1, text.clone())
    );

    // The node's own publication of the same text, beside it: printed.
    let mut own_reads = Vec::new();
    for _ in 0..200 {
        let asked = Instant::now();
        let read = surface.publication();
        own_reads.push(asked.elapsed());
        assert!(read.is_ok(), "{read:?}");
    }
    let _ = spread("the node's own publication of the same text", own_reads);

    let mut rounds = Rounds::default();
    for _ in 0..200 {
        let asked = Instant::now();
        let from = ProcessorTime::process();
        let answered = surface.cluster();
        rounds.took.push(asked.elapsed());
        rounds.worked.push(from.elapsed());
        assert!(
            matches!(&answered, Ok(Clustered::Gathered(1, read)) if read.len() == text.len()),
            "{answered:?}"
        );
        rounds.beside();
    }
    rounds.hold("Cluster answered from the gathered view of nine members");
}

/// Writing a view, by the millisecond rule: what each assembly pays once,
/// held by the processor time the writing thread ran, the fastest of five,
/// under the millisecond; each step printed beside it — the publication's
/// records gathered and ordered, the drawing taken, and the text written.
#[test]
fn a_view_of_nine_members_is_written_within_the_millisecond() {
    let view = nine();
    let (mut whole, mut drawn, mut text, mut all) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for _ in 0..100 {
        let from = ProcessorTime::thread();
        let publication = Publication::whole(&view.topology.source, &view.root, &view.snapshot);
        whole.push(from.elapsed());
        let from = ProcessorTime::thread();
        let publication = publication.with_topology(Some(view.topology.clone()));
        drawn.push(from.elapsed());
        let from = ProcessorTime::thread();
        let written_once = publication.to_toml();
        text.push(from.elapsed());
        assert!(!written_once.is_empty());
        let from = ProcessorTime::thread();
        let _ = written(&view);
        all.push(from.elapsed());
    }
    let _ = spread("the records gathered and ordered", whole);
    let _ = spread("the drawing taken", drawn);
    let _ = spread("the text written", text);
    let all = spread("a view of nine members written", all);
    assert!(
        all.fastest_of_five < BOUND,
        "a view written in {:?} of processor time, the fastest of five",
        all.fastest_of_five
    );
}
