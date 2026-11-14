//! A cluster's view gathered over loopback (`plane::gather`; ADR-0052,
//! amendment 2026-11-13): the members the cluster's `Membership` names, each
//! followed over its operate listener inside Xmip's mutual TLS as the test
//! says this process reaches it, heard as it publishes because its surface
//! is told, never asked again and again; a member lost, and one this process
//! cannot reach, said not to answer and why, and one its membership says
//! stopped in order said so; and a gatherer that ends at once. What an
//! assembly costs is the timing program's (`tests/measured`).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use configure::fixture::test_cluster;
use node::{Capability, NodeRole};
use observe::{Health, HealthRecord, Publication, Snapshot};
use xcluster::{ClusterError, Member, Membership};
use xmip_core_runtime::fixture::Authority;
use xmip_core_runtime::plane::gather::{Follow, Gathered, Gatherer, Reach, Said, own};
use xmip_core_runtime::plane::{Board, Listener, Published, Remote, Role};

use super::certified::{node, remote};
use super::surface_as;

/// How long a test waits for what it is told before it fails.
const WITHIN: Duration = Duration::from_secs(5);

/// Where a member is reached, as the test says it.
const AT: &str = "at its operate listener";

/// The members a test lists, as the cluster's seam hands them.
struct Listed(Vec<Member>);

impl Membership for Listed {
    fn members(&self) -> Result<Vec<Member>, ClusterError> {
        Ok(self.0.clone())
    }
}

/// What the test cluster's node at `place` publishes: one leaf, Fine.
fn published(place: usize, leaf: &str) -> String {
    let scope = test_cluster().node_scope(place);
    let mut snapshot = Snapshot::new();
    snapshot.record_health(HealthRecord {
        scope: format!("{scope}/{leaf}"),
        health: Health::Fine,
        severity: 0,
        evidence: "published".to_string(),
        observed_unix_nanos: 7,
    });
    Publication::whole("plane-test", &scope, &snapshot).to_toml()
}

/// The test cluster's node at `place`, receiving, operated at `operate`,
/// running.
fn member(place: usize, operate: Option<String>) -> Member {
    Member {
        node: test_cluster().node_scope(place),
        address: None,
        capability: Capability::of(&[NodeRole::Receiving]),
        operate,
        storage_place: None,
        stopped: None,
    }
}

/// A node at `place` publishing `leaf`, its listener, and a surface on it.
fn serving(authority: &Authority, place: usize, leaf: &str) -> (Arc<Board>, Listener, Arc<Remote>) {
    let board = Arc::new(Board::default());
    board.post(published(place, leaf));
    let (listener, _) = node(authority, &board, surface_as(Role::Observer));
    let surface = Arc::new(remote(authority, &listener));
    (board, listener, surface)
}

/// How this test reaches each member: through what it holds on the member
/// — a surface on its operate listener, or its own publication — found by
/// its node; one it holds nothing on it cannot reach.
fn reaching(surfaces: Vec<(Member, Arc<dyn Follow>)>) -> impl Fn(&Member) -> Reach {
    move |member| Reach {
        at: AT.to_string(),
        through: surfaces
            .iter()
            .find(|(one, _)| one.node == member.node)
            .map(|(_, through)| Arc::clone(through))
            .ok_or_else(|| "this process holds no surface on it".to_string()),
    }
}

/// The record at `<node at place>/<leaf>` of `view`, where it has one.
fn leaf(view: &Gathered, place: usize, leaf: &str) -> Option<HealthRecord> {
    let scope = format!("{}/{leaf}", test_cluster().node_scope(place));
    view.snapshot
        .health_records()
        .find(|one| one.scope == scope)
        .cloned()
}

/// The first view after `view` that `holds`, waited for.
fn until(
    gatherer: &Gatherer,
    view: Arc<Gathered>,
    holds: impl Fn(&Gathered) -> bool,
) -> Arc<Gathered> {
    let deadline = Instant::now() + WITHIN;
    let mut view = view;
    while !holds(&view) && Instant::now() < deadline {
        view = gatherer.wait(view.revision, WITHIN);
    }
    view
}

/// Two members over their operate listeners, and the gathering node itself,
/// the third, followed in process through its own publication (`own`), as
/// a node with no role on its own listener follows itself.
#[test]
fn a_gatherer_hears_every_member_at_once_and_again_as_each_publishes() {
    let authority = Authority::new();
    let (first, a, first_surface) = serving(&authority, 0, "receive/Orders");
    let (_board, b, second_surface) = serving(&authority, 1, "receive/Invoices");
    let itself = Arc::new(Board::default());
    itself.post(published(2, "receive/Claims"));
    let root = test_cluster().scope();
    let (one, two, three) = (
        member(0, Some(a.address())),
        member(1, Some(b.address())),
        member(2, None),
    );
    let reach = reaching(vec![
        (one.clone(), first_surface as Arc<dyn Follow>),
        (two.clone(), second_surface as Arc<dyn Follow>),
        (
            three.clone(),
            own(Arc::clone(&itself) as Arc<dyn Published>),
        ),
    ]);
    let by = three.node.clone();
    let listed = Listed(vec![one, two, three]);

    let gatherer = Gatherer::start(&root, Some(&by), &listed, &reach).expect("listed");

    let view = gatherer.gathered();
    assert!(view.revision >= 1, "the first view, assembled at the start");
    assert!(
        view.heard
            .iter()
            .all(|one| matches!(one.said, Said::Published { .. })),
        "every member heard once before the start returns"
    );
    let name = |place: usize| test_cluster().node(place).name.clone();
    assert_eq!(
        view.topology.source,
        format!(
            "{}, gathered by {}: 3 of 3 nodes reached",
            test_cluster().name,
            name(2)
        )
    );
    for (place, published) in [
        (0, "receive/Orders"),
        (1, "receive/Invoices"),
        (2, "receive/Claims"),
    ] {
        assert!(leaf(&view, place, published).is_some(), "{place}");
        let reached = leaf(&view, place, "reached").expect("its reach said");
        assert_eq!(
            (reached.health, reached.evidence.as_str()),
            (Health::Fine, AT)
        );
    }
    let receiving = view
        .topology
        .nodes
        .iter()
        .find(|one| one.id == format!("node/{}", test_cluster().node(0).name))
        .expect("drawn by its name in its scope");
    assert_eq!(receiving.roles, "receiving", "by what it declares");

    let posted = Instant::now();
    first.post(published(0, "receive/Returns"));
    itself.post(published(2, "receive/Refunds"));
    let told = until(&gatherer, view, |one| {
        leaf(one, 0, "receive/Returns").is_some() && leaf(one, 2, "receive/Refunds").is_some()
    });
    assert!(
        leaf(&told, 0, "receive/Returns").is_some(),
        "heard as it published, told and never asked"
    );
    assert!(
        leaf(&told, 2, "receive/Refunds").is_some(),
        "its own publication heard in process as it posted"
    );
    assert!(
        posted.elapsed() < Duration::from_secs(1),
        "{:?}",
        posted.elapsed()
    );
}

#[test]
fn a_member_lost_or_out_of_reach_does_not_answer_and_one_stopped_in_order_says_so() {
    let authority = Authority::new();
    let (_board, mut listener, surface) = serving(&authority, 0, "receive/Orders");
    let root = test_cluster().scope();
    let (followed, unreached) = (member(0, Some(listener.address())), member(1, None));
    let stopped = Member {
        stopped: Some(1_794_528_000_000_000_000),
        ..member(2, None)
    };
    let reach = reaching(vec![(followed.clone(), surface as Arc<dyn Follow>)]);
    let listed = Listed(vec![followed, unreached, stopped]);
    let gatherer = Gatherer::start(&root, None, &listed, &reach).expect("listed");
    let view = gatherer.gathered();

    let out_of_reach = leaf(&view, 1, "reached").expect("said at once");
    assert_eq!(out_of_reach.health, Health::Exhausted);
    assert_eq!(
        out_of_reach.evidence,
        format!("{AT}, did not answer: this process holds no surface on it")
    );
    let paused = leaf(&view, 2, "reached").expect("said at once");
    assert_eq!(
        (paused.health, paused.evidence.as_str()),
        (
            Health::Paused,
            format!("{AT}, stopped in order at 2026-11-13T00:00:00Z").as_str()
        ),
        "followed by nothing, said as its membership says"
    );

    listener.stop();
    let lost = until(&gatherer, view, |one| {
        leaf(one, 0, "reached").is_some_and(|reached| reached.health == Health::Exhausted)
    });
    let reached = leaf(&lost, 0, "reached").expect("its reach said");
    assert_eq!(reached.health, Health::Exhausted, "{}", reached.evidence);
    assert!(
        reached
            .evidence
            .starts_with(&format!("{AT}, did not answer: ")),
        "{}",
        reached.evidence
    );
    assert!(
        leaf(&lost, 0, "receive/Orders").is_none(),
        "nothing else of a member that does not answer"
    );
}

#[test]
fn a_membership_that_cannot_be_read_follows_nothing_and_says_why() {
    struct Unread;
    impl Membership for Unread {
        fn members(&self) -> Result<Vec<Member>, ClusterError> {
            Err(ClusterError::new(
                "the administration database did not answer",
            ))
        }
    }
    let reach = reaching(Vec::new());
    let refused = Gatherer::start(&test_cluster().scope(), None, &Unread, &reach)
        .err()
        .expect("refused");
    assert_eq!(
        refused.message,
        "the administration database did not answer"
    );
}

#[test]
fn a_gatherer_ends_at_once_and_leaves_the_surface_it_shared_working() {
    let authority = Authority::new();
    let (_board, listener, surface) = serving(&authority, 0, "receive/Orders");
    let root = test_cluster().scope();
    let only = member(0, Some(listener.address()));
    let shared = Arc::clone(&surface) as Arc<dyn Follow>;
    let reach = reaching(vec![(only.clone(), shared)]);
    let gatherer = Gatherer::start(&root, None, &Listed(vec![only]), &reach).expect("listed");
    // Its follower waiting on the surface's follow.
    let _ = gatherer.wait(0, Duration::from_millis(100));

    let dropped = Instant::now();
    drop(gatherer);
    assert!(
        dropped.elapsed() < Duration::from_secs(1),
        "{:?}",
        dropped.elapsed()
    );
    assert!(surface.publication().is_ok(), "the surface is not ended");
}

/// A publisher waiting on a gatherer's views is let go at once when what
/// stops it says so and the gatherer is woken — another gatherer taking
/// its place, its node stopping — with the last view and no new one.
#[test]
fn a_wait_on_the_views_ends_at_once_when_woken_and_stopped() {
    let itself = Arc::new(Board::default());
    itself.post(published(0, "receive/Orders"));
    let only = member(0, None);
    let reach = reaching(vec![(
        only.clone(),
        own(Arc::clone(&itself) as Arc<dyn Published>),
    )]);
    let root = test_cluster().scope();
    let gatherer =
        Arc::new(Gatherer::start(&root, None, &Listed(vec![only]), &reach).expect("listed"));
    let last = gatherer.gathered().revision;
    let stopped = Arc::new(AtomicBool::new(false));
    let waiting = {
        let (gatherer, stopped) = (Arc::clone(&gatherer), Arc::clone(&stopped));
        std::thread::spawn(move || {
            let view = gatherer.wait_unless(last, Duration::from_secs(30), &|| {
                stopped.load(Ordering::SeqCst)
            });
            view.revision
        })
    };
    std::thread::sleep(Duration::from_millis(50));

    let woken = Instant::now();
    stopped.store(true, Ordering::SeqCst);
    gatherer.wake();
    let revision = waiting.join().expect("the wait ended");
    assert!(
        woken.elapsed() < Duration::from_secs(1),
        "{:?}",
        woken.elapsed()
    );
    assert_eq!(revision, last, "let go with the last view, none new");
}
