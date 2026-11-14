//! The cluster's publication over the operate listener (ADR-0027 decision
//! 8, amendment 2026-11-13): `Cluster` refused, naming the role, by a
//! node that gathers none — after its caller's role was judged, so a
//! caller holding none learns nothing of the node's roles — and answered
//! beside the node's own publication by one that gathers, its follower told
//! as it advances; and a monitoring node's gathering (`plane::monitoring`):
//! every member followed, itself in process, a member that also gathers
//! read for its own publication only, the members followed anew as they
//! change, and a stop that ends it at once. What answering `Cluster` costs
//! is the timing program's (`tests/measured/clustered.rs`).

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use configure::fixture::test_cluster;
use node::{Capability, NodeRole};
use observe::{Health, HealthRecord, Publication, Snapshot};
use xcluster::{ClusterError, Member, Membership};
use xcore::lock::Locked;
use xcore::wake::Revision;
use xmip_core_runtime::fixture::Authority;
use xmip_core_runtime::plane::gather::{Follow, Reach, own};
use xmip_core_runtime::plane::monitoring::{Members, Monitoring};
use xmip_core_runtime::plane::remote::{Clustered, Follows};
use xmip_core_runtime::plane::served::GATHERS_NO_CLUSTER;
use xmip_core_runtime::plane::{Board, Listener, Published, Remote, Role};

use super::certified::{node, remote, remote_as};
use super::surface_as;

/// How long a test waits for what it is told before it fails.
const WITHIN: Duration = Duration::from_secs(5);

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
    Publication::whole("clustered-test", &scope, &snapshot).to_toml()
}

/// A node's listener publishing `own`, every surface the authority signs
/// an Observer, and a surface on it.
fn serving(authority: &Authority, own: &str) -> (Arc<Board>, Listener, Remote) {
    let board = Arc::new(Board::default());
    board.post(own.to_string());
    let (listener, _) = node(authority, &board, surface_as(Role::Observer));
    let surface = remote(authority, &listener);
    (board, listener, surface)
}

#[test]
fn a_node_gathering_none_refuses_the_cluster_naming_the_role_after_the_callers_role() {
    let authority = Authority::new();
    let (_board, listener, surface) = serving(&authority, "source = \"own\"\n");
    let said = match surface.cluster().expect("it answers") {
        Clustered::GathersNone(said) => said,
        gathered @ Clustered::Gathered(..) => panic!("gathers none: {gathered:?}"),
    };
    assert_eq!(said, GATHERS_NO_CLUSTER);
    assert!(said.contains("declares no monitoring role"), "{said}");
    // Its own publication stays its own.
    let (_, text) = surface.publication().expect("its own");
    assert_eq!(text, "source = \"own\"\n");
    // A caller holding no role is refused by role first: it is not told
    // whether the node gathers.
    let stranger = remote_as(&authority, &listener, "stranger");
    let refused = stranger.cluster().expect_err("refused by role");
    assert!(
        refused.contains("may not read the cluster's publication")
            && refused.contains("no role on this node"),
        "{refused}"
    );
    assert!(!refused.contains("monitoring"), "{refused}");
}

#[test]
fn a_gathering_node_answers_the_cluster_beside_its_own_and_tells_its_follower() {
    let authority = Authority::new();
    let (_board, listener, surface) = serving(&authority, "source = \"own\"\n");
    let cluster = Arc::new(Board::default());
    listener.gathers(Arc::clone(&cluster) as Arc<dyn Published>);
    // Nothing gathered yet: revision 0 and no text, as a node's own
    // publication before its first.
    let nothing = surface.cluster().expect("it answers");
    assert_eq!(nothing, Clustered::Gathered(0, String::new()));
    cluster.post("source = \"gathered\"\n".to_string());
    let gathered = surface.cluster().expect("it answers");
    assert_eq!(
        gathered,
        Clustered::Gathered(1, "source = \"gathered\"\n".to_string())
    );
    assert_eq!(
        surface.publication().expect("its own").1,
        "source = \"own\"\n"
    );

    let reached = surface
        .follow(Follows::Cluster, 0, WITHIN)
        .expect("follows the cluster's");
    assert!(reached.reachable, "{}", reached.reason);
    assert_eq!(reached.revision, 1);
    let posted = Instant::now();
    cluster.post("source = \"again\"\n".to_string());
    let told = surface
        .follow(Follows::Cluster, reached.told, WITHIN)
        .expect("follows the cluster's");
    assert_eq!(told.revision, 2);
    assert!(
        posted.elapsed() < Duration::from_secs(1),
        "told in {:?}",
        posted.elapsed()
    );
    // One surface follows one publication.
    let other = surface
        .follow(Follows::Node, 0, WITHIN)
        .expect_err("the other");
    assert!(
        other.contains("follows the cluster's publication"),
        "{other}"
    );
}

/// The members a test lists, as membership hands them, and told when they
/// change.
#[derive(Default)]
struct Listed {
    members: Mutex<Vec<Member>>,
    moved: Revision,
}

impl Listed {
    fn list(&self, members: Vec<Member>) {
        *self.members.locked() = members;
        self.moved.raise();
    }
}

impl Membership for Listed {
    fn members(&self) -> Result<Vec<Member>, ClusterError> {
        Ok(self.members.locked().clone())
    }
}

impl Members for Listed {
    fn moved(&self) -> &Revision {
        &self.moved
    }
}

/// The test cluster's node at `place`, declaring `roles`, operated at
/// `operate`, running.
fn member(place: usize, roles: &[NodeRole], operate: Option<String>) -> Member {
    Member {
        node: test_cluster().node_scope(place),
        address: None,
        capability: Capability::of(roles),
        operate,
        storage_place: None,
        stopped: None,
    }
}

/// The cluster's publication once `holds` says it of its text, waited for
/// on what `monitoring` answers from.
fn until(monitoring: &Monitoring, holds: impl Fn(&str) -> bool) -> String {
    let published = monitoring.published();
    let deadline = Instant::now() + WITHIN;
    let (mut revision, mut text) = published.read();
    while !holds(&text) && Instant::now() < deadline {
        published.wait(revision, WITHIN, &|| false);
        (revision, text) = published.read();
    }
    text
}

#[test]
fn a_monitoring_node_gathers_every_member_itself_in_process_and_follows_them_anew() {
    let authority = Authority::new();
    // A member that gathers too: what it gathered is never read from it.
    let (_first_board, first, _) = serving(&authority, &published(0, "receive/Orders"));
    let its_cluster = Arc::new(Board::default());
    its_cluster.post(published(0, "only-in-its-cluster"));
    first.gathers(Arc::clone(&its_cluster) as Arc<dyn Published>);
    let (_second_board, second, _) = serving(&authority, &published(1, "receive/Invoices"));
    // The monitoring node itself, followed in process: no listener at all.
    let itself = Arc::new(Board::default());
    itself.post(published(2, "send/Claims"));

    let listed = Arc::new(Listed::default());
    let gathering = [NodeRole::Operational, NodeRole::Monitoring];
    let (one, me) = (
        member(0, &[NodeRole::Monitoring], Some(first.address())),
        member(2, &gathering, None),
    );
    listed.list(vec![one, me.clone()]);
    let identity = authority.identity("surface");
    let own_follow = own(Arc::clone(&itself) as Arc<dyn Published>);
    let reach = move |member: &Member| -> Reach {
        if member.node == me.node {
            return Reach {
                at: "in process".to_string(),
                through: Ok(Arc::clone(&own_follow)),
            };
        }
        let address = member.operate.clone().unwrap_or_default();
        let through = Remote::retrying(&address, &identity, vec![Duration::from_millis(50)])
            .map(|remote| Arc::new(remote) as Arc<dyn Follow>);
        Reach {
            at: format!("at {address}"),
            through,
        }
    };
    let monitoring = Monitoring::default();
    let cluster = test_cluster();
    let by = cluster.node_scope(2);
    monitoring
        .begin(
            (cluster.scope(), by),
            Arc::clone(&listed) as Arc<dyn Members>,
            Box::new(reach),
        )
        .expect("it begins");

    let text = until(&monitoring, |text| text.contains("2 of 2"));
    let read = Publication::read(&text).expect("a publication");
    assert_eq!(read.node, cluster.scope(), "the cluster's scope");
    assert!(read.source.contains("gathered by"), "{}", read.source);
    let scopes: Vec<String> = read.records.iter().map(|one| one.scope.clone()).collect();
    let has = |place: usize, leaf: &str| {
        let scope = format!("{}/{leaf}", cluster.node_scope(place));
        scopes.contains(&scope)
    };
    assert!(
        has(0, "receive/Orders") && has(2, "send/Claims"),
        "{scopes:?}"
    );
    assert!(
        !has(0, "only-in-its-cluster"),
        "read for its own only: {scopes:?}"
    );

    // A member joins: the members are followed anew, never asked again.
    let joined = member(1, &[NodeRole::Receiving], Some(second.address()));
    let mut members = listed.members().expect("listed");
    members.push(joined);
    listed.list(members);
    let text = until(&monitoring, |text| text.contains("3 of 3"));
    assert!(
        text.contains(&format!("{}/receive/Invoices", cluster.node_scope(1))),
        "{text}"
    );

    let stopping = Instant::now();
    monitoring.stop();
    assert!(
        stopping.elapsed() < Duration::from_secs(1),
        "stopped in {:?}",
        stopping.elapsed()
    );
}
