//! A node's membership: its row written once Storage is reached and again
//! as it stops in order, the members followed as other nodes write theirs,
//! the one seam's members read back from the rows, and a save not its
//! peers' flagged.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use node::NodeRole;
use observe::Health;
use persist::storage::{MemberRecord, XmipStorage};
use xcluster::Membership;

use super::*;
use crate::fixture::{Failing, Operation};

/// Far longer than any test here takes: a wait that ends sooner was told.
const LONG: Duration = Duration::from_secs(60);

/// How long a try that failed rests: short, so a test heals at once.
const REST: Duration = Duration::from_millis(1);

fn scope(place: usize) -> String {
    configure::fixture::test_cluster().node_scope(place)
}

fn storage() -> Arc<dyn XmipStorage> {
    let (node, _) = persist::fixture::crowd::node();
    Arc::new(node)
}

/// The node at `place`, receiving, its row keyed by `process` and running
/// `save`.
fn row(process: u128, place: usize, save: &str) -> MemberRecord {
    let declared = node::Capability::of(&[NodeRole::Receiving]).with_online(true);
    MemberRecord {
        process,
        node: scope(place),
        roles: declared.words(),
        evidence: declared.evidence(),
        operate: Some("127.0.0.1:7443".to_string()),
        sync: None,
        storage_place: None,
        save: save.to_string(),
        serial: 4,
        started_unix_nanos: 0,
        stopped_unix_nanos: None,
        written: 0,
        latest: false,
    }
}

fn nowhere() -> Place {
    Box::new(|| None)
}

fn processes(rows: &[MemberRecord]) -> Vec<u128> {
    let mut each: Vec<u128> = rows.iter().map(|row| row.process).collect();
    each.sort_unstable();
    each
}

/// What `followed` says at `<node>/membership`.
fn said(followed: &Followed, node: &str) -> (String, Health, String) {
    let said = Mutex::new(Vec::new());
    followed.publish(node, |scope, health, evidence| {
        said.lock().expect("said").push((scope, health, evidence));
    });
    let mut said = said.into_inner().expect("said");
    assert_eq!(said.len(), 1, "one record");
    said.remove(0)
}

#[test]
fn a_node_s_row_is_written_and_the_members_followed_as_another_writes_its_own() {
    let storage = storage();
    let place: Place = Box::new(|| Some(1));
    let own = (row(1, 0, "sha256:a"), place);
    let mut joined = Joined::start(Arc::clone(&storage), own, (LONG, REST)).expect("started");
    let followed = Arc::clone(joined.followed());
    let first = followed.revision().wait(0, LONG);
    assert!(followed.written(), "written once Storage is reached");
    assert_eq!(processes(&followed.rows()), [1]);
    assert_eq!(
        followed.rows()[0].storage_place,
        Some(1),
        "found as written"
    );

    let asked = Instant::now();
    storage
        .write_member(&row(2, 1, "sha256:a"))
        .expect("another node's");
    let second = followed.revision().wait(first, LONG);
    assert!(
        asked.elapsed() < LONG && second > first,
        "told, never asked again"
    );
    assert_eq!(processes(&followed.rows()), [1, 2]);

    let members = followed.members().expect("the members");
    assert_eq!(members.len(), 2);
    let one = members
        .iter()
        .find(|m| m.node == scope(0))
        .expect("this node");
    assert_eq!(one.capability.roles(), [NodeRole::Receiving]);
    assert!(one.capability.is_online(), "read back from its evidence");
    assert_eq!((one.storage_place, one.stopped), (Some(1), None));
    assert_eq!(one.operate.as_deref(), Some("127.0.0.1:7443"));
    assert_eq!(one.address, None, "no sync listener starts yet");

    assert_eq!(joined.stop(Ok(())), None, "stopped in order");
    let kept = storage.read_members().expect("read");
    let stopped = kept.iter().find(|m| m.process == 1).expect("kept");
    assert!(stopped.stopped_unix_nanos.is_some(), "its stop written");
    assert!(kept.iter().any(|m| m.process == 2 && m.runs()));
}

/// The stop of a node whose Storage its client knows not to answer writes
/// nothing, waits on nothing, and says why its row still says it runs.
#[test]
fn a_stop_with_storage_not_answering_writes_nothing_and_says_why() {
    let storage = storage();
    let mut joined = Joined::start(
        Arc::clone(&storage),
        (row(1, 0, "sha256:a"), nowhere()),
        (LONG, REST),
    )
    .expect("started");
    joined.followed().revision().wait(0, LONG);
    assert_eq!(joined.stop(Err(UNANSWERED)), Some(UNANSWERED));
    assert_eq!(joined.stop(Ok(())), None, "once is enough");
    let kept = storage.read_members().expect("read");
    assert!(
        kept[0].runs(),
        "no stop written: the cluster says it did not answer"
    );
}

#[test]
fn a_node_whose_row_cannot_be_written_is_no_member_yet_and_says_why_and_stops_writing_nothing() {
    let failing = Failing::over(storage());
    failing.fail(Operation::WriteMember, u32::MAX);
    let storage: Arc<dyn XmipStorage> = Arc::clone(&failing) as Arc<dyn XmipStorage>;
    let mut joined = Joined::start(
        Arc::clone(&storage),
        (row(1, 0, "sha256:a"), nowhere()),
        (LONG, REST),
    )
    .expect("started");
    let followed = Arc::clone(joined.followed());
    let deadline = Instant::now() + LONG;
    while followed.problem().is_none() {
        assert!(Instant::now() < deadline, "never tried");
        std::thread::yield_now();
    }
    let (at, health, evidence) = said(&followed, &scope(0));
    assert!(at.ends_with("/membership"), "{at}");
    assert_eq!(health, Health::Working, "{evidence}");
    assert!(evidence.starts_with("not a member yet"), "{evidence}");
    assert!(
        followed.members().is_err(),
        "no members said before its row"
    );
    assert_eq!(joined.stop(Ok(())), None, "nothing to write");
    assert_eq!(storage.read_members().expect("read"), [], "no row, no stop");

    failing.heal();
    let joined = Joined::start(
        Arc::clone(&storage),
        (row(3, 0, "sha256:a"), nowhere()),
        (LONG, REST),
    )
    .expect("started");
    joined.followed().revision().wait(0, LONG);
    let (_, health, evidence) = said(joined.followed(), &scope(0));
    assert_eq!(health, Health::Fine, "{evidence}");
    assert!(
        evidence.contains("1 member(s) run, on this save"),
        "{evidence}"
    );
}

#[test]
fn a_save_not_its_peers_is_flagged_and_where_two_saves_tie_neither_is_theirs() {
    let storage = storage();
    for (process, place, save) in [(2, 1, "sha256:a"), (3, 2, "sha256:a")] {
        storage
            .write_member(&row(process, place, save))
            .expect("a peer");
    }
    let joined = Joined::start(
        Arc::clone(&storage),
        (row(1, 0, "sha256:b"), nowhere()),
        (LONG, REST),
    )
    .expect("started");
    joined.followed().revision().wait(0, LONG);
    let (_, health, evidence) = said(joined.followed(), &scope(0));
    assert_eq!(health, Health::Stressed, "{evidence}");
    assert!(
        evidence.contains("this save is not its peers'"),
        "{evidence}"
    );
    assert!(evidence.contains("sha256:a"), "{evidence}");

    let rows = storage.read_members().expect("read");
    assert_eq!(peers_save(&rows), Some("sha256:a"));
    let tied: Vec<MemberRecord> = rows.iter().filter(|m| m.process != 3).cloned().collect();
    assert_eq!(peers_save(&tied), None, "one each: no save is the peers'");
    let stopped: Vec<MemberRecord> = tied
        .iter()
        .map(|m| MemberRecord {
            stopped_unix_nanos: (m.process == 2).then_some(1),
            ..m.clone()
        })
        .collect();
    assert_eq!(peers_save(&stopped), Some("sha256:b"), "only what runs");
    assert_eq!(peers_save(&[]), None);
}
