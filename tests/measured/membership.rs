//! A node's stop with its Xmip Storage gone, held to the millisecond rule:
//! its membership's stop is decided by what its Storage client already
//! knows (`storage::Reached::answers`), never by a try that would wait out a
//! Storage node's timeout, so it adds no more than a millisecond beyond the
//! stop's own work; its row is left saying it runs, and the stop says why.

use std::net::TcpListener;
use std::sync::Arc;
use std::time::{Duration, Instant};

use persist::storage::{MemberRecord, StorageServer, XmipStorage};
use xmip_core_runtime::fixture::Authority;
use xmip_core_runtime::linked::Linked;
use xmip_core_runtime::membership::{Joined, UNANSWERED};
use xmip_core_runtime::storage::Planned;
use xmip_core_runtime::tuning::Tuning;

/// Far longer than anything here takes.
const LONG: Duration = Duration::from_secs(60);

/// The test cluster's first node as it writes its row.
fn row() -> MemberRecord {
    let declared = node::Capability::of(&[node::NodeRole::Receiving]);
    MemberRecord {
        process: 1,
        node: configure::fixture::test_cluster().node_scope(0),
        roles: declared.words(),
        evidence: declared.evidence(),
        operate: None,
        sync: None,
        storage_place: None,
        save: "sha256:00".to_string(),
        serial: 1,
        started_unix_nanos: 0,
        stopped_unix_nanos: None,
        written: 0,
        latest: false,
    }
}

#[test]
fn a_stop_with_its_storage_gone_adds_no_more_than_a_millisecond() {
    let authority = Authority::new();
    let (behind, _) = persist::fixture::crowd::node();
    let behind: Arc<dyn XmipStorage> = Arc::new(behind);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bound");
    let server =
        StorageServer::start(behind, listener, &authority.identity("storage")).expect("served");
    let planned = Planned::Reaching {
        listed: vec![server.address().to_string()],
        identity: authority.identity("node"),
    };
    let reached = planned
        .open(&Linked::default(), &Tuning::default())
        .expect("reached");
    let mut joined = Joined::start(
        Arc::clone(reached.storage()),
        (row(), reached.placing()),
        (LONG, Duration::from_millis(1)),
    )
    .expect("started");
    joined.followed().revision().wait(0, LONG);
    assert!(joined.followed().written(), "a member");
    assert_eq!(reached.answers(), Ok(()));

    // Storage gone, and its client knowing it, as a node asking it does.
    server.stop();
    let deadline = Instant::now() + LONG;
    while reached.answers().is_ok() {
        assert!(Instant::now() < deadline, "never known gone");
        let _ = reached.storage().read_members();
    }

    let asked = Instant::now();
    let left = joined.stop(reached.answers());
    let took = asked.elapsed();
    eprintln!("a node's membership stopped with its Storage gone in {took:?}");
    assert_eq!(left, Some(UNANSWERED), "its stop record says why");
    assert!(took < Duration::from_millis(1), "{took:?}");
}
