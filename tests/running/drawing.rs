//! What a running node received moving its published drawing over its
//! publisher's window (ADR-0052 and ADR-0018, amendments 2026-11-10), and
//! what it publishes it declares (amendment 2026-11-25).

use std::time::{Duration, Instant};

use file::temporary::Folder;
use net::fixture::unheld;
use node::{Capability, NodeRole};
use observe::Relation;
use observe::topology::link_id;
use observe::topology::window::Window;
use tcp::TcpTransport;
use xmip_core_runtime::fixture::started;
use xmip_core_runtime::running::Running;

use crate::node::{deliver, first, linked, node, path_text, written};

/// The owner, 2026-11-10: motion follows traffic. What a running node
/// received moves its own drawing, stated by the window its publisher keeps
/// and hands `Running::publication` every time (ADR-0018, amendment
/// 2026-11-10): the Party sending in, and the node.
#[test]
fn what_a_running_node_received_moves_its_published_drawing_through_its_publishers_window() {
    let far = TcpTransport::loopback();
    let (listener, far_address) = far.bind().expect("the far end binds");
    let receive = unheld().to_string();
    let folder = Folder::new("runtime-running-moves");
    let path = written(&folder, &node(&receive, &far_address));
    let running = started(path_text(&path), || linked(&path)).expect("the node starts");
    let (name, _) = first();
    let into = link_id(
        &format!("party/sending/node/{name}"),
        &format!("node/{name}/receive"),
        Relation::Traffic,
    );
    let mut window = Window::new();
    let drawn = |window: &mut Window| {
        running
            .publication("the running tests", window)
            .topology
            .expect("the node is drawn")
    };
    let still = drawn(&mut window);
    assert!(
        still
            .links
            .iter()
            .all(|link| link.rate.abs() < f64::EPSILON),
        "nothing moved yet: {still:?}"
    );

    deliver(&TcpTransport::loopback(), &receive, b"moved");
    far.accept_one(&listener)
        .expect("it reaches the far end")
        .taken()
        .expect("read whole");
    // The receive cycle counts what it carried as it ends, beside the send:
    // published again until it has.
    let deadline = Instant::now() + Duration::from_secs(5);
    let moved = loop {
        let drawing = drawn(&mut window);
        let rate = drawing.links.iter().find(|link| link.id == into);
        if rate.is_some_and(|link| link.rate > 0.0) {
            break drawing;
        }
        assert!(Instant::now() < deadline, "{into} never moved: {drawing:?}");
        std::thread::yield_now();
    };
    let at = format!("node/{name}");
    assert!(
        moved
            .nodes
            .iter()
            .any(|node| node.id == at && node.activity > 0.0),
        "{moved:?}"
    );
    running.stop();
}

/// What `running` says it declares at `<node>/capability`, read back as
/// every surface reads it, and the evidence it said it in.
fn published(running: &Running) -> (Capability, String) {
    let snapshot = running.snapshot();
    let scope = observe::capability::scope(&running.location());
    let evidence = snapshot
        .health(&scope)
        .into_iter()
        .find(|record| record.scope == scope)
        .expect("it declares")
        .evidence;
    let (_, declared) = observe::capability::declared(&scope, &evidence).expect("a capability");
    (declared.expect("read"), evidence)
}

/// ADR-0018, amendment 2026-11-11: a node processes where it routes. One
/// that starts no Receive Location and runs no Work Process publishes no
/// Subscription, though its slice carries one; and it declares what its
/// slice declares, sending, never what it serves (amendment 2026-11-25).
#[test]
fn a_node_that_starts_no_receive_location_declares_no_processing_and_publishes_no_subscription() {
    let receive = unheld().to_string();
    let far = unheld().to_string();
    let configuration = format!(
        "roles = \"sending\"\n{}",
        node(&receive, &far).replacen("start = true", "start = false", 1)
    );
    let folder = Folder::new("runtime-running-sends-only");
    let path = written(&folder, &configuration);
    let running = started(path_text(&path), || linked(&path)).expect("the node starts");

    assert_eq!(
        running.snapshot().subscriptions().count(),
        0,
        "none published"
    );
    let (declared, evidence) = published(&running);
    assert_eq!(declared, Capability::of(&[NodeRole::Sending]), "{evidence}");
    assert!(!declared.can(node::Stage::Process), "{evidence}");

    // Its pickup routes by none (`Pickup::routing_none`), which section 14
    // lists as none and refuses an act on in words (the operate library's
    // `ffi::subscription`):
    // the publication, section 14 and an order agree.
    assert!(running.pickup().standing().is_empty(), "it takes none up");
    let refused = running
        .pickup()
        .act("onward", observe::Act::Pause, "ilian")
        .expect_err("it routes by none");
    assert!(
        refused.starts_with("REFUSED") && refused.contains("routes by no Subscription"),
        "{refused}"
    );
    running.stop();
}

/// ADR-0018, amendment 2026-11-25 (the owner: "Also the DS2 standby node is
/// not shown"): a node's capability record says the roles its slice
/// declares, as its membership row does, and never the stages it serves.
/// A node keeping Xmip Storage says storage, though storage serves no
/// stage; one whose slice declares no role says none, though it receives,
/// routes and sends. Until then the record said the stages served, so every
/// Storage node and every operational node published *declares no role*.
#[test]
fn a_nodes_capability_record_says_the_roles_its_slice_declares_never_the_stages_it_serves() {
    let configuration = node(&unheld().to_string(), &unheld().to_string());
    for (roles, declares) in [
        (
            "roles = \"executing, storage\"\n",
            vec![NodeRole::Executing, NodeRole::Storage],
        ),
        ("", Vec::new()),
    ] {
        let folder = Folder::new("runtime-running-declares");
        let path = written(&folder, &format!("{roles}{configuration}"));
        let running = started(path_text(&path), || linked(&path)).expect("the node starts");
        let (declared, evidence) = published(&running);
        assert_eq!(declared, Capability::of(&declares), "{roles}: {evidence}");
        running.stop();
    }
}
