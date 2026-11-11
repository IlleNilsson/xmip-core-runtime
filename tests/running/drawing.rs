//! What a running node received moving its published drawing over its
//! publisher's window (ADR-0052 and ADR-0018, amendments 2026-11-10).

use std::time::{Duration, Instant};

use net::fixture::unheld;
use observe::topology::window::Window;
use tcp::TcpTransport;
use xmip_core_runtime::running::Running;
use xmip_core_runtime::running::publication::ANY_PARTY;

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
    let path = written("moves", &node(&receive, &far_address));
    let running = Running::start(path_text(&path), linked(&path)).expect("the node starts");
    let (name, _) = first();
    let into = format!("party/sending/{ANY_PARTY}/{name}");
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
    let _ = std::fs::remove_dir_all(path.parent().expect("its directory"));
}
