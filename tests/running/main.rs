//! A node running (`xmip_core_runtime::running`), started as a program
//! starts it, over the transports and test Storage node its tests link
//! (`node.rs`, the timing program's too): a Location held to its
//! technology's declaration as the node starts, every transport given its
//! node's location, a clean stop that lets its listener go, what the
//! program was not built with refused at start, a library module refused
//! or opened once, and a paused Subscription holding and sending in order
//! on its resume. How long a node takes to carry a Message is the
//! module's timing program's (`tests/measured`).

mod node;

#[cfg(feature = "dynamic-loading")]
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use net::fixture::unheld;
use observe::Health;
use tcp::TcpTransport;
#[cfg(feature = "dynamic-loading")]
use xmip_core_runtime::host::HostService;
use xmip_core_runtime::running::Running;
use xmip_core_runtime::service::StartupPhase;

use node::{
    count_anew, deliver, first, given, linked, node, node_sending, path_text, test_storage, written,
};

#[test]
fn a_location_is_held_to_its_technologys_declaration_as_the_node_starts() {
    let unsound = node(&unheld().to_string(), &unheld().to_string())
        .replace("timeout = \"100ms\"", "timeout = 5\ncolor = \"lime\"");
    let path = written("declared", &unsound);

    let refused = Running::start(path_text(&path), linked(&path))
        .err()
        .expect("refused");

    assert_eq!(refused.phase, StartupPhase::ValidateStartup);
    assert_eq!(refused.problems.len(), 2, "{:?}", refused.problems);
    for setting in ["\"timeout\"", "\"color\""] {
        assert!(
            refused
                .problems
                .iter()
                .any(|p| p.contains(setting) && p.contains("xmip-core-transport-tcp")),
            "{setting}: {:?}",
            refused.problems
        );
    }

    // Once a node has loaded tcp, a surface validating in this process
    // holds a tcp Location to the same declaration (xmip_validate_v1).
    let sound = written(
        "declared-sound",
        &node(&unheld().to_string(), &unheld().to_string()),
    );
    Running::start(path_text(&sound), linked(&sound))
        .expect("the node starts")
        .stop();
    let problems = xmip_core_runtime::start::validate(&unsound);
    assert!(
        problems.iter().any(|p| p.contains("\"color\"")),
        "{problems:?}"
    );
    for written in [path, sound] {
        let _ = std::fs::remove_dir_all(written.parent().expect("its directory"));
    }
}

#[test]
fn every_transport_is_given_its_nodes_location_as_it_is_built() {
    let path = written("given", &node(&unheld().to_string(), &unheld().to_string()));
    count_anew();
    let running = Running::start(path_text(&path), linked(&path)).expect("the node starts");
    let given = given();
    assert_eq!(
        given.len(),
        2,
        "the Receive and the Send Location: {given:?}"
    );
    assert!(
        given.iter().all(|node| *node == running.location()),
        "{given:?}"
    );
    assert_eq!(running.location(), first().1);
    running.stop();
    let _ = std::fs::remove_dir_all(path.parent().expect("its directory"));
}

#[test]
fn a_node_stops_cleanly_and_lets_its_listener_go() {
    let far = TcpTransport::loopback();
    let (listener, far_address) = far.bind().expect("the far end binds");
    let receive = unheld().to_string();
    let path = written("stops", &node(&receive, &far_address));
    let running = Running::start(path_text(&path), linked(&path)).expect("the node starts");
    deliver(&TcpTransport::loopback(), &receive, b"before the stop");
    far.accept_one(&listener)
        .expect("it reaches the far end")
        .taken()
        .expect("read whole");

    let health = running.snapshot().health(&first().1);
    assert!(
        !health.is_empty() && health.iter().all(|record| record.health == Health::Fine),
        "{health:?}"
    );

    let stopping = Instant::now();
    let outcomes = running.stop();
    let took = stopping.elapsed();

    assert_eq!(outcomes.sent, 1);
    // Bounded by the Location's own wait, 100 ms, not by a timeout of
    // the runtime's.
    assert!(took < Duration::from_secs(2), "stopping took {took:?}");
    let address: std::net::SocketAddr = receive.parse().expect("an address");
    assert!(
        std::net::TcpStream::connect_timeout(&address, Duration::from_millis(500)).is_err(),
        "the listener is let go"
    );

    // Dropped without a stop, a node stops all the same.
    let again = Running::start(path_text(&path), linked(&path)).expect("starts again");
    deliver(&TcpTransport::loopback(), &receive, b"after");
    far.accept_one(&listener)
        .expect("it reaches the far end")
        .taken()
        .expect("read whole");
    drop(again);
    assert!(std::net::TcpStream::connect_timeout(&address, Duration::from_millis(500)).is_err());
    let _ = std::fs::remove_dir_all(path.parent().expect("its directory"));
}

#[test]
fn what_the_program_was_not_built_with_refuses_the_node_at_start() {
    let base = node(&unheld().to_string(), &unheld().to_string());
    let cases = [
        (
            base.replacen("address = \"tcp://", "address = \"sftp://", 1),
            "and this node carries no transport for sftp://; it carries tcp, http, https",
        ),
        (
            base.replace("[\"circumstance\"]", "[\"mutual-tls\"]"),
            "accepts 'mutual-tls', and no authenticator this node was built with verifies it",
        ),
        (
            base.replace(
                "address = \"tcp://127",
                "contract = \"xmip-core-contract-json\"\naddress = \"tcp://127",
            ),
            "holds no Stream to a contract at arrival yet",
        ),
    ];

    for (configuration, reason) in cases {
        let path = written("unlinked", &configuration);
        let refused = Running::start(path_text(&path), linked(&path))
            .err()
            .expect("refused");
        assert_eq!(refused.phase, StartupPhase::ValidateStartup);
        assert!(
            refused.problems.iter().any(|p| p.contains(reason)),
            "{reason}: {:?}",
            refused.problems
        );
        let _ = std::fs::remove_dir_all(path.parent().expect("its directory"));
    }

    // ADR-0066 clause 1: a filter naming what no route technology this
    // node was built with reads is refused now, not at the first Message.
    let directory = written(
        "unread",
        &base.replace("xmip.transport.mechanism", "party:sender"),
    );
    let refused = Running::start(path_text(&directory), linked(&directory))
        .err()
        .expect("refused");
    assert_eq!(refused.phase, StartupPhase::ValidateStartup);
    assert!(
        refused.problems[0].contains("no route technology"),
        "{refused}"
    );
    let _ = std::fs::remove_dir_all(directory.parent().expect("its directory"));
}

/// The directories are named for the process, and Windows gives a
/// process id again: what an earlier process of the same id left —
/// a ledger sealed under a key-encryption key that ended with it — is
/// not what the next one's test Storage node opens.
#[test]
fn what_an_earlier_process_of_the_same_id_left_is_gone() {
    let earlier = written("left", "");
    let place = earlier.parent().expect("its directory").join("ledger");
    drop(test_storage(&place));

    let path = written("left", "");

    drop(test_storage(&place));
    let _ = std::fs::remove_dir_all(path.parent().expect("its directory"));
}

const LIBRARY_MODULE: &str = "\n[[modules]]\nname = \"test-module\"\nstart = true\n\
    [modules.manifest]\noffline = true\n\
    [modules.manifest.identity]\nname = \"xmip-core-test-module\"\nversion = \"0.1.0\"\n\
    [[modules.manifest.capabilities]]\ncapability = \"contract\"\n\
    execution_host = \"c-abi\"\ntrusted_required = false\n\
    [modules.manifest.entrypoint]\n";

#[cfg(not(feature = "dynamic-loading"))]
#[test]
fn a_library_module_is_refused_where_the_runtime_opens_none() {
    let configuration = format!(
        "{}{LIBRARY_MODULE}library_path = \"xmip_core_test_module.dll\"\n",
        node(&unheld().to_string(), &unheld().to_string())
    );
    let path = written("library", &configuration);

    let refused = Running::start(path_text(&path), linked(&path))
        .err()
        .expect("refused");

    assert_eq!(refused.phase, StartupPhase::LoadModules);
    assert!(refused.problems[0].contains("dynamic-loading"), "{refused}");
    let _ = std::fs::remove_dir_all(path.parent().expect("its directory"));
}

/// ADR-0057: a Module the configuration starts is opened from its
/// library once, through the C ABI, held while the node runs and let go
/// when it stops. `test/core/module` builds it, or
/// `XMIP_MODULE_LIBRARY` names one.
#[cfg(feature = "dynamic-loading")]
#[test]
fn a_library_module_is_opened_once_and_let_go_at_the_stop() {
    let library = std::env::var("XMIP_MODULE_LIBRARY").map_or_else(
        |_| {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../../test/core/module/target/debug")
                .join(if cfg!(windows) {
                    "xmip_core_test_module.dll"
                } else if cfg!(target_os = "macos") {
                    "libxmip_core_test_module.dylib"
                } else {
                    "libxmip_core_test_module.so"
                })
        },
        PathBuf::from,
    );
    assert!(
        library.exists(),
        "build the module first: {}",
        library.display()
    );
    let configuration = format!(
        "{}{LIBRARY_MODULE}library_path = '{}'\n",
        node(&unheld().to_string(), &unheld().to_string()),
        library.display()
    );
    let path = written("opened", &configuration);

    let running = Running::start(path_text(&path), linked(&path)).expect("the node starts");

    let contract = running
        .capabilities()
        .get("contract")
        .expect("registered once");
    assert_eq!(contract.module, "xmip-core-test-module");
    assert_eq!(
        contract.load,
        xmip_core_runtime::capability_registry::Load::Library(library.clone())
    );
    assert!(running.host_services().iter().all(HostService::in_process));
    running.stop();
    let _ = std::fs::remove_dir_all(path.parent().expect("its directory"));
}

#[test]
fn a_paused_subscription_holds_at_the_node_and_its_resume_sends_what_it_held_in_order() {
    let far = TcpTransport::loopback();
    let (listener, far_address) = far.bind().expect("the far end binds");
    let receive = unheld().to_string();
    // In order: a Send Port naming a set keyed by itself keeps it, one
    // Message at a time (`xmip_core_runtime::sequence`).
    let sequential = "correlation = \"InOrder\"";
    let configured = format!(
        "{}\n[[correlations]]\nname = \"InOrder\"\nkeys = [\"send-port\"]\n",
        node_sending(&receive, &far_address, sequential)
    );
    let path = written("paused", &configured);
    let running = Running::start(path_text(&path), linked(&path)).expect("the node starts");
    deliver(&TcpTransport::loopback(), &receive, b"before the pause");
    far.accept_one(&listener)
        .expect("it reaches the far end")
        .taken()
        .expect("read whole");

    let pickup = running.pickup();
    assert_eq!(pickup.node(), first().1);
    let standing = &pickup.standing()[0];
    assert_eq!(standing.name, "onward");
    assert_eq!(standing.application, "Loopback");
    assert!(standing.file.ends_with("node.xmip"));
    assert!(
        standing
            .configuration
            .starts_with("[[xmip_applications.subscriptions]]")
    );
    pickup
        .act("onward", observe::Act::Pause, "ilian")
        .expect("paused");
    // Each held before the next is sent: TCP's connections arrive in no
    // order of their own (`Arrivals::Unordered`), so the order held is
    // the order the receive cycles finished.
    for n in 1..=3 {
        deliver(
            &TcpTransport::loopback(),
            &receive,
            format!("held {n}").as_bytes(),
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        while pickup.standing()[0].held < n && Instant::now() < deadline {
            std::thread::yield_now();
        }
        assert_eq!(pickup.standing()[0].held, n, "held, not sent");
    }

    pickup
        .act("onward", observe::Act::Resume, "ilian")
        .expect("resumed");
    for n in 1..=3 {
        let arrived = far
            .accept_one(&listener)
            .expect("it reaches the far end")
            .taken()
            .expect("read whole");
        assert_eq!(
            arrived.bytes,
            format!("held {n}").as_bytes(),
            "oldest first"
        );
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while pickup.standing()[0].held > 0 && Instant::now() < deadline {
        std::thread::yield_now();
    }
    let outcomes = running.stop();
    assert_eq!((outcomes.held, outcomes.sent), (3, 4), "{outcomes:?}");
    let _ = std::fs::remove_dir_all(path.parent().expect("its directory"));
}
