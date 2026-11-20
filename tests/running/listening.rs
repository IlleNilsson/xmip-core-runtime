//! A node listens when it says it started (the owner, 2026-11-16, *Bind at
//! open*): each listening Receive Location binds its listener as its
//! transport is opened at startup phase 9, so a caller that connects the
//! moment the start returns is taken on its first connect, and a port that
//! is taken refuses the start there, naming the Location, the address and
//! the port. Until 2026-11-16 the listener was bound on the Location's
//! first receive, on its own thread after the start, and such a caller
//! could be refused (open problem 71).

use file::temporary::Folder;
use net::fixture::unheld;
use tcp::TcpTransport;
use transport::Transport;
use xmip_core_runtime::fixture::started;
use xmip_core_runtime::service::StartupPhase;

use super::node::{linked, node, path_text, written};

/// The technologies a test node's Receive Location listens with: raw TCP,
/// whose listener is kept ([`transport::kept::Kept`]), and HTTP, which
/// serves its callers' kept connections ([`transport::serving::Serving`]).
const LISTENING: [&str; 2] = ["tcp", "http"];

/// [`node`], its Receive Location on `scheme` at `receive`.
fn receiving_over(scheme: &str, receive: &str, far: &str) -> String {
    node(receive, far).replacen("address = \"tcp://", &format!("address = \"{scheme}://"), 1)
}

#[test]
fn a_caller_that_connects_the_moment_a_node_starts_is_taken_on_its_first_connect() {
    for scheme in LISTENING {
        let folder = Folder::new(&format!("runtime-running-listening-{scheme}"));
        let far = TcpTransport::loopback();
        let (listener, far_address) = far.bind().expect("the far end binds");
        let receive = unheld().to_string();
        let configuration = receiving_over(scheme, &receive, &far_address);
        let path = written(&folder, &configuration);
        let running = started(path_text(&path), || linked(&path)).expect("the node starts");

        // The moment the start returns: one send, its one connect never
        // asked again, since a refusal is answered at once (ADR-0044,
        // amendment 2026-11-14). Over raw TCP a bare connect would be a
        // Stream of its own.
        let sent = match scheme {
            "http" => http::HttpTransport::loopback()
                .send(&format!("http://{receive}/orders"), b"at once"),
            _ => TcpTransport::loopback().send(&receive, b"at once"),
        };
        sent.unwrap_or_else(|refused| panic!("{scheme}: refused at {receive}: {refused:?}"));
        let arrived = far
            .accept_one(&listener)
            .expect("it reaches the far end")
            .taken()
            .expect("read whole");
        assert_eq!(arrived.bytes, b"at once", "{scheme}");

        running.stop();
    }
}

#[test]
fn a_port_that_is_taken_refuses_the_start_at_phase_nine_naming_it() {
    for scheme in LISTENING {
        let folder = Folder::new(&format!("runtime-running-taken-{scheme}"));
        let holder = std::net::TcpListener::bind("127.0.0.1:0").expect("another holds a port");
        let taken = holder.local_addr().expect("its address").to_string();
        let port = taken.rsplit_once(':').expect("a port").1.to_string();
        let configuration = receiving_over(scheme, &taken, &unheld().to_string());
        let path = written(&folder, &configuration);

        let refused = started(path_text(&path), || linked(&path))
            .err()
            .expect("refused");

        assert_eq!(refused.phase, StartupPhase::AcceptWork, "{scheme}");
        let named = format!("at {taken}: port {port} is taken");
        assert!(
            refused
                .problems
                .iter()
                .any(|p| p.starts_with("the Location 'In': ") && p.contains(&named)),
            "{scheme}: {:?}",
            refused.problems
        );
        drop(holder);
    }
}
