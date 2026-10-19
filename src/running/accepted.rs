//! A node that receives what its configuration accepts: a Receive Location
//! terminating TLS with the node's `receive` certificate and taking a named
//! Party alone (ADR-0019 clause 1; ADR-0033, amendment 2026-10-19). The
//! gates are stand-ins, each the smallest thing that is its gate — the
//! certificate's subject claimed as `mutual-tls`, proven, and a policy
//! admitting at the Locations it was set up from — so what is proved here
//! is the node's: the guard handed to the transport, the Party resolved
//! through `[[parties]]`, `accept.party` narrowing the gate, and the
//! receive policy set up from the Locations the node starts.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use authorize::{Action, Attempt, Authorizer, Decision};
use context::IdentityFacts;
use context::property::TLS_PEER_SUBJECT;
use identify::{IdentifyError, Presented, StreamArrival, TransportIdentifier};
use net::fixture::unheld;
use tcp::TcpTransport;
use xcore::{Layer, Mechanism, mechanism};

use super::Running;
use crate::fixture::{Always, Authority};
use crate::linked::{Linked, LinkedTransport};
use crate::receiving::ReceiveGate;

/// Claims the subject the handshake proved, as `mutual-tls`.
struct Subject;

impl TransportIdentifier for Subject {
    fn mechanism(&self) -> Mechanism {
        mechanism::mutual_tls()
    }

    fn identify(&self, arrival: &StreamArrival<'_>) -> Result<Option<Presented>, IdentifyError> {
        Ok(arrival
            .property(TLS_PEER_SUBJECT)
            .map(|subject| Presented::passed(mechanism::mutual_tls(), subject)))
    }
}

/// Admits a receive at the Locations it was set up from, and has no
/// opinion anywhere else.
struct Admitting(Vec<String>);

impl Authorizer for Admitting {
    fn name(&self) -> &str {
        "admitting"
    }

    fn layer(&self) -> Layer {
        Layer::Transport
    }

    fn decide(&self, _identity: &IdentityFacts, attempt: &Attempt) -> Option<Decision> {
        (attempt.action == Action::Receive && self.0.contains(&attempt.artifact))
            .then_some(Decision::Allowed)
    }
}

fn admitting(gates: &[ReceiveGate]) -> Box<dyn Authorizer> {
    Box::new(Admitting(
        gates.iter().map(|gate| gate.location.clone()).collect(),
    ))
}

/// A node at `receive`, its one Receive Location terminating TLS, taking
/// `mutual-tls` from the Party `first` alone; `provision` after it.
fn node(receive: &str, provision: &str) -> String {
    let cluster = configure::fixture::test_cluster();
    format!(
        r#"[service]
name = "xmip"
cluster_name = "{cluster}"
node_name = "{node}"

[[parties]]
name = "first"
identities = ["CN=first.example"]

[[parties]]
name = "second"
identities = ["CN=second.example"]

[[receive_locations]]
name = "In"
start = true
transport = "xmip-core-transport-tcp"
address = "{receive}"
[receive_locations.settings]
timeout = "100ms"
tls = true
[receive_locations.accept]
mechanism = ["mutual-tls"]
party = ["first"]

{provision}"#,
        cluster = cluster.name,
        node = cluster.node(0).name,
    )
}

/// The node's configuration written in `authority`'s directory, with the
/// node's `receive` certificate and the authority as the anchors a Party's
/// must reach.
fn written(authority: &Authority, receive: &str) -> PathBuf {
    let (certificate, key, anchors) = authority.pem("localhost");
    for (name, text) in [
        ("receive.pem", &certificate),
        ("receive.key", &key),
        ("parties.pem", &anchors),
    ] {
        std::fs::write(authority.directory.join(name), text).expect("written");
    }
    let provision = "[provision.receive]\ncertificate = \"receive.pem\"\nkey = \"receive.key\"\n\
                     anchors = \"parties.pem\"\n";
    let path = authority.directory.join("node.toml");
    std::fs::write(&path, node(receive, provision)).expect("written");
    path
}

/// What the tests' program links: tcp, the stand-in gates, and Xmip
/// Storage in memory.
fn linked() -> Linked {
    Linked {
        transports: vec![LinkedTransport::of::<TcpTransport>()],
        transport_identifiers: vec![Box::new(Subject)],
        authenticators: vec![Box::new(Always(
            mechanism::mutual_tls(),
            context::Verified::Proven,
        ))],
        receive_policies: vec![admitting],
        storage: Some(Arc::clone(crate::ledger::in_memory())),
        ..Linked::default()
    }
}

/// `client` sends a Stream to `address` in TLS, connecting again while the
/// Location has not yet bound, and reads to the node's close.
fn send(address: &str, client: tls::ClientConfig) {
    let deadline = Instant::now() + Duration::from_secs(5);
    let tcp = loop {
        match transport::socket::connect_tcp(address, Some(Duration::from_secs(5))) {
            Ok(tcp) => break tcp,
            Err(_) if Instant::now() < deadline => std::thread::yield_now(),
            Err(failed) => panic!("the node took nothing at {address}: {failed:?}"),
        }
    };
    let Ok(mut stream) = tls::client_with("localhost", tcp, Arc::new(client)) else {
        return;
    };
    let _ = stream.write_all(b"<order/>");
    stream.conn.send_close_notify();
    let _ = stream.flush();
    let _ = stream.read_to_end(&mut Vec::new());
}

#[test]
fn a_named_party_is_received_over_tls_and_any_other_refused_at_authentication() {
    let authority = Authority::new();
    let receive = unheld().to_string();
    let path = written(&authority, &receive);
    let running = Running::start(path.to_str().expect("UTF-8"), linked()).expect("the node starts");

    let registered: Vec<&str> = running
        .capabilities()
        .capabilities()
        .map(|c| c.capability.as_str())
        .collect();
    assert!(
        registered.contains(&"authorize:admitting"),
        "{registered:?}"
    );

    for name in ["first.example", "second.example", "third.example"] {
        let client = authority.identity(name).client().expect("a client");
        send(&receive, client);
    }
    // Another authority's client is refused in the handshake, before any
    // gate: never received.
    let stranger = Authority::new().identity("first.example").client();
    send(&receive, stranger.expect("a client"));

    let outcomes = running.stop();
    assert_eq!(outcomes.received, 3, "{outcomes:?}");
    assert_eq!(outcomes.unroutable, 1, "the Party's, kept: {outcomes:?}");
    assert_eq!(outcomes.refused, 2, "another Party and none: {outcomes:?}");
}

#[test]
fn a_location_terminating_tls_on_a_node_with_no_receive_certificate_is_refused() {
    let authority = Authority::new();
    let path = authority.directory.join("node.toml");
    std::fs::write(&path, node(&unheld().to_string(), "")).expect("written");

    let refused = Running::start(path.to_str().expect("UTF-8"), linked())
        .err()
        .expect("refused");

    let said = refused.problems.join("\n");
    assert!(said.contains(tcp::NO_RECEIVE_CERTIFICATE), "{said}");
}
