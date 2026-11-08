//! What proving a browser's caller to the nodes costs Xmip itself
//! (ADR-0009, amendment 2026-11-02), held to the millisecond rule as its
//! own share — processor time, never a wait on the network or on another
//! program (`xcore::spent`).
//!
//! On the host: what the session's handshake thread and the threads that
//! hand it to the nodes spend binding it, recovering its transcript and
//! making and sending each `Vouch` (`SecureSession::own`), over one node
//! and over three asked at once — one session's own share either way. On
//! the node: what its check of one handshake spends — the possession proof
//! and the browser's chain and gate — for a browser it has not seen, each
//! round a new certificate. The fastest of each is held, since a machine
//! shared with other work only ever adds. The wall-clock time proving adds
//! to a session's start, beside a listener the nodes give no nonce for, is
//! said for information alone.

use std::io::Write;
use std::net::TcpListener;
use std::sync::Arc;
use std::time::{Duration, Instant};

use authenticate::x509::{Chain, Usage};
use serde_json::json;
use xcore::processor_time::ProcessorTime;
use xmip_core_runtime::fixture::Authority;
use xmip_core_runtime::plane::local::running_as;
use xmip_core_runtime::plane::vouched::{self, Relaying};
use xmip_core_runtime::plane::{Board, Grants, Listener, Remote, Role, held};
use xmip_core_runtime::secure_listener::SecureListener;

use super::browsing::{browsed, listening, reached};
use super::endpoint::{account_as, node};

/// How many of each are made: the fastest is what is held.
const ROUNDS: usize = 31;

/// The millisecond rule.
const BOUND: Duration = Duration::from_millis(1);

/// One browser's session at `listener`, its certificate from `authority`:
/// Xmip's own share of its start, and how long it took.
fn start(listener: &SecureListener, authority: &Authority) -> (Duration, Duration) {
    let began = Instant::now();
    let (caller, _, own, connected) = browsed(listener, authority, "alice");
    let took = began.elapsed();
    connected.join().expect("ended");
    held::release(caller);
    (own, took)
}

/// At a host following `nodes` relaying nodes: the fastest own share of a
/// session proven to each, and the fastest start at a listener they trust
/// and at one they do not.
fn hosted(nodes: usize) -> (Duration, Duration, Duration) {
    let trusted = Authority::new();
    let stranger = Authority::new();
    let (_, _, anchors) = trusted.pem("anchors");
    let account = running_as().expect("this process's account");
    let board = Arc::new(Board::default());
    let mut kept: Vec<(Listener, Remote)> = Vec::new();
    for _ in 0..nodes {
        let (listening_node, _, called) = node(&board, account_as(Role::Operator, &["CN=alice"]));
        let relaying = Relaying::new(vec![account.clone()], &anchors).expect("anchors");
        listening_node.relay(Arc::new(relaying));
        kept.push((listening_node, reached(&called)));
    }
    let (proving, plain) = (listening(&trusted), listening(&stranger));
    // A first browser at each, so each surface keeps its node's nonces for
    // the one and knows its node gives none for the other.
    start(&proving, &trusted);
    start(&plain, &stranger);
    let (mut own, mut proven, mut plainly) = (Duration::MAX, Duration::MAX, Duration::MAX);
    for _ in 0..ROUNDS {
        let (spent, took) = start(&proving, &trusted);
        (own, proven) = (own.min(spent), proven.min(took));
        plainly = plainly.min(start(&plain, &stranger).1);
    }
    (own, proven, plainly)
}

/// A browser's handshake, a new certificate of `authority`'s, with the web
/// host's `host` server, bound to one fresh nonce `relaying` issued
/// `through` for that server's leaf `listener`: the `Vouch` the node is
/// handed.
fn handshake(
    authority: &Authority,
    host: &Arc<tls::ServerConfig>,
    relaying: &Relaying,
    through: &str,
    listener: &[u8],
) -> serde_json::Value {
    let nonce = relaying.fresh.issue(through, listener, 1)[0].to_vec();
    let binding = tls::possession::binding(&[nonce.as_slice()]);
    let socket = TcpListener::bind("127.0.0.1:0").expect("bound");
    let address = socket.local_addr().expect("an address");
    let client = Arc::new(authority.identity("alice").client().expect("a client"));
    let (served, waiting) = std::sync::mpsc::channel::<()>();
    // Kept connected until the host has its handshake.
    let browser = std::thread::spawn(move || {
        let tcp = net::connect(address, Some(Duration::from_secs(5))).expect("connected");
        let mut stream = tls::client_with("localhost", tcp, client).expect("tls");
        stream.write_all(b"x").expect("said");
        let _ = waiting.recv();
    });
    // bounded: the browser connects on loopback on the thread above, or fails
    let (tcp, _) = socket.accept().expect("accepted");
    let within = Some(Duration::from_secs(5));
    tcp.set_read_timeout(within).expect("bounded");
    tcp.set_write_timeout(within).expect("bounded");
    let (_, recorded) =
        tls::possession::handshaken(tcp, Arc::clone(host), binding).expect("handshaken");
    let _ = served.send(());
    browser.join().expect("the browser");
    let transcript = recorded.transcript().expect("a transcript");
    json!({
        "transcript": codec::base64::encode(&transcript),
        "nonces": [codec::hex::encode(&nonce)],
    })
}

/// A node's check of one browser's handshake, the fastest of [`ROUNDS`]
/// each a browser it has not seen, and its two parts apart: the possession
/// proof, and the chain verified and run through the gate.
fn checked() -> (Duration, Duration, Duration) {
    let authority = Authority::new();
    let (certificate, key, anchors) = authority.pem("xmip-web-host");
    let identity =
        tls::Identity::from_pem(certificate.as_bytes(), key.as_bytes(), anchors.as_bytes())
            .expect("an identity");
    let host = Arc::new(tls::possession::proving(&identity).expect("a proving server"));
    let listener = Chain::from_pem(&certificate)
        .expect("a chain")
        .leaf()
        .to_vec();
    let through = running_as().expect("this process's account");
    let relaying = Relaying::new(vec![through.clone()], &anchors).expect("anchors");
    // The browser's role read off its certificate, as a node lists one.
    let grants = Grants::listed([&[], &["CN=operator@example.org".to_string()], &[]]);
    let (mut whole, mut proof, mut chain) = (Duration::MAX, Duration::MAX, Duration::MAX);
    for _ in 0..ROUNDS {
        let message = handshake(&authority, &host, &relaying, &through, &listener);
        let began = ProcessorTime::thread();
        let answer = vouched::vouched_for(&relaying, &through, &message, &grants);
        whole = whole.min(began.elapsed());
        assert!(answer["caller"].is_u64(), "vouched: {answer}");

        let message = handshake(&authority, &host, &relaying, &through, &listener);
        let transcript =
            codec::base64::decode(message["transcript"].as_str().expect("one")).expect("base64");
        let began = ProcessorTime::thread();
        let proved = tls::possession::proved(&transcript).expect("proved");
        proof = proof.min(began.elapsed());
        let began = ProcessorTime::thread();
        vouched::verified(&relaying, &proved.client_chain, Usage::ClientAuth).expect("verified");
        chain = chain.min(began.elapsed());
    }
    (whole, proof, chain)
}

#[test]
fn proving_a_browsers_caller_to_one_node_or_three_costs_under_a_millisecond_of_its_own() {
    ProcessorTime::calibrate();
    for nodes in [1, 3] {
        let (own, proven, plainly) = hosted(nodes);
        eprintln!(
            "a browser's session at a host following {nodes} node(s): the host's own share \
             {own:?}; started in {proven:?} against {plainly:?} unproven, {:?} added, said \
             only",
            proven.saturating_sub(plainly)
        );
        assert!(
            own < BOUND,
            "proving a browser's caller to {nodes} node(s) cost the host {own:?} of its own"
        );
    }
    let (whole, proof, chain) = checked();
    eprintln!(
        "a node's check of a browser it has not seen: {whole:?} of its own, the possession \
         proof {proof:?} and the chain and gate {chain:?} of it"
    );
    assert!(
        whole < BOUND,
        "a node's check of a browser's handshake cost it {whole:?} of its own"
    );
}
