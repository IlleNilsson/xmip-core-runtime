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
//! round a new certificate. The host's own share is measured by the
//! session, so it is held by the rule's processor-time half: within a
//! millisecond of this process's processor time across a plain wake
//! measured in the same rounds (`xcore::latency::worked_beside_a_plain_wake`).
//! The node's check waits on nothing, so it is held by the fastest of five
//! under the millisecond (`xcore::latency::spread`). Until 2026-11-15 the
//! fastest of all the rounds was held, which says nothing of the rest. The
//! wall-clock time proving adds to a session's start, beside a listener
//! the nodes give no nonce for, is said for information alone.

use std::io::Write;
use std::net::TcpListener;
use std::sync::Arc;
use std::time::{Duration, Instant};

use authenticate::x509::{Chain, Usage};
use serde_json::json;
use xcore::fastest::FIVE;
use xcore::latency::{PlainWake, spread, worked_beside_a_plain_wake};
use xcore::processor_time::ProcessorTime;
use xmip_core_runtime::fixture::Authority;
use xmip_core_runtime::plane::local::running_as;
use xmip_core_runtime::plane::vouched::{self, Relaying};
use xmip_core_runtime::plane::{Board, Grants, Listener, Remote, Role, held};
use xmip_core_runtime::secure_listener::SecureListener;

use super::browsing::{browsed, listening, reached};
use super::endpoint::{account_as, node};

/// How many of each are made: six fives.
const ROUNDS: usize = 6 * FIVE;

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

/// At a host following `nodes` relaying nodes: the own share of a session
/// proven to each, the fastest of five, and this process's processor time
/// across a plain wake beside each round; the starts at a listener they
/// trust and at one they do not, said.
fn hosted(nodes: usize) -> (Duration, Vec<Duration>) {
    let trusted = Authority::new();
    let stranger = Authority::new();
    let (_, _, anchors) = trusted.pem("anchors");
    let account = running_as().expect("this process's account");
    let board = Arc::new(Board::default());
    let mut kept: Vec<(Listener, Remote)> = Vec::new();
    for _ in 0..nodes {
        let (listening_node, _, called) = node(&board, account_as(Role::Operator, &["CN=alice"]));
        let clock = Arc::new(xcore::SystemClock);
        let relaying = Relaying::new(vec![account.clone()], &anchors, clock).expect("anchors");
        listening_node.relay(Arc::new(relaying));
        kept.push((listening_node, reached(&called)));
    }
    let (proving, plain) = (listening(&trusted), listening(&stranger));
    // A first browser at each, so each surface keeps its node's nonces for
    // the one and knows its node gives none for the other.
    start(&proving, &trusted);
    start(&plain, &stranger);
    let plain_wake = PlainWake::start();
    let (mut own, mut proven, mut plainly, mut idle) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for _ in 0..ROUNDS {
        let (spent, took) = start(&proving, &trusted);
        own.push(spent);
        proven.push(took);
        plainly.push(start(&plain, &stranger).1);
        idle.push(plain_wake.round().1);
    }
    let following = format!("a browser's session at a host following {nodes} node(s)");
    let proven = spread(&format!("{following}, started"), proven).fastest_of_five;
    let plainly = spread(&format!("{following}, started unproven"), plainly).fastest_of_five;
    println!(
        "{following}: {:?} added by proving, the fastest of five each, said only",
        proven.saturating_sub(plainly)
    );
    let own = spread(&format!("{following}, the host's own share"), own);
    (own.fastest_of_five, idle)
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

/// A node's check of one browser's handshake over [`ROUNDS`], each a
/// browser it has not seen, the processor time its thread ran, the fastest
/// of five; its two parts apart, said: the possession proof, and the chain
/// verified and run through the gate.
fn checked() -> Duration {
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
    let clock = Arc::new(xcore::SystemClock);
    let relaying = Relaying::new(vec![through.clone()], &anchors, clock).expect("anchors");
    // The browser's role read off its certificate, as a node lists one.
    let grants = Grants::listed([&[], &["CN=operator@example.org".to_string()], &[]]);
    let (mut whole, mut proof, mut chain) = (Vec::new(), Vec::new(), Vec::new());
    for _ in 0..ROUNDS {
        let message = handshake(&authority, &host, &relaying, &through, &listener);
        let began = ProcessorTime::thread();
        let answer = vouched::vouched_for(&relaying, &through, &message, &grants);
        whole.push(began.elapsed());
        assert!(answer["caller"].is_u64(), "vouched: {answer}");

        let message = handshake(&authority, &host, &relaying, &through, &listener);
        let transcript =
            codec::base64::decode(message["transcript"].as_str().expect("one")).expect("base64");
        let began = ProcessorTime::thread();
        let proved = tls::possession::proved(&transcript).expect("proved");
        proof.push(began.elapsed());
        let began = ProcessorTime::thread();
        vouched::verified(&relaying, &proved.client_chain, Usage::ClientAuth).expect("verified");
        chain.push(began.elapsed());
    }
    let checking = "a node's check of a browser it has not seen";
    let _ = spread(&format!("{checking}: the possession proof"), proof);
    let _ = spread(&format!("{checking}: the chain and gate"), chain);
    spread(&format!("{checking}, of its own"), whole).fastest_of_five
}

#[test]
fn proving_a_browsers_caller_to_one_node_or_three_costs_under_a_millisecond_of_its_own() {
    ProcessorTime::calibrate();
    for nodes in [1, 3] {
        let (own, idle) = hosted(nodes);
        worked_beside_a_plain_wake(
            &format!("proving a browser's caller to {nodes} node(s): the host's own share"),
            own,
            idle,
        );
    }
    let whole = checked();
    assert!(
        whole < BOUND,
        "a node's check of a browser's handshake cost it {whole:?} of its own, the fastest of \
         five"
    );
}
