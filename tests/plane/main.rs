//! The operate plane end to end over loopback (ADR-0014, amendment
//! 2026-10-12): a node's operate listener and a remote surface, each with
//! a certificate from one test authority, over gRPC inside Xmip's mutual
//! TLS — an act gated by the caller's role and audited, a stranger refused,
//! and a node lost and found again on the recovery loop; each caller its
//! own role (`granted`), and the listener held to its limits (`bounded`);
//! and a cluster's view gathered from members followed over theirs
//! (`gathered`), which a monitoring node gathers and answers as `Cluster`
//! (`clustered`). How fast a follower is told, a read is answered and a
//! view assembled is the module's timing program's (`tests/measured`,
//! `doc/governance/rust-style.md` section 5c).

mod bounded;
mod browsing;
mod certified;
mod clustered;
mod endpoint;
mod gathered;
mod granted;
mod local;
mod relayed;
mod revoked;

use std::net::TcpListener;
use std::sync::Arc;
use std::time::{Duration, Instant};

use certified::{node, remote};
use endpoint::listing;
use xaudit::program_audit::ProgramAudit;
use xmip_core_runtime::fixture::{Authority, absent_node};
use xmip_core_runtime::plane::{Board, Grants, Listener, Outcome, Role};

/// The surface `remote` opens, listed under `role`.
fn surface_as(role: Role) -> Grants {
    listing(role, &["CN=surface"])
}

#[test]
fn an_act_is_the_certificates_and_is_refused_to_an_observer() {
    let authority = Authority::new();
    let board = Arc::new(Board::default());
    let (listener, audit) = node(&authority, &board, surface_as(Role::Observer));
    let surface = remote(&authority, &listener);

    let (outcome, said) = surface
        .act(0, &absent_node(), ("subscription", "orders", "pause"))
        .expect("it answers");
    assert_eq!(outcome, Outcome::Denied);
    assert!(
        // Decided by its method before the call is read (ADR-0009, amendment
        // 2026-10-29), so the refusal names the method, not the Subscription.
        said.starts_with("REFUSED. CN=surface may not act on this node"),
        "{said}"
    );
    let file = audit.file().expect("an audit file");
    let kept = std::fs::read_to_string(file).expect("the audit file");
    assert!(
        kept.contains("CN=surface") && kept.contains("Observer"),
        "{kept}"
    );

    let (outcome, said) = surface
        .act(0, &absent_node(), ("subscription", "orders", "remove"))
        .expect("it answers");
    // Who may ask is decided first: an Observer is told so, whatever it asks.
    assert_eq!(outcome, Outcome::Denied, "{said}");
}

#[test]
fn an_operator_acts_as_the_certificate_and_the_node_answers() {
    let authority = Authority::new();
    let board = Arc::new(Board::default());
    let (listener, _) = node(&authority, &board, surface_as(Role::Operator));
    let surface = remote(&authority, &listener);

    let (outcome, said) = surface
        .act(0, &absent_node(), ("message", "j1", "retry"))
        .expect("it answers");
    assert_eq!(outcome, Outcome::Refused);
    // A listener no node keeps a door on carries no act to another node.
    let refused = format!("REFUSED: no node at {} runs in this process", absent_node());
    assert!(said.starts_with(&refused), "{said}");
    assert!(said.contains("declares no operational role"), "{said}");
}

#[test]
fn a_surface_whose_certificate_the_node_does_not_trust_is_refused() {
    let ours = Authority::new();
    let theirs = Authority::new();
    let board = Arc::new(Board::default());
    let (listener, _) = node(&ours, &board, surface_as(Role::Observer));
    let stranger = remote(&theirs, &listener);

    let refused = stranger.publication().expect_err("refused");
    assert!(refused.contains("unreachable"), "{refused}");
}

#[test]
fn a_node_lost_is_told_and_found_again_on_the_recovery_loop() {
    let authority = Authority::new();
    let board = Arc::new(Board::default());
    board.post("source = \"one\"\n".to_string());
    let (mut listener, _) = node(&authority, &board, surface_as(Role::Observer));
    let port = listener
        .address()
        .parse::<std::net::SocketAddr>()
        .expect("host:port")
        .port();
    let surface = remote(&authority, &listener);

    let reached = surface.wait(0, Duration::from_secs(5));
    assert!(reached.reachable);

    let stopped = Instant::now();
    listener.stop();
    let lost = surface.wait(reached.told, Duration::from_secs(5));
    assert!(!lost.reachable, "told it is lost");
    assert!(
        stopped.elapsed() < Duration::from_secs(1),
        "{:?}",
        stopped.elapsed()
    );
    let unanswered = surface.publication().expect_err("not answered as current");
    assert!(unanswered.contains("unreachable"), "{unanswered}");

    let again = TcpListener::bind(("127.0.0.1", port)).expect("the same port");
    let audit = ProgramAudit::new("plane-test", Some(&authority.directory));
    let _back = Listener::start(
        again,
        &authority.identity("node"),
        Arc::clone(&board) as Arc<dyn xmip_core_runtime::plane::Published>,
        surface_as(Role::Observer),
        &audit,
    )
    .expect("it serves again");
    let mut found = lost;
    let deadline = Instant::now() + Duration::from_secs(5);
    while !found.reachable && Instant::now() < deadline {
        found = surface.wait(found.told, Duration::from_secs(1));
    }
    assert!(found.reachable, "{}", found.reason);
    assert!(surface.publication().is_ok());
}
