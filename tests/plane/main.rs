//! The operate plane end to end over loopback (ADR-0014, amendment
//! 2026-10-12): a node's operate listener and a remote surface, each with
//! a certificate from one test authority, over gRPC inside Xmip's mutual
//! TLS — the publication read, a follower told as it advances and how
//! fast, an act gated by the caller's role and audited, a stranger
//! refused, and a node lost and found again on the recovery loop.

mod local;

use std::net::TcpListener;
use std::sync::Arc;
use std::time::{Duration, Instant};

use xaudit::program_audit::ProgramAudit;
use xmip_core_runtime::fixture::{Authority, absent_node};
use xmip_core_runtime::plane::{Board, Listener, Outcome, Remote, Role};

/// A node's listener over `board` on a loopback port, holding `role`.
fn node(authority: &Authority, board: &Arc<Board>, role: Option<Role>) -> (Listener, ProgramAudit) {
    let audit = ProgramAudit::new("plane-test", Some(&authority.directory));
    let listener = TcpListener::bind("127.0.0.1:0").expect("an operate listener");
    let served = Listener::start(
        listener,
        &authority.identity("node"),
        Arc::clone(board) as Arc<dyn xmip_core_runtime::plane::Published>,
        role,
        &audit,
    )
    .expect("it serves");
    (served, audit)
}

fn remote(authority: &Authority, listener: &Listener) -> Remote {
    let address = listener.address();
    Remote::retrying(
        &address,
        &authority.identity("surface"),
        vec![Duration::from_millis(50)],
    )
    .expect("a remote")
}

#[test]
fn a_surface_reads_the_publication_and_is_told_as_it_advances() {
    let authority = Authority::new();
    let board = Arc::new(Board::default());
    board.post("source = \"one\"\n".to_string());
    let (listener, _) = node(&authority, &board, None);
    let surface = remote(&authority, &listener);

    assert_eq!(
        surface.publication().expect("it answers"),
        (1, "source = \"one\"\n".to_string())
    );

    let reached = surface.wait(0, Duration::from_secs(5));
    assert!(reached.reachable, "{}", reached.reason);
    assert_eq!(reached.revision, 1);

    // The millisecond rule: a follow notification over loopback, measured
    // from the post to the follower told, over many rounds.
    let mut seen = reached.told;
    let mut took = Vec::new();
    for round in 2..=201u64 {
        let posted = Instant::now();
        board.post(format!("source = \"{round}\"\n"));
        let told = surface.wait(seen, Duration::from_secs(5));
        took.push(posted.elapsed());
        assert_eq!(told.revision, round);
        seen = told.told;
    }
    took.sort();
    let (median, p99) = (took[took.len() / 2], took[took.len() * 99 / 100]);
    println!("follow notification over loopback: median {median:?}, p99 {p99:?}");
    assert!(median < Duration::from_millis(1), "median {median:?}");
}

#[test]
fn an_act_is_the_certificates_and_is_refused_to_an_observer() {
    let authority = Authority::new();
    let board = Arc::new(Board::default());
    let (listener, audit) = node(&authority, &board, None);
    let surface = remote(&authority, &listener);

    let (outcome, said) = surface
        .act(&absent_node(), "subscription", "orders", "pause")
        .expect("it answers");
    assert_eq!(outcome, Outcome::Denied);
    assert!(
        said.starts_with("REFUSED. CN=surface may not pause a Subscription 'orders'"),
        "{said}"
    );
    let file = audit.file().expect("an audit file");
    let kept = std::fs::read_to_string(file).expect("the audit file");
    assert!(
        kept.contains("CN=surface") && kept.contains("Observer"),
        "{kept}"
    );

    let (outcome, said) = surface
        .act(&absent_node(), "subscription", "orders", "remove")
        .expect("it answers");
    assert_eq!(outcome, Outcome::Invalid, "{said}");
}

#[test]
fn an_operator_acts_as_the_certificate_and_the_node_answers() {
    let authority = Authority::new();
    let board = Arc::new(Board::default());
    let (listener, _) = node(&authority, &board, Some(Role::Operator));
    let surface = remote(&authority, &listener);

    let (outcome, said) = surface
        .act(&absent_node(), "journey", "j1", "retry")
        .expect("it answers");
    assert_eq!(outcome, Outcome::Refused);
    assert_eq!(
        said,
        format!("REFUSED: no node at {} runs in this process", absent_node())
    );
}

#[test]
fn a_surface_whose_certificate_the_node_does_not_trust_is_refused() {
    let ours = Authority::new();
    let theirs = Authority::new();
    let board = Arc::new(Board::default());
    let (listener, _) = node(&ours, &board, None);
    let stranger = remote(&theirs, &listener);

    let refused = stranger.publication().expect_err("refused");
    assert!(refused.contains("unreachable"), "{refused}");
}

#[test]
fn a_node_lost_is_told_and_found_again_on_the_recovery_loop() {
    let authority = Authority::new();
    let board = Arc::new(Board::default());
    board.post("source = \"one\"\n".to_string());
    let (mut listener, _) = node(&authority, &board, None);
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
        None,
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

#[test]
fn a_read_after_the_node_was_not_there_says_so_at_once_and_the_loop_finds_it() {
    let authority = Authority::new();
    let address = net::fixture::unheld();
    let surface = Remote::retrying(
        &address.to_string(),
        &authority.identity("surface"),
        vec![Duration::from_millis(50)],
    )
    .expect("a remote");

    let first = surface.publication().expect_err("nothing there");
    assert!(first.contains("unreachable"), "{first}");
    let asked = Instant::now();
    let again = surface.publication().expect_err("still nothing");
    assert!(
        asked.elapsed() < Duration::from_millis(5),
        "{:?}",
        asked.elapsed()
    );
    assert!(again.contains("unreachable"), "{again}");

    let board = Arc::new(Board::default());
    board.post("source = \"back\"\n".to_string());
    let audit = ProgramAudit::new("plane-test", Some(&authority.directory));
    let _back = Listener::start(
        TcpListener::bind(address).expect("the same port"),
        &authority.identity("node"),
        Arc::clone(&board) as Arc<dyn xmip_core_runtime::plane::Published>,
        None,
        &audit,
    )
    .expect("it serves");
    let mut state = surface.state();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !state.reachable && Instant::now() < deadline {
        state = surface.wait(state.told, Duration::from_secs(1));
    }
    assert!(state.reachable, "{}", state.reason);
    assert_eq!(
        surface.publication().expect("back").1,
        "source = \"back\"\n"
    );
}
