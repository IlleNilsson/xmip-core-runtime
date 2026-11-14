//! The operate plane on this machine (ADR-0014, amendment 2026-10-13): a
//! node's local endpoint — a named pipe on Windows, a Unix domain socket
//! elsewhere — and the surface over it, with no certificate: an act taken
//! as the operating system user this test runs as and refused to an
//! Observer, and a stop and a drop that end a follow waiting on the
//! endpoint at once. How fast a follower is told and a connection answered
//! is the module's timing program's (`tests/measured`).

use std::sync::Arc;
use std::time::{Duration, Instant};

use super::endpoint::{account_as, endpoint, node, surface};
use xmip_core_runtime::fixture::absent_node;
use xmip_core_runtime::plane::{Board, Outcome, Remote, Role};

/// The user this test runs as, as the system names it in a login.
fn user() -> String {
    std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_default()
        .to_lowercase()
}

#[test]
fn an_act_on_this_machine_is_the_users_and_is_refused_to_an_observer() {
    let board = Arc::new(Board::default());
    let (_listener, audit, called) = node(&board, account_as(Role::Observer, &[]));
    let surface = surface(&called);

    let (outcome, said) = surface
        .act(0, &absent_node(), ("subscription", "orders", "pause"))
        .expect("it answers");
    assert_eq!(outcome, Outcome::Denied);
    assert!(said.starts_with("REFUSED. "), "{said}");
    assert!(said.to_lowercase().contains(&user()), "{said}");
    let kept = std::fs::read_to_string(audit.file().expect("an audit file")).expect("read");
    assert!(kept.contains("Observer"), "{kept}");
    assert!(
        kept.contains("operate.local"),
        "the plain text is said: {kept}"
    );
}

#[test]
fn an_operator_on_this_machine_acts_and_the_node_answers() {
    let board = Arc::new(Board::default());
    let (_listener, _, called) = node(&board, account_as(Role::Operator, &[]));
    let surface = surface(&called);

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
fn a_secret_is_set_through_the_endpoint_as_an_act_and_never_said_back() {
    let board = Arc::new(Board::default());
    let (_listener, _, called) = node(&board, account_as(Role::Operator, &[]));
    let operator = surface(&called);
    let drawn = format!("drawn-{}", std::process::id());

    let (outcome, said) = operator
        .set_secret(0, &absent_node(), ("partner-x", "password", &drawn))
        .expect("it answers");
    assert_eq!(outcome, Outcome::Refused);
    assert_eq!(
        said,
        format!("REFUSED: no node at {} runs in this process", absent_node())
    );
    assert!(!said.contains(&drawn));
    let listed = operator
        .secrets(0, &absent_node())
        .expect_err("no such node");
    assert!(listed.starts_with("REFUSED: no node at"), "{listed}");

    let (_watching, _, watched) = node(&board, account_as(Role::Observer, &[]));
    let (outcome, said) = surface(&watched)
        .set_secret(0, &absent_node(), ("partner-x", "password", &drawn))
        .expect("it answers");
    assert_eq!(outcome, Outcome::Denied, "{said}");
}

#[test]
fn a_stop_ends_a_follow_waiting_on_the_endpoint_and_it_is_told() {
    let board = Arc::new(Board::default());
    board.post("source = \"one\"\n".to_string());
    let (mut listener, _, called) = node(&board, account_as(Role::Observer, &[]));
    let surface = surface(&called);
    let reached = surface.wait(0, Duration::from_secs(5));
    assert!(reached.reachable, "{}", reached.reason);
    // The follow now waits on the node, which holds its wait.
    std::thread::sleep(Duration::from_millis(20));

    let stopped = Instant::now();
    listener.stop();
    assert!(
        stopped.elapsed() < Duration::from_secs(1),
        "the stop took {:?}",
        stopped.elapsed()
    );
    let lost = surface.wait(reached.told, Duration::from_secs(5));
    assert!(!lost.reachable, "told it is lost");
    assert!(stopped.elapsed() < Duration::from_secs(1));
}

#[test]
fn a_surface_dropped_while_its_follow_waits_ends_at_once() {
    let board = Arc::new(Board::default());
    let (_listener, _, called) = node(&board, account_as(Role::Observer, &[]));
    let surface = surface(&called);
    assert!(surface.wait(0, Duration::from_secs(5)).reachable);
    std::thread::sleep(Duration::from_millis(20));

    let dropped = Instant::now();
    drop(surface);
    assert!(
        dropped.elapsed() < Duration::from_secs(1),
        "the drop took {:?}",
        dropped.elapsed()
    );
}

#[test]
fn a_surface_with_no_node_at_the_endpoint_says_so() {
    let surface = surface(&endpoint());
    let said = surface.publication().expect_err("nothing there");
    assert!(said.contains("unreachable"), "{said}");
    assert!(Remote::local(" ", Duration::ZERO).is_err());
}
