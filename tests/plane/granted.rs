//! Each caller holds its own role, by name (ADR-0009, amendment 2026-11-07):
//! a second certificate from the same anchors as an Operator's is no one the
//! node lists and reads and acts on nothing, an account on the local endpoint
//! is listed apart, and a browser a relay vouches for acts by the role its
//! own certificate is listed with, never one the whole node holds.

use std::sync::Arc;

use xmip_core_runtime::fixture::{Authority, absent_node};
use xmip_core_runtime::plane::local::running_as;
use xmip_core_runtime::plane::vouched::Relaying;
use xmip_core_runtime::plane::{Board, Grants, Outcome, held};

use super::browsing::{browser, listening, reached};
use super::certified::{node, remote_as};
use super::endpoint::{self, surface};

/// `operators` listed as Operators, `observers` as Observers, no one else.
fn listed(observers: &[&str], operators: &[&str]) -> Grants {
    let owned = |names: &[&str]| names.iter().map(ToString::to_string).collect::<Vec<_>>();
    Grants::listed([&owned(observers), &owned(operators), &[]])
}

const NO_ROLE: &str = "no role on this node is granted";

#[test]
fn a_second_certificate_from_the_same_anchors_reads_and_acts_on_nothing() {
    let authority = Authority::new();
    let board = Arc::new(Board::default());
    board.post("source = \"one\"\n".to_string());
    let (listener, audit) = node(&authority, &board, listed(&["CN=watcher"], &["CN=alice"]));
    let pause = ("subscription", "orders", "pause");

    let alice = remote_as(&authority, &listener, "alice");
    let (outcome, said) = alice.act(0, &absent_node(), pause).expect("it answers");
    assert_eq!(outcome, Outcome::Refused, "admitted, no such node: {said}");

    let watcher = remote_as(&authority, &listener, "watcher");
    assert!(watcher.publication().is_ok(), "an Observer reads");
    let (outcome, said) = watcher.act(0, &absent_node(), pause).expect("it answers");
    assert_eq!(outcome, Outcome::Denied);
    assert!(said.contains("CN=watcher is Observer"), "{said}");

    let mallory = remote_as(&authority, &listener, "mallory");
    let refused = mallory.publication().expect_err("refused");
    assert!(refused.contains(NO_ROLE), "{refused}");
    let (outcome, said) = mallory.act(0, &absent_node(), pause).expect("it answers");
    assert_eq!(outcome, Outcome::Denied);
    assert!(said.starts_with(&format!(
        "REFUSED. CN=mallory may not act on this node: {NO_ROLE}"
    )));
    let secret = ("partner-x", "password", "not-a-real-value");
    let (outcome, said) = mallory
        .set_secret(0, &absent_node(), secret)
        .expect("it answers");
    assert_eq!(outcome, Outcome::Denied);
    assert!(
        said.contains(NO_ROLE) && !said.contains("not-a-real-value"),
        "{said}"
    );

    let kept = std::fs::read_to_string(audit.file().expect("an audit")).expect("read");
    assert!(
        kept.contains("CN=mallory") && kept.contains("\"none\""),
        "{kept}"
    );
}

#[test]
fn an_account_on_the_local_endpoint_holds_the_role_its_own_name_is_listed_with() {
    let account = running_as().expect("this process's account");
    let board = Arc::new(Board::default());
    let pause = ("subscription", "orders", "pause");

    let (_listed, _, called) = endpoint::node(&board, listed(&[], &[&account]));
    let (outcome, said) = surface(&called)
        .act(0, &absent_node(), pause)
        .expect("it answers");
    assert_eq!(outcome, Outcome::Refused, "admitted, no such node: {said}");

    let (_unlisted, _, called) = endpoint::node(&board, listed(&[], &["NOBODY\\else"]));
    let (outcome, said) = surface(&called)
        .act(0, &absent_node(), pause)
        .expect("it answers");
    assert_eq!(outcome, Outcome::Denied);
    assert!(said.contains(NO_ROLE), "{said}");
}

#[test]
fn a_browser_a_relay_vouches_for_acts_by_its_own_listed_role_and_never_the_relays() {
    let authority = Authority::new();
    let (_, _, anchors) = authority.pem("anchors");
    let account = running_as().expect("this process's account");
    let board = Arc::new(Board::default());
    // The relay's own account watches, as a web host following the node
    // does; alice is an Operator; bob is listed nowhere.
    let (operating, _, called) = endpoint::node(&board, listed(&[&account], &["CN=alice"]));
    operating.relay(Arc::new(
        Relaying::new(vec![account.clone()], &anchors).expect("anchors"),
    ));
    let surface = reached(&called);
    let listener = listening(&authority);
    let retry = |caller| {
        surface
            .act(caller, &absent_node(), ("message", "j1", "retry"))
            .expect("it answers")
    };

    let (alice, _, alice_connected) = browser(&listener, &authority, "alice");
    let (outcome, said) = retry(alice);
    assert_eq!(outcome, Outcome::Refused, "admitted, no such node: {said}");

    let (bob, name, bob_connected) = browser(&listener, &authority, "bob");
    let (outcome, said) = retry(bob);
    assert_eq!(outcome, Outcome::Denied);
    assert!(
        said.starts_with(&format!("REFUSED. {name} may not")),
        "{said}"
    );
    assert!(said.contains(NO_ROLE), "{said}");

    let (outcome, said) = retry(0);
    assert_eq!(outcome, Outcome::Denied, "the relay's own act: {said}");
    assert!(said.contains("is Observer"), "by its own role: {said}");

    for (handle, connected) in [(alice, alice_connected), (bob, bob_connected)] {
        connected.join().expect("ended");
        assert!(held::release(handle));
    }
}
