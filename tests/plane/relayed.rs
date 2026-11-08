//! A caller a web host relays to the node (ADR-0009, amendments 2026-11-01
//! and 2026-11-02: the node decides): a browser makes its handshake with
//! the host's secure listener, bound to a fresh nonce of the node; the node
//! is handed that handshake and, where `[operate] relay` names the host's
//! account, finds the browser held its key in it, with the host's own
//! listener, and acts for the browser by the browser's own role, auditing
//! who and through. Where the account is no relay, the node trusts another
//! authority, or the host's handle holds no one, the act is no one's.

use std::sync::Arc;

use xmip_core_runtime::fixture::{Authority, absent_node};
use xmip_core_runtime::plane::local::running_as;
use xmip_core_runtime::plane::vouched::Relaying;
use xmip_core_runtime::plane::{Board, Outcome, Remote, Role, held};

use super::browsing::{browser, listening, reached};
use super::endpoint::{account_as, node};

/// An act for `caller` through `surface`, as a web host takes one.
fn retry(surface: &Remote, caller: u64) -> (Outcome, String) {
    surface
        .act(caller, &absent_node(), ("message", "j1", "retry"))
        .expect("it answers")
}

#[test]
fn a_relayed_act_is_the_browsers_by_its_own_role_proven_by_its_handshake_and_audited() {
    let authority = Authority::new();
    let (_, _, anchors) = authority.pem("anchors");
    let account = running_as().expect("this process's account");
    // Each node its own: its relays, its nonces and the callers it holds.
    let relaying = || Arc::new(Relaying::new(vec![account.clone()], &anchors).expect("anchors"));
    let board = Arc::new(Board::default());
    let (operating, audit, called) = node(&board, account_as(Role::Operator, &["CN=alice"]));
    operating.relay(relaying());
    let (watching, _, watched) = node(&board, account_as(Role::Observer, &["CN=alice"]));
    watching.relay(relaying());
    // The surfaces exist before the browser connects: its handshake is
    // bound to a nonce of each of their nodes.
    let (operator, observer) = (reached(&called), reached(&watched));
    let listener = listening(&authority);

    let (alice, name, connected) = browser(&listener, &authority, "alice");
    let (outcome, said) = retry(&operator, alice);
    assert_eq!(
        outcome,
        Outcome::Refused,
        "admitted, and no such node: {said}"
    );
    let kept = std::fs::read_to_string(audit.file().expect("an audit")).expect("read");
    assert!(kept.contains(&name), "who is the browser: {kept}");
    assert!(kept.contains("\"through\""), "and through the host: {kept}");
    let (outcome, said) = retry(&observer, alice);
    assert_eq!(outcome, Outcome::Denied);
    assert!(said.starts_with(&format!("REFUSED. {name}")), "{said}");

    // Let go: no one, in this process and at the nodes alike.
    connected.join().expect("ended");
    assert!(held::release(alice));
    let (outcome, said) = retry(&operator, alice);
    assert_eq!(outcome, Outcome::Denied);
    assert!(said.starts_with("REFUSED. Nothing proved"), "{said}");
}

#[test]
fn an_account_that_is_no_relay_or_a_listener_the_node_does_not_trust_acts_for_no_one() {
    let authority = Authority::new();
    let account = running_as().expect("this process's account");
    let board = Arc::new(Board::default());

    // The node relays for another account alone: it gives no nonce.
    let (elsewhere, _, called) = node(&board, account_as(Role::Developer, &["CN=bob"]));
    let (_, _, anchors) = authority.pem("anchors");
    let other = Relaying::new(vec!["NOBODY\\relay".to_string()], &anchors).expect("anchors");
    elsewhere.relay(Arc::new(other));
    // The node relays for this account, but its anchors are another
    // authority's: the host's listener is none of its own.
    let stranger = Authority::new();
    let (_, _, theirs) = stranger.pem("anchors");
    let (trusting, _, trusted) = node(&board, account_as(Role::Developer, &["CN=bob"]));
    trusting.relay(Arc::new(
        Relaying::new(vec![account], &theirs).expect("anchors"),
    ));
    let (untold, unbound) = (reached(&called), reached(&trusted));
    let listener = listening(&authority);

    let (bob, _, connected) = browser(&listener, &authority, "bob");
    let (outcome, said) = retry(&untold, bob);
    assert_eq!(outcome, Outcome::Denied);
    assert!(said.contains("was not proven to"), "{said}");
    let (outcome, said) = retry(&unbound, bob);
    assert_eq!(outcome, Outcome::Denied);
    assert!(said.starts_with("REFUSED."), "{said}");
    connected.join().expect("ended");
    assert!(held::release(bob));
}

#[test]
fn two_browsers_acting_at_once_through_one_surface_each_reach_the_node_as_their_own() {
    let authority = Authority::new();
    let (_, _, anchors) = authority.pem("anchors");
    let account = running_as().expect("this process's account");
    let board = Arc::new(Board::default());
    // An Observer node, so each refusal names whom the node acted for.
    let browsers = ["CN=carol", "CN=dave"];
    let (watching, _, called) = node(&board, account_as(Role::Observer, &browsers));
    watching.relay(Arc::new(
        Relaying::new(vec![account], &anchors).expect("anchors"),
    ));
    let shared = Arc::new(reached(&called));
    let listener = listening(&authority);
    let callers = [
        browser(&listener, &authority, "carol"),
        browser(&listener, &authority, "dave"),
    ];

    let acting: Vec<_> = callers
        .iter()
        .map(|(handle, who, _)| {
            let (surface, handle, who) = (Arc::clone(&shared), *handle, who.clone());
            std::thread::spawn(move || {
                for _ in 0..25 {
                    let (outcome, said) = retry(&surface, handle);
                    assert_eq!(outcome, Outcome::Denied);
                    assert!(said.starts_with(&format!("REFUSED. {who} ")), "{said}");
                }
            })
        })
        .collect();
    for thread in acting {
        thread.join().expect("each acted as its own");
    }
    for (handle, _, connected) in callers {
        connected.join().expect("ended");
        assert!(held::release(handle));
    }
}
