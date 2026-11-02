//! A caller a web host relays to the node (ADR-0009, amendment
//! 2026-11-01: the node decides): the host's runtime holds a browser's
//! caller by the certificate that proved it, the node — where `[operate]
//! relay` names the host's account — verifies that certificate itself and
//! acts for the caller by the caller's own role, auditing who and through;
//! where the account is no relay, or the host's handle holds no one, the
//! act is no one's.

use std::sync::Arc;

use authenticate::x509::Chain;
use context::AuthenticatedIdentity;
use xmip_core_runtime::fixture::{Authority, absent_node};
use xmip_core_runtime::plane::caller;
use xmip_core_runtime::plane::held;
use xmip_core_runtime::plane::local::running_as;
use xmip_core_runtime::plane::vouched::Relaying;
use xmip_core_runtime::plane::{Board, Outcome, Role};

use super::endpoint::{node, surface};

/// A browser's caller as a web host's runtime holds it: proven by the
/// certificate `authority` issued `person`, and that certificate's leaf.
fn browser(authority: &Authority, person: &str) -> (u64, AuthenticatedIdentity) {
    let (certificate, _, _) = authority.pem(person);
    let leaf = Chain::from_pem(&certificate)
        .expect("a chain")
        .leaf()
        .to_vec();
    let identity = caller::certificate(&leaf).expect("proven");
    let handle = held::hold(identity.clone(), None, None, Some(leaf));
    (handle, identity)
}

#[test]
fn a_relayed_act_is_the_browsers_by_its_own_role_and_audited_through_the_host() {
    let authority = Authority::new();
    let (_, _, anchors) = authority.pem("anchors");
    let account = running_as().expect("this process's account");
    let relaying = Arc::new(Relaying::new(vec![account.clone()], &anchors).expect("anchors"));
    let board = Arc::new(Board::default());

    // An Operator node: the browser's act is admitted and reaches the node.
    let (operating, audit, called) = node(&board, Some(Role::Operator));
    operating.relay(Arc::clone(&relaying));
    let (alice, identity) = browser(&authority, "alice");
    let (outcome, said) = surface(&called)
        .act(alice, &absent_node(), ("message", "j1", "retry"))
        .expect("it answers");
    assert_eq!(outcome, Outcome::Refused, "{said}");
    let kept = std::fs::read_to_string(audit.file().expect("an audit")).expect("read");
    assert!(kept.contains(&identity.value), "who is the browser: {kept}");
    assert!(kept.contains("\"through\""), "and through the host: {kept}");

    // An Observer node: refused as the browser, never as the host.
    let (watching, _, watched) = node(&board, Some(Role::Observer));
    watching.relay(Arc::clone(&relaying));
    let (outcome, said) = surface(&watched)
        .act(alice, &absent_node(), ("message", "j1", "retry"))
        .expect("it answers");
    assert_eq!(outcome, Outcome::Denied);
    assert!(
        said.starts_with(&format!("REFUSED. {}", identity.value)),
        "{said}"
    );

    // Let go: no one, in this process and at the node alike.
    assert!(held::release(alice));
    let (outcome, said) = surface(&called)
        .act(alice, &absent_node(), ("message", "j1", "retry"))
        .expect("it answers");
    assert_eq!(outcome, Outcome::Denied);
    assert!(said.starts_with("REFUSED. Nothing proved"), "{said}");
}

#[test]
fn an_account_that_is_no_relay_and_a_certificate_the_node_does_not_trust_act_for_no_one() {
    let authority = Authority::new();
    let (_, _, anchors) = authority.pem("anchors");
    let board = Arc::new(Board::default());

    // The node relays for another account alone.
    let (elsewhere, _, called) = node(&board, Some(Role::Developer));
    let other = Relaying::new(vec!["NOBODY\\relay".to_string()], &anchors).expect("anchors");
    elsewhere.relay(Arc::new(other));
    let (bob, _) = browser(&authority, "bob");
    let (outcome, said) = surface(&called)
        .act(bob, &absent_node(), ("message", "j1", "retry"))
        .expect("it answers");
    assert_eq!(outcome, Outcome::Denied);
    assert!(said.contains("relays for no one"), "{said}");

    // The node relays for this account, but trusts another authority.
    let stranger = Authority::new();
    let (mallory, _) = browser(&stranger, "mallory");
    let account = running_as().expect("this process's account");
    let (trusting, _, trusted) = node(&board, Some(Role::Developer));
    trusting.relay(Arc::new(
        Relaying::new(vec![account], &anchors).expect("anchors"),
    ));
    let (outcome, said) = surface(&trusted)
        .act(mallory, &absent_node(), ("message", "j1", "retry"))
        .expect("it answers");
    assert_eq!(outcome, Outcome::Denied);
    assert!(said.contains("The caller's certificate"), "{said}");

    // A node that relays for no one at all refuses a named caller too.
    let (plain, _, alone) = node(&board, Some(Role::Developer));
    let (outcome, said) = surface(&alone)
        .act(bob, &absent_node(), ("message", "j1", "retry"))
        .expect("it answers");
    drop(plain);
    assert_eq!(outcome, Outcome::Denied);
    assert!(said.contains("relays for no one"), "{said}");
    assert!(held::release(bob) && held::release(mallory));
}

#[test]
fn two_callers_acting_at_once_through_one_surface_each_reach_the_node_as_their_own() {
    let authority = Authority::new();
    let (_, _, anchors) = authority.pem("anchors");
    let account = running_as().expect("this process's account");
    let board = Arc::new(Board::default());
    // An Observer node, so each refusal names whom the node acted for.
    let (watching, _, called) = node(&board, Some(Role::Observer));
    watching.relay(Arc::new(
        Relaying::new(vec![account], &anchors).expect("anchors"),
    ));
    let shared = Arc::new(surface(&called));
    let callers = [browser(&authority, "carol"), browser(&authority, "dave")];

    let acting: Vec<_> = callers
        .iter()
        .map(|(handle, identity)| {
            let (surface, handle, who) = (Arc::clone(&shared), *handle, identity.value.clone());
            std::thread::spawn(move || {
                for _ in 0..25 {
                    let (outcome, said) = surface
                        .act(handle, &absent_node(), ("message", "j1", "retry"))
                        .expect("it answers");
                    assert_eq!(outcome, Outcome::Denied);
                    assert!(said.starts_with(&format!("REFUSED. {who} ")), "{said}");
                }
            })
        })
        .collect();
    for thread in acting {
        thread.join().expect("each acted as its own");
    }
    for (handle, _) in callers {
        assert!(held::release(handle));
    }
}
