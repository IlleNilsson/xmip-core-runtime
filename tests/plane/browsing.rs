//! A web host's secure listener and a browser at it, presenting a person's
//! certificate (ADR-0009, amendment 2026-11-02): what the plane's relayed
//! tests and the module's timing program (`tests/measured`) both stand up.

use std::io::Write;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use xmip_core_runtime::fixture::Authority;
use xmip_core_runtime::plane::{Remote, held};
use xmip_core_runtime::secure_listener::{Accepted, Protection, SecureListener};

use super::endpoint::surface;

/// A surface on the endpoint `called` whose follow has reached its node, so
/// a browser's handshake is bound to it: a web host follows the nodes it
/// shows before a browser acts.
pub fn reached(called: &str) -> Remote {
    let surface = surface(called);
    assert!(surface.wait(0, std::time::Duration::from_secs(5)).reachable);
    surface
}

/// A web host's secure listener under `authority`.
pub fn listening(authority: &Authority) -> SecureListener {
    let (certificate, key, anchors) = authority.pem("xmip-web-host");
    SecureListener::listen(Protection::Tls, "127.0.0.1:0", &certificate, &key, &anchors)
        .expect("listening")
}

/// A browser presenting `person`'s certificate under `authority` at
/// `listener`, kept connected until it is joined; the caller the host's
/// runtime holds for its session, a handle of the test's own, and the name.
pub fn browser(
    listener: &SecureListener,
    authority: &Authority,
    person: &str,
) -> (u64, String, JoinHandle<()>) {
    let (caller, name, _, connected) = browsed(listener, authority, person);
    (caller, name, connected)
}

/// The same, with Xmip's own share of the session's start
/// (`SecureSession::own`).
pub fn browsed(
    listener: &SecureListener,
    authority: &Authority,
    person: &str,
) -> (u64, String, Duration, JoinHandle<()>) {
    let address = listener.address();
    let config = Arc::new(authority.identity(person).client().expect("a client"));
    let (done, waiting) = std::sync::mpsc::channel::<()>();
    let connected = std::thread::spawn(move || {
        let tcp = net::connect(address, Some(Duration::from_secs(5))).expect("connected");
        let mut stream = tls::client_with("localhost", tcp, config).expect("tls");
        stream.write_all(b"x").expect("said");
        let _ = waiting.recv();
    });
    // A handshake is bounded by HANDSHAKE_WITHIN, and the browser connects
    // on loopback on the thread above.
    // bounded: as said above
    let Accepted::Session(session) = listener.accept() else {
        panic!("a session");
    };
    let caller = held::again(session.caller());
    let name = held::proven(caller).expect("held").value;
    let own = session.own();
    let ending = std::thread::spawn(move || {
        drop(session);
        let _ = done.send(());
        connected.join().expect("the browser");
    });
    (caller, name, own, ending)
}
