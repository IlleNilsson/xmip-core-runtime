//! A node's operate listener on a loopback port and a remote surface on it,
//! each with a certificate from one test authority: what the plane's tests
//! and the module's timing program (`tests/measured`) both stand up.

use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

use xaudit::program_audit::ProgramAudit;
use xmip_core_runtime::fixture::Authority;
use xmip_core_runtime::plane::{Board, Listener, Remote, Role};

/// A node's listener over `board` on a loopback port, holding `role`.
pub fn node(
    authority: &Authority,
    board: &Arc<Board>,
    role: Option<Role>,
) -> (Listener, ProgramAudit) {
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

/// A surface on `listener`, as `surface` of `authority`.
pub fn remote(authority: &Authority, listener: &Listener) -> Remote {
    let address = listener.address();
    Remote::retrying(
        &address,
        &authority.identity("surface"),
        vec![Duration::from_millis(50)],
    )
    .expect("a remote")
}
