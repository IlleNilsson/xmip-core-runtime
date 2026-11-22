//! Xmip Storage reached over loopback, as a node reaches a Storage node over
//! Xmip's TLS: what `claim_ahead.rs` sends over the wire, and what the
//! timing program's drain reads and writes through
//! (`tests/measured/work_drain.rs`).

use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

use persist::storage::{StorageClient, StorageServer, XmipStorage, client};
use xmip_core_runtime::fixture::Authority;

/// `beneath` served on loopback, and a node's Xmip Storage reaching it over
/// the wire, each read bounded by `timeout`.
pub fn over_the_wire(
    beneath: &Arc<dyn XmipStorage>,
    timeout: Duration,
) -> (StorageServer, Arc<dyn XmipStorage>) {
    let authority = Authority::new();
    let listener = TcpListener::bind("127.0.0.1:0").expect("bound");
    let identity = authority.identity("storage");
    let server = StorageServer::start(Arc::clone(beneath), listener, &identity).expect("served");
    let at = [server.address().to_string()];
    let identity = authority.identity("node");
    let reached = StorageClient::new(&at, &identity, timeout, client::PASS_OVER);
    (server, Arc::new(reached.expect("a client")))
}
