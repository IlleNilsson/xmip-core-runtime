//! A caller that breaches a bound is turned away at its own connection,
//! audited as a refusal of that caller, and its Receive Location goes on
//! serving every other (ADR-0018, amendment 2026-11-13). Until then the
//! breach was the receive's failure, and one asking again would not mend
//! stopped the Location for every other caller. A failure of the listener itself
//! still stops it.

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::time::Duration;

use http::HttpTransport;
use transport::Transport;
use xaudit::program_audit::ProgramAudit;
use xmip_core_runtime::ledger::CHUNK;
use xmip_core_runtime::receiving::Receiving;
use xmip_core_runtime::stopping::Stopping;

use super::drained::location;
use super::receive_cycle::on_runtime;
use super::{directory, test_node};

/// How long a caller waits on its answer.
const WAIT: Duration = Duration::from_secs(5);

/// How long one receive of the Location waits: what bounds its stop once
/// the good caller is carried.
const RECEIVE_WAIT: Duration = Duration::from_millis(500);

/// A caller whose head runs past the longest line Xmip reads
/// (`net::read::MAX_LINE`), unended, and then a good one, once the node let
/// the first go: where the first called from, and how the second's send
/// was answered.
fn callers(address: &str) -> (SocketAddr, transport::Result<()>) {
    // Bounded: the connect, and the reads and writes after it, within WAIT.
    let mut breaching =
        transport::socket::connect_tcp(address, Some(WAIT)).expect("the breaching caller connects");
    let from = breaching.local_addr().expect("its address");
    // The node may let it go before the last byte is written.
    drop(breaching.write_all(&vec![b'a'; net::read::MAX_LINE + 1]));
    let mut rest = Vec::new();
    drop(breaching.read_to_end(&mut rest));
    let good = HttpTransport::new("127.0.0.1:0").timing_out_after(WAIT);
    let sent = good.send(&format!("http://{address}/in"), b"after the breach");
    (from, sent)
}

#[test]
fn a_caller_past_a_bound_is_turned_away_and_the_next_caller_served() {
    let at = directory("turned-away");
    let storage = test_node(&at.join("node"));
    let audited = at.join("audit");
    let http = HttpTransport::new("127.0.0.1:0").timing_out_after(RECEIVE_WAIT);
    let address = http.listening().expect("bound").to_string();
    let stopping = Stopping::default();
    let (ended, (from, sent)) = on_runtime(&storage, CHUNK, |runtime, pickup, gate| {
        let location = Receiving {
            audit: Some(ProgramAudit::new(
                "xmip-runtime turned-away tests",
                Some(&audited),
            )),
            ..location("http://in", Box::new(http), gate)
        };
        std::thread::scope(|scope| {
            let calling = scope.spawn(|| callers(&address));
            let ended = location.serve(scope, runtime, pickup, &stopping, |_| stopping.raise());
            (ended, calling.join().expect("the callers"))
        })
    });
    ended.expect("the Location went on past the breach, and stopped when asked");
    sent.expect("the next caller was served");
    xaudit::keeper::settle();
    let text =
        std::fs::read_to_string(audited.join(xaudit::file_sink::FILE_NAME)).expect("audited");
    let turned = format!("the Receive Location 'In' turned away the caller at {from}");
    assert!(text.contains(&turned), "{text}");
    let _ = std::fs::remove_dir_all(&at);
}

#[test]
fn a_listener_that_cannot_bind_stops_the_location() {
    let at = directory("turned-away-listener");
    let storage = test_node(&at.join("node"));
    let http = HttpTransport::new("127.0.0.1:99999").timing_out_after(RECEIVE_WAIT);
    let ended = on_runtime(&storage, CHUNK, |runtime, pickup, gate| {
        let location = location("http://127.0.0.1:99999", Box::new(http), gate);
        let stopping = Stopping::default();
        std::thread::scope(|scope| location.serve(scope, runtime, pickup, &stopping, |_| {}))
    });
    let why = ended.expect_err("no listener, no Location");
    assert!(
        why.starts_with("the Receive Location 'In' stopped: binding the listener"),
        "{why}"
    );
    let _ = std::fs::remove_dir_all(&at);
}
