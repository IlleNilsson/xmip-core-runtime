//! A stop drains what a Receive Location's far end already let go of
//! (ADR-0018 clause 12; `runtime-model.md` section 5, *How a receive
//! runs*): raw TCP's sender is done once its kernel took the bytes, so a
//! connection the operating system completed and queued in the listener's
//! backlog before the stop is a Stream the sender was told went through.
//! Until 2026-10-15 the Location took nothing more once the stop was
//! raised, the listener was closed with the backlog in it, and those
//! Streams were lost — 7 of 50 on the CI's Linux runner, 32 on its macOS
//! one, none on Windows, which drained faster than the test sent.
//!
//! Here the backlog is filled while the Location's serve is held inside a
//! receive, and the stop is raised before that receive returns, so what is
//! queued at the stop is known on every machine rather than left to how
//! fast one runs.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tcp::TcpTransport;
use transport::{Arrivals, Arrived, Directions, Transport, Waiting};
use xmip_core_runtime::ledger::CHUNK;
use xmip_core_runtime::receiving::Receiving;
use xmip_core_runtime::stopping::Stopping;
use xmip_core_runtime::tuning::Tuning;

use super::receive_cycle::on_runtime;
use super::{directory, test_node};

/// The connections queued in the listener's backlog when the stop is
/// raised: fewer than any operating system's smallest backlog, 128.
const QUEUED: usize = 32;

/// The Location's own wait, as the root crate's service test sets it.
const WAIT: Duration = Duration::from_millis(100);

/// A tcp Receive Location whose first receive takes one connection, then
/// fills the listener's backlog with [`QUEUED`] connections nobody accepts
/// yet — each sent and closed, as a sender that was told it went through —
/// and raises the node's stop before it returns.
struct Backlogged {
    tcp: TcpTransport,
    address: String,
    stopping: Arc<Stopping>,
    filled: AtomicBool,
}

/// Send `payload` to `address`, asking again while nothing listens there
/// yet. Bounded, and never a sleep.
fn deliver(address: &str, payload: &[u8]) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match TcpTransport::loopback().send(address, payload) {
            Ok(()) => return,
            Err(refused) if refused.retryable && Instant::now() < deadline => {
                std::thread::yield_now();
            }
            Err(failed) => panic!("nothing took it at {address}: {failed:?}"),
        }
    }
}

impl Transport for Backlogged {
    fn name(&self) -> &'static str {
        "tcp"
    }

    fn directions(&self) -> Directions {
        Directions::RECEIVE
    }

    fn arrivals(&self) -> Arrivals {
        self.tcp.arrivals()
    }

    fn waiting(&self) -> Waiting {
        self.tcp.waiting()
    }

    fn receive_up_to(&self, _most: usize) -> transport::Result<Vec<Arrived>> {
        if self.filled.swap(true, Ordering::AcqRel) {
            return self.tcp.receive();
        }
        let address = self.address.clone();
        let first = std::thread::spawn(move || deliver(&address, b"before the backlog"));
        let taken = loop {
            match self.tcp.receive() {
                Ok(arrivals) if !arrivals.is_empty() => break arrivals,
                Err(failed) if !failed.retryable => panic!("{failed:?}"),
                _ => {}
            }
        };
        first.join().expect("the first sender");
        for queued in 0..QUEUED {
            deliver(&self.address, format!("queued {queued}").as_bytes());
        }
        self.stopping.raise();
        Ok(taken)
    }

    fn sending(&self) -> transport::Sending {
        transport::Sending::Streamed("it sends nothing")
    }

    fn send_from(&self, _: &str, _: transport::Outgoing<'_>) -> transport::Result<()> {
        Ok(())
    }
}

/// A Receive Location called `In` over `transport`, at the default pace.
fn location(
    transport: Box<dyn Transport + Send + Sync>,
    gate: &xmip_core_runtime::receiving::ReceiveGate,
) -> Receiving {
    Receiving {
        configured: configure::ConfiguredLocation {
            name: "In".to_string(),
            start: true,
            address: "tcp://in".to_string(),
            credentials: None,
            contract: None,
            settings: configure::LocationSettings::default(),
            contract_settings: configure::LocationSettings::default(),
            accept: configure::Accept::default(),
            prepare: Vec::new(),
            transform: None,
            promote: None,
            demote: None,
            debatch: None,
            correlation: None,
        },
        gate: gate.clone(),
        transport,
        limits: Tuning::default().receive(),
        pace: Tuning::default().pace(),
        audit: None,
    }
}

#[test]
fn a_stop_takes_every_connection_already_queued_at_the_listener() {
    let at = directory("drained-backlog");
    let storage = test_node(&at.join("node"));
    let stopping = Arc::new(Stopping::default());
    let address = net::fixture::unheld().to_string();
    let backlogged = Backlogged {
        tcp: TcpTransport::new(address.clone()).timing_out_after(WAIT),
        address,
        stopping: Arc::clone(&stopping),
        filled: AtomicBool::new(false),
    };
    let told = Mutex::new(0_usize);
    let took = on_runtime(&storage, CHUNK, |runtime, pickup, gate| {
        let location = location(Box::new(backlogged), gate);
        let began = Instant::now();
        std::thread::scope(|pool| {
            location.serve(pool, runtime, pickup, &stopping, |_| {
                *told.lock().expect("lock") += 1;
            })
        })
        .expect("the Location stopped when asked");
        began.elapsed()
    });
    let _ = std::fs::remove_dir_all(&at);

    assert_eq!(
        told.into_inner().expect("lock"),
        QUEUED + 1,
        "every connection queued before the stop is received and judged"
    );
    // The drain ends at the first receive that finds nothing: one wait of
    // the Location's own, not a timeout of the runtime's.
    assert!(took < Duration::from_secs(2), "draining took {took:?}");
}
