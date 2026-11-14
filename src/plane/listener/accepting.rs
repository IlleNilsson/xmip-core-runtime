//! How an operate listener accepts its connections: each answered on one of
//! its threads (`plane::workers`) within its [`Limits`] — one past them
//! closed as it is accepted and told to the audit once, the handshake of
//! one taken bounded in all — and each kept among its connections until it
//! has ended, so a stop ends every one reading.

use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use xcore::lock::Locked;

use super::{Serve, WAKE};
use crate::plane::limits::{Backoff, Handshaking, Limits};
use crate::plane::local::{Acceptor, Cancel};
use crate::plane::served::{answer, answer_local, noted};
use crate::plane::workers::Workers;

/// A connection being answered, whether it has ended, and what ends a read
/// it waits in.
pub(super) struct Connection {
    done: Arc<AtomicBool>,
    cancel: Option<Cancel>,
}

/// The connections being answered, the threads answering them, what bounds
/// them, the handshakes in progress, and whether a connection past a bound
/// was told to the audit since one was last taken.
#[derive(Default)]
pub(super) struct Served {
    pub(super) connections: Mutex<Vec<Connection>>,
    pub(super) workers: Arc<Workers>,
    pub(super) limits: Mutex<Limits>,
    handshaking: Arc<AtomicUsize>,
    refusing: AtomicBool,
}

impl Served {
    /// Whether `most` connections are being answered already.
    fn full(&self, most: usize) -> bool {
        let mut connections = self.connections.locked();
        connections.retain(|connection| !connection.done.load(Ordering::SeqCst));
        connections.len() >= most
    }

    /// A connection from `peer` closed for going past `most` of `bound`,
    /// told to the audit where it is the first since one was taken.
    fn refused(&self, serve: &Serve, peer: &str, (most, bound): (usize, &str)) {
        if !self.refusing.swap(true, Ordering::SeqCst) {
            let said = format!(
                "refused: the listener takes {most} {bound} at once ([tuning] operate_{bound}); \
                 every connection past them is closed until one ends"
            );
            noted(serve, peer, &said);
        }
    }
}

pub(super) type Connections = Arc<Served>;

/// A connection ended: a read it waits in cancelled until it has ended — a
/// pipe has no timeout to look between — waiting at most [`WAKE`]; one
/// that has not by then is left to end alone.
pub(super) fn ended(connection: &Connection) {
    let until = Instant::now() + WAKE;
    while !connection.done.load(Ordering::SeqCst) && Instant::now() < until {
        if let Some(cancel) = &connection.cancel {
            cancel.cancel();
        }
        std::thread::sleep(Duration::from_micros(200));
    }
}

/// Each connection accepted answered, within the listener's [`Limits`]: one
/// past them closed as it is accepted, the handshake of one taken bounded in
/// all.
pub(super) fn accept(listener: &TcpListener, serve: &Arc<Serve>, served: &Connections) {
    let mut backoff = Backoff::default();
    loop {
        // bounded: a listener waits as long as its node runs; a stop wakes it
        let accepted = listener.accept();
        if serve.stopped() {
            return;
        }
        let Ok((connection, peer)) = accepted else {
            backoff.failed();
            continue;
        };
        backoff.succeeded();
        let limits = *served.limits.locked();
        if served.full(limits.connections) {
            served.refused(
                serve,
                &peer.to_string(),
                (limits.connections, "connections"),
            );
            continue;
        }
        let Some(handshaking) = Handshaking::begun(&served.handshaking, limits.handshakes) else {
            served.refused(serve, &peer.to_string(), (limits.handshakes, "handshakes"));
            continue;
        };
        let bound = (limits.handshake_within, handshaking);
        let serve = Arc::clone(serve);
        answered(served, None, move || {
            answer(connection, peer, &serve, bound)
        });
    }
}

pub(super) fn accept_local(acceptor: &Acceptor, serve: &Arc<Serve>, served: &Connections) {
    let mut backoff = Backoff::default();
    loop {
        let accepted = acceptor.accept();
        if serve.stopped() {
            return;
        }
        let Ok(stream) = accepted else {
            backoff.failed();
            continue;
        };
        backoff.succeeded();
        let most = served.limits.locked().connections;
        if served.full(most) {
            served.refused(serve, "the local endpoint", (most, "connections"));
            continue;
        }
        let cancel = stream.cancel();
        let serve = Arc::clone(serve);
        answered(served, Some(cancel), move || answer_local(stream, &serve));
    }
}

/// `work` answered on one of the listener's threads (`plane::workers`),
/// and kept among its connections until it has ended.
fn answered(served: &Connections, cancel: Option<Cancel>, work: impl FnOnce() + Send + 'static) {
    let done = Arc::new(AtomicBool::new(false));
    let ending = Arc::clone(&done);
    let mut connections = served.connections.locked();
    connections.retain(|connection| !connection.done.load(Ordering::SeqCst));
    let running = served.workers.run(Box::new(move || {
        work();
        ending.store(true, Ordering::SeqCst);
    }));
    if running {
        connections.push(Connection { done, cancel });
        served.refusing.store(false, Ordering::SeqCst);
    }
}
