//! How long a local call may wait — decided by the owner, 2026-10-13: *a
//! local call waits at most a set time — `[tuning]`, default 2 s — then
//! says the node did not answer and shows it so; the tool recovers on its
//! own.*
//!
//! A socket's read keeps time itself (`net::watched`'s silence); a named
//! pipe's has none, so a call on a pipe is bounded by one thread per
//! surface that cancels the asking line's read once its deadline passes
//! (`plane::local::Cancel`). The thread waits on nothing until a call
//! arms it, and ends with its surface.

use std::path::Path;
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::plane::remote::LOCAL_TIMEOUT;
use crate::plane::shared::Shared;

#[derive(Default)]
struct Armed {
    until: Option<Instant>,
    fired: bool,
}

/// The deadline of the call in flight on a surface's asking line.
#[derive(Default)]
pub(crate) struct Deadline {
    armed: Mutex<Armed>,
    changed: Condvar,
}

impl Deadline {
    /// A call begins: it may wait `within`.
    pub(crate) fn arm(&self, within: Duration) {
        let mut armed = self.armed.lock().unwrap_or_else(PoisonError::into_inner);
        armed.until = Some(Instant::now() + within);
        armed.fired = false;
        self.changed.notify_all();
    }

    /// The call ended: whether its deadline passed first.
    pub(crate) fn disarm(&self) -> bool {
        let mut armed = self.armed.lock().unwrap_or_else(PoisonError::into_inner);
        armed.until = None;
        std::mem::take(&mut armed.fired)
    }

    /// Whether the deadline of the call in flight has passed.
    pub(crate) fn passed(&self) -> bool {
        self.armed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .fired
    }

    /// Wake the thread to see its surface ends.
    pub(crate) fn wake(&self) {
        let _armed = self.armed.lock().unwrap_or_else(PoisonError::into_inner);
        self.changed.notify_all();
    }
}

/// The key a node declares its `[tuning] local_timeout` under, in
/// milliseconds, beside its endpoint (ADR-0053): how a surface on the
/// machine opened with no wait of its own learns the node's.
pub const DECLARED: &str = "local_timeout_ms";

/// How long a call to the local endpoint at `path` waits: what the node
/// serving it declared, else [`LOCAL_TIMEOUT`].
#[must_use]
pub fn declared(path: &Path) -> Duration {
    let at = path.display().to_string();
    let said = |standing: &node::Standing, key: &str| {
        let said = &standing.declaration.said;
        said.iter()
            .find(|(named, _)| named == key)
            .map(|(_, value)| value.clone())
    };
    node::standing(&node::declaration::directory())
        .iter()
        .filter(|standing| {
            said(standing, "operate").is_some_and(|operate| operate.split(" and ").any(|a| a == at))
        })
        .find_map(|standing| said(standing, DECLARED)?.parse::<u64>().ok())
        .filter(|millis| *millis > 0)
        .map_or(LOCAL_TIMEOUT, Duration::from_millis)
}

/// The one sentence a surface says of a node that took longer than
/// `within` to answer.
#[must_use]
pub fn not_answered(within: Duration) -> String {
    let millis = within.as_millis();
    let said = if millis.is_multiple_of(1000) {
        format!("{} s", millis / 1000)
    } else {
        format!("{millis} ms")
    };
    format!("the node did not answer within {said}")
}

/// Keep `shared`'s calls to their deadline: on a named pipe, a thread
/// watching it for as long as the surface lives; elsewhere the line's own
/// silence does.
pub(crate) fn kept(shared: &Arc<Shared>) {
    if cfg!(windows) {
        let shared = Arc::clone(shared);
        // Detached: it ends when its surface ends and wakes it.
        let _ = std::thread::Builder::new()
            .name("xmip-operate-deadline".to_string())
            .spawn(move || watch(&shared));
    }
}

/// Watch `shared`'s deadline until it ends, cancelling the asking line's
/// read whenever one passes.
fn watch(shared: &Arc<Shared>) {
    let deadline = &shared.deadline;
    let mut armed = deadline
        .armed
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    while !shared.ending() {
        let Some(until) = armed.until else {
            armed = deadline
                .changed
                .wait(armed)
                .unwrap_or_else(PoisonError::into_inner);
            continue;
        };
        let now = Instant::now();
        if now < until {
            armed = deadline
                .changed
                .wait_timeout(armed, until - now)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
            continue;
        }
        armed.until = None;
        armed.fired = true;
        // Under the lock, so the next call cannot arm before this cancel
        // has reached the read it was meant for.
        shared.cancel_asking();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "node")]
    use crate::plane::Remote;
    #[cfg(feature = "node")]
    use crate::plane::local::{Acceptor, place};

    #[test]
    fn a_wait_is_said_in_seconds_or_milliseconds() {
        assert_eq!(
            not_answered(Duration::from_secs(2)),
            "the node did not answer within 2 s"
        );
        assert_eq!(
            not_answered(Duration::from_millis(150)),
            "the node did not answer within 150 ms"
        );
    }

    /// Decided by the owner, 2026-10-13: *a local call waits at most a set
    /// time, then says the node did not answer and shows it so.* An
    /// endpoint that takes the connection and never answers stands for a
    /// hung node: the node's end, so only where the node is built.
    #[cfg(feature = "node")]
    #[test]
    fn a_node_that_does_not_answer_within_the_wait_is_unreachable_at_once_after() {
        let name = format!("xmip-deadline-test-{}", std::process::id());
        let acceptor = Acceptor::bind(&place(&name).expect("a name")).expect("bound");
        let held = std::thread::spawn(move || acceptor.accept().map(|stream| (stream, acceptor)));
        let within = Duration::from_millis(150);
        let surface = Remote::local_retrying(&name, within, vec![Duration::from_secs(60)])
            .expect("a surface");

        let asked = Instant::now();
        let said = surface.publication().expect_err("no answer");
        assert!(asked.elapsed() < within * 4, "{:?}", asked.elapsed());
        assert!(said.ends_with(&not_answered(within)), "{said}");
        assert!(!surface.state().reachable);
        // Said at once from now on, while the follow recovers it.
        let again = Instant::now();
        assert!(surface.publication().is_err());
        assert!(again.elapsed() < Duration::from_millis(10));
        drop(surface);
        drop(held.join());
    }
}
