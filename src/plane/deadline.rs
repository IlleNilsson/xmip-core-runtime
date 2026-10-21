//! How long a local call may wait — decided by the owner, 2026-10-13: *a
//! local call waits at most a set time — `[tuning]`, default 2 s — then
//! says the node did not answer and shows it so; the tool recovers on its
//! own.*
//!
//! A socket's read keeps time itself (`net::watched`'s silence); a named
//! pipe's has none, so a call on a pipe is bounded by one thread for the
//! process that cancels a surface's asking line's read once its deadline
//! passes (`plane::local::Cancel`). The thread waits on nothing until a
//! call arms a deadline. Until 2026-10-21 each surface had a thread of its
//! own, whose start and wakes cost a connection on the local endpoint more
//! processor time than the rest of it (open problem 35).

use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock, PoisonError, Weak};
use std::time::{Duration, Instant};

use xcore::wake::Wake;

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
}

impl Deadline {
    /// A call begins: it may wait `within`.
    pub(crate) fn arm(&self, within: Duration) {
        let until = Instant::now() + within;
        {
            let mut armed = self.armed.lock().unwrap_or_else(PoisonError::into_inner);
            armed.until = Some(until);
            armed.fired = false;
        }
        sooner(until);
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

/// Every surface whose calls the process's deadline thread keeps, and
/// when the thread looks at them next: `None` while it waits to be told.
#[derive(Default)]
struct Kept {
    surfaces: Vec<Weak<Shared>>,
    looks: Option<Instant>,
}

/// What the process's deadline thread keeps, and what wakes it.
#[derive(Default)]
struct Watcher {
    kept: Mutex<Kept>,
    changed: Wake,
}

static WATCHER: OnceLock<Watcher> = OnceLock::new();

/// Keep `shared`'s calls to their deadline: on a named pipe, by the
/// process's deadline thread for as long as the surface lives, started
/// with the first; elsewhere the line's own silence does. A surface ended
/// or dropped is let go at the thread's next look.
pub(crate) fn kept(shared: &Arc<Shared>) {
    if !cfg!(windows) {
        return;
    }
    let mut first = false;
    let watcher = WATCHER.get_or_init(|| {
        first = true;
        Watcher::default()
    });
    watcher
        .kept
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .surfaces
        .push(Arc::downgrade(shared));
    if first {
        // Detached: it keeps every local surface the process opens.
        let _ = std::thread::Builder::new()
            .name("xmip-operate-deadline".to_string())
            .spawn(move || watch(watcher));
    }
}

/// A deadline armed for `until`: the thread woken only where it would look
/// later, so a call made while it already waits for an earlier one costs no
/// wake. Under its lock, so a deadline armed after it looked at a surface
/// is never lost before it waits.
fn sooner(until: Instant) {
    if let Some(watcher) = WATCHER.get() {
        let kept = watcher.kept.lock().unwrap_or_else(PoisonError::into_inner);
        if kept.looks.is_none_or(|looks| until < looks) {
            watcher.changed.notify_all();
        }
    }
}

/// How long a passed deadline's cancel waits for its call to end before it
/// cancels again.
const AGAIN: Duration = Duration::from_millis(1);

/// Watch every kept surface's deadline, cancelling its asking line's read
/// whenever one passes, and again each [`AGAIN`] until its call has ended;
/// a surface ended or dropped is let go. A cancel reaches only a read in
/// flight: one made while the call was still connecting, or before its
/// thread, kept from its processor, began the read, is lost, and the read
/// then waited for good — the runtime's deadline test hung beside eight
/// processor-bound jobs (2026-10-21). Until then a passed deadline
/// cancelled once.
fn watch(watcher: &Watcher) {
    let mut kept = watcher.kept.lock().unwrap_or_else(PoisonError::into_inner);
    loop {
        let now = Instant::now();
        let mut next: Option<Instant> = None;
        kept.surfaces.retain(|weak| {
            let Some(shared) = weak.upgrade().filter(|shared| !shared.ending()) else {
                return false;
            };
            let mut armed = shared
                .deadline
                .armed
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let due = match (armed.fired, armed.until) {
                // Its call has not ended: `disarm` takes `fired`.
                (true, _) => {
                    shared.cancel_asking();
                    Some(now + AGAIN)
                }
                (false, Some(until)) if now >= until => {
                    armed.until = None;
                    armed.fired = true;
                    // Under its lock, so the next call cannot arm before
                    // this cancel has reached the read it was meant for.
                    shared.cancel_asking();
                    Some(now + AGAIN)
                }
                (false, until) => until,
            };
            next = match (next, due) {
                (Some(next), Some(due)) => Some(next.min(due)),
                (next, due) => next.or(due),
            };
            true
        });
        kept.looks = next;
        kept = match next {
            Some(next) => watcher.changed.wait_until(&watcher.kept, kept, next).0,
            None => watcher.changed.wait(&watcher.kept, kept),
        };
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
        let acceptor = Acceptor::bind(&place(&name).expect("a name"), &[]).expect("bound");
        let held = std::thread::spawn(move || acceptor.accept().map(|stream| (stream, acceptor)));
        let within = Duration::from_millis(150);
        let surface = Remote::local_retrying(&name, within, vec![Duration::from_secs(60)])
            .expect("a surface");

        let asked = Instant::now();
        let said = surface.publication().expect_err("no answer");
        assert!(asked.elapsed() < within * 4, "{:?}", asked.elapsed());
        assert!(said.ends_with(&not_answered(within)), "{said}");
        assert!(!surface.state().reachable);
        // Said at once from now on, while the follow recovers it: the
        // fastest of five under the millisecond, and no more than that of
        // the caller's processor time in any (xcore::latency::at_once).
        let (again, fastest, spent) =
            xcore::latency::at_once("a hung node, asked again", || surface.publication());
        assert!(again.is_err());
        assert!(fastest < Duration::from_millis(1), "said in {fastest:?}");
        assert!(
            spent < Duration::from_millis(1),
            "{spent:?} of processor time"
        );
        drop(surface);
        drop(accepted(held, &place(&name).expect("a name")));
    }

    /// A read begun only after its call's deadline passed — the asking
    /// thread kept from its processor that long — is cancelled still: the
    /// deadline cancels again until its call has ended.
    #[cfg(all(windows, feature = "node"))]
    #[test]
    fn a_read_begun_after_its_deadline_passed_is_cancelled_still() {
        use std::io::Read;
        use std::sync::atomic::{AtomicBool, Ordering};

        let name = format!("xmip-deadline-late-{}", std::process::id());
        let path = place(&name).expect("a name");
        let acceptor = Acceptor::bind(&path, &[]).expect("bound");
        let held = std::thread::spawn(move || acceptor.accept().map(|stream| (stream, acceptor)));
        let mut stream =
            crate::plane::local::connect(&path, Duration::from_secs(5)).expect("connected");
        let shared = Arc::new(Shared {
            address: path.display().to_string(),
            reach: crate::plane::line::Reach::Local(path),
            patience: Duration::ZERO,
            deadline: Deadline::default(),
            retry: Vec::new(),
            state: Mutex::new(crate::plane::remote::State::default()),
            told: Wake::new(),
            ending: Arc::new(AtomicBool::new(false)),
            connecting: AtomicBool::new(false),
            following: Mutex::new(None),
            asking: Mutex::new(None),
        });
        kept(&shared);

        shared.deadline.arm(Duration::ZERO);
        while !shared.deadline.passed() {
            std::thread::yield_now();
        }
        *shared.asking.lock().expect("the slot") = Some(stream.cancel());
        let read = stream.read(&mut [0u8; 1]);

        assert!(read.is_err(), "cancelled, not answered: {read:?}");
        assert!(shared.deadline.disarm(), "the deadline passed first");
        shared.ending.store(true, Ordering::SeqCst);
        drop(stream);
        drop(accepted(held, &place(&name).expect("a name")));
    }

    /// `held`, a stand-in node's accept, joined once it has taken a
    /// connection: knocked on until it has (`net::accepting::woken`). A
    /// client that connected and left before the accept began is passed
    /// over by it, and the accept waits for the next: joined bare, a
    /// stand-in kept from its processor that long waited for good, and the
    /// test with it (2026-10-21, beside eight processor-bound jobs).
    #[cfg(feature = "node")]
    fn accepted<T>(held: std::thread::JoinHandle<T>, path: &Path) -> std::thread::Result<T> {
        net::accepting::woken(held, Duration::from_secs(1), || {
            crate::plane::local::wake(path)
        })
    }
}
