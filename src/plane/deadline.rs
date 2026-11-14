//! How long a local call may wait — decided by the owner, 2026-10-13: *a
//! local call waits at most a set time — `[tuning]`, default 2 s — then
//! says the node did not answer and shows it so; the tool recovers on its
//! own.*
//!
//! A socket's read keeps time itself (`net::watched`'s silence); a named
//! pipe's has none, so a call on a pipe is bounded by one thread for the
//! process that cancels a surface's asking line's read once its deadline
//! passes (`plane::local::Cancel`), and the follow's line's read the same
//! where its try — connect, handshake and the node's first answer — runs
//! past the same wait (`plane::follow`; 2026-11-13). The thread waits on nothing until a
//! call arms a deadline. Until 2026-10-21 each surface had a thread of its
//! own, whose start and wakes cost a connection on the local endpoint more
//! processor time than the rest of it (open problem 35).

use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};
use xcore::lock::Locked;

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
            let mut armed = self.armed.locked();
            armed.until = Some(until);
            armed.fired = false;
        }
        sooner(until);
    }

    /// The call ended: whether its deadline passed first.
    pub(crate) fn disarm(&self) -> bool {
        let mut armed = self.armed.locked();
        armed.until = None;
        std::mem::take(&mut armed.fired)
    }

    /// Whether the deadline of the call in flight has passed.
    pub(crate) fn passed(&self) -> bool {
        self.armed.locked().fired
    }

    /// Kept at `now` by the process's deadline thread: `cancel` the read of
    /// a call whose deadline passed, and again until its call has ended;
    /// when the thread looks next for this one, none while nothing is
    /// armed.
    fn kept(&self, now: Instant, cancel: impl Fn()) -> Option<Instant> {
        let mut armed = self.armed.locked();
        match (armed.fired, armed.until) {
            // Its call has not ended: `disarm` takes `fired`.
            (true, _) => {
                cancel();
                Some(now + AGAIN)
            }
            (false, Some(until)) if now >= until => {
                armed.until = None;
                armed.fired = true;
                // Under its lock, so the next call cannot arm before this
                // cancel has reached the read it was meant for.
                cancel();
                Some(now + AGAIN)
            }
            (false, until) => until,
        }
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
    crate::declared::standing(&crate::declared::directory())
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
    watcher.kept.locked().surfaces.push(Arc::downgrade(shared));
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
        let kept = watcher.kept.locked();
        if kept.looks.is_none_or(|looks| until < looks) {
            watcher.changed.notify_all();
        }
    }
}

/// A deadline a surface's line is kept to, and what cancels that line's
/// read once it passes.
type Keeping<'a> = (&'a Deadline, fn(&Shared));

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
    let mut kept = watcher.kept.locked();
    loop {
        let now = Instant::now();
        let mut next: Option<Instant> = None;
        kept.surfaces.retain(|weak| {
            let Some(shared) = weak.upgrade().filter(|shared| !shared.ending()) else {
                return false;
            };
            // The asking line's call, and the follow's try (`plane::follow`).
            let deadlines: [Keeping<'_>; 2] = [
                (&shared.deadline, Shared::cancel_asking),
                (&shared.trying, Shared::cancel_following),
            ];
            for (deadline, cancel) in deadlines {
                let due = deadline.kept(now, || cancel(&shared));
                next = match (next, due) {
                    (Some(next), Some(due)) => Some(next.min(due)),
                    (next, due) => next.or(due),
                };
            }
            true
        });
        kept.looks = next;
        kept = match next {
            Some(next) => watcher.changed.wait_until(&watcher.kept, kept, next).0,
            None => watcher.changed.wait(&watcher.kept, kept),
        };
    }
}

/// A hung node on this machine, as a test stands one up: a local endpoint
/// that takes a connection and never answers, so a surface's call on it
/// waits out its deadline. The node's end, so only where the node is
/// built; a test's, never a node's — the module's timing program's
/// (`tests/measured`) and this file's tests.
#[cfg(all(feature = "node", any(test, feature = "test-support")))]
pub struct Hung {
    path: std::path::PathBuf,
    held: Option<std::thread::JoinHandle<HungAccept>>,
}

/// What a [`Hung`] node's accept ends with: the connection it took and its
/// endpoint, kept open until both are let go.
#[cfg(all(feature = "node", any(test, feature = "test-support")))]
type HungAccept = std::io::Result<(crate::plane::local::Stream, crate::plane::local::Acceptor)>;

#[cfg(all(feature = "node", any(test, feature = "test-support")))]
impl Hung {
    /// A hung node at the local endpoint called `name`.
    ///
    /// # Panics
    ///
    /// Where `name` is no endpoint's name, or the endpoint does not bind.
    #[must_use]
    pub fn at(name: &str) -> Self {
        use crate::plane::local::{Acceptor, Admitting, place};
        let path = place(name).expect("a name");
        let acceptor = Acceptor::bind(&path, Admitting::default()).expect("bound");
        let held = std::thread::spawn(move || acceptor.accept().map(|stream| (stream, acceptor)));
        Self {
            path,
            held: Some(held),
        }
    }
}

#[cfg(all(feature = "node", any(test, feature = "test-support")))]
impl Drop for Hung {
    fn drop(&mut self) {
        if let Some(held) = self.held.take() {
            drop(accepted(held, &self.path));
        }
    }
}

/// `held`, a stand-in node's accept, joined once it has taken a
/// connection: knocked on until it has (`net::accepting::woken`). A client
/// that connected and left before the accept began is passed over by it,
/// and the accept waits for the next: joined bare, a stand-in kept from its
/// processor that long waited for good, and the test with it (2026-10-21,
/// beside eight processor-bound jobs).
#[cfg(all(feature = "node", any(test, feature = "test-support")))]
fn accepted<T>(held: std::thread::JoinHandle<T>, path: &Path) -> std::thread::Result<T> {
    net::accepting::woken(held, Duration::from_secs(1), || {
        crate::plane::local::wake(path)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(all(windows, feature = "node"))]
    use crate::plane::local::{Acceptor, Admitting, place};

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
        let acceptor = Acceptor::bind(&path, Admitting::default()).expect("bound");
        let held = std::thread::spawn(move || acceptor.accept().map(|stream| (stream, acceptor)));
        let mut stream =
            crate::plane::local::connect(&path, Duration::from_secs(5)).expect("connected");
        let shared = Arc::new(Shared {
            address: path.display().to_string(),
            reach: crate::plane::line::Reach::Local(path),
            patience: Duration::ZERO,
            deadline: Deadline::default(),
            trying: Deadline::default(),
            retry: Vec::new(),
            state: Mutex::new(crate::plane::remote::State::default()),
            told: Wake::new(),
            ending: Arc::new(AtomicBool::new(false)),
            connecting: AtomicBool::new(false),
            following: Mutex::new(None),
            follows: std::sync::OnceLock::new(),
            asking: Mutex::new(None),
            line: Mutex::new(None),
            #[cfg(feature = "node")]
            fresh: Mutex::default(),
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
}
