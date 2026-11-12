//! Xmip Storage that fails on demand, lets another writer in first, or
//! loses a Publication's answer: what the runtime's tests race and break
//! Storage with, by the test's order rather than its luck; and that counts
//! and times what it is asked, what a timing program takes a node's Storage
//! work apart by.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use xcore::lock::Locked;

use persist::PersistError;
use persist::storage::XmipStorage;

mod storage;

/// An operation of Xmip Storage a [`Failing`] can be told to fail.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Operation {
    Publish,
    ReadHeld,
    ReadFailed,
    ReadDue,
    HandOn,
    Claim,
    Renew,
    ReadJourney,
    WriteJourney,
    ReadMessage,
    ReadChunk,
    WriteAdministration,
    ReadDead,
    Replay,
    WaitQueues,
}

/// What a [`Failing`] runs once, the next time an operation is asked,
/// before it answers: another writer's step, landed between two of the
/// caller's.
pub type Interleaved = Box<dyn FnOnce() + Send>;

/// Xmip Storage that fails on demand, as a Storage node that does not
/// answer: each operation told to fail does so the number of times it was
/// told, as `PersistError::Unreachable`, and every other call passes
/// through to the Storage beneath. An operation can also be told to let
/// another writer in first, once ([`Failing::before`]), or once it was
/// answered and before the caller has the answer ([`Failing::after`]), so a
/// race is a test's order rather than its luck; and a Publication's answer
/// can be lost, once ([`Failing::lose_answer`]).
pub struct Failing {
    beneath: Arc<dyn XmipStorage>,
    failing: Mutex<BTreeMap<Operation, u32>>,
    before: Mutex<BTreeMap<Operation, Interleaved>>,
    after: Mutex<BTreeMap<Operation, Interleaved>>,
    lost: Mutex<Option<Interleaved>>,
    /// Whether every wait on queues is answered at once with none moved,
    /// as a Storage node that ends each wait early would.
    at_once: AtomicBool,
    /// How often each operation was asked.
    counted: Mutex<BTreeMap<Operation, u64>>,
    /// How long each operation the Storage beneath answered took, in the
    /// order answered.
    taken: Mutex<BTreeMap<Operation, Vec<Duration>>>,
}

impl Failing {
    /// Failing nothing yet, over `beneath`.
    #[must_use]
    pub fn over(beneath: Arc<dyn XmipStorage>) -> Arc<Self> {
        Arc::new(Self {
            beneath,
            failing: Mutex::new(BTreeMap::new()),
            before: Mutex::new(BTreeMap::new()),
            after: Mutex::new(BTreeMap::new()),
            lost: Mutex::new(None),
            at_once: AtomicBool::new(false),
            counted: Mutex::new(BTreeMap::new()),
            taken: Mutex::new(BTreeMap::new()),
        })
    }

    /// The next Publication written beneath and its answer lost: `meanwhile`
    /// runs — another node's work landing before the answer would have
    /// come — and the Publication is asked again, as a Storage client asks
    /// the next Storage node when one does not answer, and that answer is
    /// the one given.
    pub fn lose_answer(&self, meanwhile: Interleaved) {
        *self.lost.locked() = Some(meanwhile);
    }

    /// Run `first` once, the next time `operation` is asked, before it is
    /// answered.
    pub fn before(&self, operation: Operation, first: Interleaved) {
        self.before.locked().insert(operation, first);
    }

    /// Run `then` once, the next time `operation` is answered by the Storage
    /// beneath, before the caller has the answer: another writer's step,
    /// landed between the caller's read and what it does with it.
    pub fn after(&self, operation: Operation, then: Interleaved) {
        self.after.locked().insert(operation, then);
    }

    /// Fail `operation` the next `times` it is asked; `u32::MAX` until
    /// [`Failing::heal`].
    pub fn fail(&self, operation: Operation, times: u32) {
        self.lock().insert(operation, times);
    }

    /// How often `operation` was asked so far: what a test counts a read
    /// by, a Stream's chunks read once for several readers among them.
    #[must_use]
    pub fn asked_times(&self, operation: Operation) -> u64 {
        self.counted.locked().get(&operation).copied().unwrap_or(0)
    }

    /// How long each time `operation` was answered so far took, from its
    /// asking to its answer, in the order answered; every one taken out.
    #[must_use]
    pub fn taken(&self, operation: Operation) -> Vec<Duration> {
        self.taken.locked().remove(&operation).unwrap_or_default()
    }

    /// Answer every wait on queues at once with none moved, from now on.
    pub fn answer_waits_at_once(&self) {
        self.at_once.store(true, Ordering::SeqCst);
    }

    /// Fail nothing any more.
    pub fn heal(&self) {
        self.lock().clear();
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<Operation, u32>> {
        self.failing.locked()
    }

    /// `operation` asked: counted, what was told to run first run, and
    /// when it was asked, or told to fail.
    fn asked(&self, operation: Operation) -> Result<Instant, PersistError> {
        let asked = Instant::now();
        *self.counted.locked().entry(operation).or_default() += 1;
        let first = self.before.locked().remove(&operation);
        if let Some(first) = first {
            first();
        }
        let mut failing = self.lock();
        let Some(left) = failing.get_mut(&operation) else {
            return Ok(asked);
        };
        if *left == 0 {
            return Ok(asked);
        }
        if *left != u32::MAX {
            *left -= 1;
        }
        Err(PersistError::Unreachable {
            reason: format!("{operation:?} told to fail"),
        })
    }

    /// `answer`, what the Storage beneath answered `operation` asked at
    /// `asked`, timed, and given once whatever was told to run after it ran.
    fn answered<T>(&self, operation: Operation, asked: Instant, answer: T) -> T {
        let took = asked.elapsed();
        self.taken.locked().entry(operation).or_default().push(took);
        let then = self.after.locked().remove(&operation);
        if let Some(then) = then {
            then();
        }
        answer
    }
}
