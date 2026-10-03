//! A dynamic, bounded pool of threads (`runtime-model.md` section 3,
//! *Threads, pools and chunks*; ADR-0018, amendment 2026-10-01): never
//! below one thread, growing while work waits up to its most — the
//! bulkhead of ADR-0018 clause 11 — and shrinking back after a thread has
//! waited its idle time with nothing to do. Threads are started ahead of
//! need, never per piece of work: a thread is started only when work waits
//! and none is free.
//!
//! The threads are scoped (`std::thread::Scope`), so work borrows what
//! outlives the scope — the node's Runtime, its Pickup, a Location's gate —
//! and nothing is copied to hand it over. Dropping the pool lets its
//! threads finish the work queued and end; the scope joins them.

use std::collections::VecDeque;
use std::panic::{self, AssertUnwindSafe};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::Scope;
use std::time::Duration;

/// How far a pool may grow, and how long a thread with nothing to do waits
/// before it ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// The most threads at once; one at least.
    pub most: usize,
    /// How long a thread waits with nothing to do before it ends, while
    /// more than one is left.
    pub idle: Duration,
}

/// A Receive Location's pool's threads for each of the machine's hardware
/// threads, where the node's `[tuning] receive_threads_per_hardware_thread`
/// does not say: two, since a receive thread waits on the Ledger's sync as
/// well as working, so more threads than the machine runs at once still pay.
pub const RECEIVE_THREADS_PER_HARDWARE_THREAD: usize = 2;

/// How long a receive thread with nothing to do waits before it ends, where
/// the node's `[tuning] receive_idle` does not say: a minute — the
/// assistant's drafting, 2026-10-02, for the owner to overrule.
pub const RECEIVE_IDLE: Duration = Duration::from_secs(60);

impl Limits {
    /// A Receive Location's pool, calculated from the machine as the node
    /// starts (the owner, 2026-10-03: *make a calculation according to CPU
    /// cores/threads*): `threads_per_hardware_thread` for each of its
    /// [`hardware_threads`], each idle for `idle` before it ends — what the
    /// node's `[tuning]` says (`crate::tuning`).
    #[must_use]
    pub fn receive(threads_per_hardware_thread: usize, idle: Duration) -> Self {
        Self {
            most: threads_per_hardware_thread.saturating_mul(hardware_threads()),
            idle,
        }
    }
}

/// The threads the machine runs at once for this process — its cores, and
/// each core's simultaneous threads, within what the platform allots the
/// process — and one where the platform does not say.
#[must_use]
pub fn hardware_threads() -> usize {
    std::thread::available_parallelism().map_or(1, std::num::NonZero::get)
}

/// One piece of work: it runs once, on whichever thread takes it.
pub type Work<'env> = Box<dyn FnOnce() + Send + 'env>;

struct State<'env> {
    queued: VecDeque<Work<'env>>,
    threads: usize,
    waiting: usize,
    closed: bool,
}

struct Shared<'env> {
    state: Mutex<State<'env>>,
    ready: Condvar,
    idle: Duration,
}

impl<'env> Shared<'env> {
    fn lock(&self) -> MutexGuard<'_, State<'env>> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A pool of threads in `scope`.
pub struct Pool<'scope, 'env> {
    scope: &'scope Scope<'scope, 'env>,
    shared: Arc<Shared<'env>>,
    most: usize,
}

impl<'scope, 'env> Pool<'scope, 'env> {
    /// A pool in `scope` within `limits`, its first thread started.
    #[must_use]
    pub fn new(scope: &'scope Scope<'scope, 'env>, limits: Limits) -> Self {
        let pool = Self {
            scope,
            shared: Arc::new(Shared {
                state: Mutex::new(State {
                    queued: VecDeque::new(),
                    threads: 1,
                    waiting: 0,
                    closed: false,
                }),
                ready: Condvar::new(),
                idle: limits.idle,
            }),
            most: limits.most.max(1),
        };
        pool.start();
        pool
    }

    /// Run `work` on a thread of the pool: a free one, or one started for
    /// it while the pool is below its most; otherwise it waits its turn.
    pub fn run(&self, work: Work<'env>) {
        let mut state = self.shared.lock();
        state.queued.push_back(work);
        let start = state.queued.len() > state.waiting && state.threads < self.most;
        if start {
            state.threads += 1;
        }
        drop(state);
        self.shared.ready.notify_one();
        if start {
            self.start();
        }
    }

    /// How many threads it has now.
    #[must_use]
    pub fn threads(&self) -> usize {
        self.shared.lock().threads
    }

    fn start(&self) {
        let shared = Arc::clone(&self.shared);
        self.scope.spawn(move || serve(&shared));
    }
}

impl Drop for Pool<'_, '_> {
    fn drop(&mut self) {
        self.shared.lock().closed = true;
        self.shared.ready.notify_all();
    }
}

/// A thread of the pool: it takes work until the pool is closed and
/// drained, or until it has waited its idle time while another is left.
///
/// **A piece of work that panics ends that piece, not the thread**: the
/// thread takes the next, so a panic never strands what is queued; what
/// the piece owed is its own to tell on the way out (`receiving`'s
/// telling). However the thread ends, it is counted out ([`Counted`]).
fn serve(shared: &Shared<'_>) {
    let mut counted = Counted { shared, out: false };
    let mut state = shared.lock();
    loop {
        if let Some(work) = state.queued.pop_front() {
            drop(state);
            let _ = panic::catch_unwind(AssertUnwindSafe(work));
            state = shared.lock();
            continue;
        }
        if state.closed {
            break;
        }
        state.waiting += 1;
        let (waited, timeout) = shared
            .ready
            .wait_timeout(state, shared.idle)
            .unwrap_or_else(PoisonError::into_inner);
        state = waited;
        state.waiting -= 1;
        if timeout.timed_out() && state.queued.is_empty() && state.threads > 1 {
            break;
        }
    }
    // Counted out under the lock that decided it may end, so two threads
    // idle at once never both see another left and leave none.
    state.threads -= 1;
    counted.out = true;
}

/// A pool thread's place in the count. A thread that returns gives it
/// back itself; one that unwinds gives it back here, so the pool never
/// believes in a thread it no longer has and starts one when work waits.
/// Until 2026-10-03 a thread that unwound stayed counted.
struct Counted<'a, 'env> {
    shared: &'a Shared<'env>,
    out: bool,
}

impl Drop for Counted<'_, '_> {
    fn drop(&mut self) {
        if !self.out {
            self.shared.lock().threads -= 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Instant;

    #[test]
    fn it_grows_while_work_waits_and_never_past_its_most() {
        let done = AtomicUsize::new(0);
        let together = Barrier::new(4);
        std::thread::scope(|scope| {
            let pool = Pool::new(
                scope,
                Limits {
                    most: 4,
                    idle: Duration::from_secs(60),
                },
            );
            for _ in 0..4 {
                pool.run(Box::new(|| {
                    // Four at once, or this never returns.
                    together.wait();
                    done.fetch_add(1, Ordering::Relaxed);
                }));
            }
            for _ in 0..8 {
                pool.run(Box::new(|| {
                    done.fetch_add(1, Ordering::Relaxed);
                }));
            }
            assert!(pool.threads() <= 4, "{}", pool.threads());
        });
        assert_eq!(done.load(Ordering::Relaxed), 12, "every piece ran");
    }

    #[test]
    fn it_shrinks_to_one_after_its_idle_time() {
        let together = Barrier::new(3);
        std::thread::scope(|scope| {
            let pool = Pool::new(
                scope,
                Limits {
                    most: 3,
                    idle: Duration::from_millis(20),
                },
            );
            for _ in 0..3 {
                pool.run(Box::new(|| {
                    together.wait();
                }));
            }
            let deadline = Instant::now() + Duration::from_secs(5);
            while pool.threads() > 1 && Instant::now() < deadline {
                std::thread::yield_now();
            }
            assert_eq!(pool.threads(), 1, "never below one, back to one");
        });
    }

    #[test]
    fn a_piece_that_panics_leaves_its_thread_taking_the_next() {
        let done = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            let pool = Pool::new(
                scope,
                Limits {
                    most: 1,
                    idle: Duration::from_secs(60),
                },
            );
            pool.run(Box::new(|| panic!("a piece that panics")));
            pool.run(Box::new(|| {
                done.fetch_add(1, Ordering::Relaxed);
            }));
            let deadline = Instant::now() + Duration::from_secs(5);
            while done.load(Ordering::Relaxed) == 0 && Instant::now() < deadline {
                std::thread::yield_now();
            }
            assert_eq!(pool.threads(), 1, "the thread is counted, and is there");
        });
        assert_eq!(done.load(Ordering::Relaxed), 1, "queued after it, ran");
    }
}
