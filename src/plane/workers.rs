//! The threads an operate listener answers its connections on, kept for
//! the next connection once one ends (open problem 35): a connection is
//! one thread, as every protocol in the estate is, and starting and ending
//! a thread for each cost a connection on the local endpoint about a fifth
//! of a millisecond of processor time on Windows (measured 2026-10-21). A
//! thread with nothing to answer waits for the next connection, at most
//! [`IDLE`] of them at once; the rest end. Stopping lets every waiting
//! thread go and joins every thread. A web host hands a browser's
//! handshake to each node it follows on threads kept alike
//! (`remote::relayed`), so a session's start waits on no thread's start.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use xcore::lock::Locked;

/// What a connection's thread runs.
type Work = Box<dyn FnOnce() + Send>;

/// How many threads wait for a connection at most.
const IDLE: usize = 8;

/// A listener's threads, or any work's kept alike.
pub(crate) struct Workers {
    /// What each thread is named.
    name: &'static str,
    /// Each waiting thread, by what hands it its next connection.
    idle: Mutex<Vec<Sender<Work>>>,
    threads: Mutex<Vec<JoinHandle<()>>>,
    stopped: AtomicBool,
}

impl Default for Workers {
    /// A listener's: each thread answers a connection.
    fn default() -> Self {
        Self::named("xmip-operate-connection")
    }
}

impl Workers {
    /// Threads named `name`.
    pub(crate) fn named(name: &'static str) -> Self {
        Self {
            name,
            idle: Mutex::default(),
            threads: Mutex::default(),
            stopped: AtomicBool::new(false),
        }
    }

    /// Run `work` on a waiting thread, else on a new one; nothing once
    /// stopped. Whether it runs.
    pub(crate) fn run(self: &Arc<Self>, work: Work) -> bool {
        if self.stopped.load(Ordering::SeqCst) {
            return false;
        }
        let waiting = self.idle.locked().pop();
        let work = match waiting {
            Some(next) => match next.send(work) {
                Ok(()) => return true,
                // That thread ended meanwhile: the work comes back.
                Err(mpsc::SendError(work)) => work,
            },
            None => work,
        };
        let workers = Arc::clone(self);
        let Ok(thread) = std::thread::Builder::new()
            .name(self.name.to_string())
            .spawn(move || workers.answering(work))
        else {
            return false;
        };
        let mut threads = self.threads.locked();
        threads.retain(|thread| !thread.is_finished());
        threads.push(thread);
        true
    }

    /// `work`, then each connection handed this thread while it waits,
    /// until no more wait or the listener stops.
    fn answering(&self, mut work: Work) {
        loop {
            work();
            let (next, handed) = mpsc::channel();
            {
                let mut idle = self.idle.locked();
                if self.stopped.load(Ordering::SeqCst) || idle.len() >= IDLE {
                    return;
                }
                idle.push(next);
            }
            // bounded: a stop drops every sender, and this receive ends
            match handed.recv() {
                Ok(handed) => work = handed,
                Err(_) => return,
            }
        }
    }

    /// Let every waiting thread go and join every thread that ends within
    /// `within`; each connection was ended first. One that does not is
    /// left to end alone.
    pub(crate) fn stop(&self, within: Duration) {
        self.stopped.store(true, Ordering::SeqCst);
        self.idle.locked().clear();
        let threads = std::mem::take(&mut *self.threads.locked());
        let until = Instant::now() + within;
        for thread in threads {
            while !thread.is_finished() && Instant::now() < until {
                std::thread::sleep(Duration::from_micros(200));
            }
            if thread.is_finished() {
                let _ = thread.join();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn a_thread_that_answered_answers_the_next_and_a_stop_lets_it_go() {
        let workers = Arc::new(Workers::default());
        let named = Arc::new(Mutex::new(Vec::new()));
        for _ in 0..3 {
            let named = Arc::clone(&named);
            assert!(workers.run(Box::new(move || {
                named
                    .lock()
                    .expect("names")
                    .push(std::thread::current().id());
            })));
            let until = Instant::now() + Duration::from_secs(5);
            while workers.idle.lock().expect("idle").is_empty() && Instant::now() < until {
                std::thread::yield_now();
            }
        }
        let named = named.lock().expect("names").clone();
        assert_eq!(named.len(), 3);
        assert!(
            named.iter().all(|id| *id == named[0]),
            "one thread: {named:?}"
        );
        workers.stop(Duration::from_secs(1));
        let ran = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&ran);
        assert!(!workers.run(Box::new(move || {
            counted.fetch_add(1, Ordering::SeqCst);
        })));
        assert_eq!(ran.load(Ordering::SeqCst), 0, "nothing runs once stopped");
    }
}
