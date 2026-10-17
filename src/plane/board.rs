//! What a node's operate listener answers from: the node's publication as
//! the text its file holds (`observe::Publication`, ADR-0027), and the
//! revision that says it changed, which a surface following the node
//! waits on and is told by — never asks again and again (ADR-0052,
//! amendments 2026-09-15 and 2026-10-05).
//!
//! One trait, so a listener is handed what it answers from (ADR-0068), and
//! one source of it: a [`Board`] the program running the node posts each
//! publication to as it writes it — `xmip-service`, or a program hosting a
//! node through the C ABI (`xmip_operate_post_v1`).

use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use xcore::wake::Wake;

/// What an operate listener answers from.
pub trait Published: Send + Sync {
    /// The revision and the publication's text now; revision 0 is nothing
    /// published yet.
    fn read(&self) -> (u64, String);

    /// The revision once it is past `after`, or after `within` where it is
    /// not, or as soon as `stopped` says the listener stops — woken by
    /// [`Published::wake`], never by looking again.
    fn wait(&self, after: u64, within: Duration, stopped: &dyn Fn() -> bool) -> u64;

    /// Wake every wait, so it looks at `stopped`.
    fn wake(&self);

    /// An operator's act was taken on a node of this process: the program
    /// running it is told, so it publishes what changed at once rather
    /// than at its next round. Nothing where it is not told.
    fn acted(&self) {}
}

/// A publication posted by the program running the node.
#[derive(Default)]
pub struct Board {
    held: Mutex<(u64, String)>,
    changed: Wake,
}

impl Board {
    /// Post the node's publication as `text`: a new revision where it
    /// differs from the last, and every wait told.
    pub fn post(&self, text: String) {
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        if held.0 != 0 && held.1 == text {
            return;
        }
        held.0 += 1;
        held.1 = text;
        self.changed.notify_all();
    }
}

impl Published for Board {
    fn read(&self) -> (u64, String) {
        self.held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn wait(&self, after: u64, within: Duration, stopped: &dyn Fn() -> bool) -> u64 {
        let held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        let (held, _) = self
            .changed
            .wait_timeout_while(&self.held, held, within, |held| {
                held.0 <= after && !stopped()
            });
        held.0
    }

    fn wake(&self) {
        let _held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        self.changed.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Instant;

    use super::*;

    #[test]
    fn a_post_that_says_nothing_new_is_no_new_revision() {
        let board = Board::default();
        assert_eq!(board.read().0, 0);
        board.post("a".to_string());
        board.post("a".to_string());
        assert_eq!(board.read(), (1, "a".to_string()));
        board.post("b".to_string());
        assert_eq!(board.read().0, 2);
    }

    #[test]
    fn a_wait_is_told_when_a_post_arrives_and_not_before() {
        let board = Arc::new(Board::default());
        board.post("a".to_string());
        let waiting = {
            let board = Arc::clone(&board);
            std::thread::spawn(move || board.wait(1, Duration::from_secs(10), &|| false))
        };
        std::thread::sleep(Duration::from_millis(20));
        let posted = Instant::now();
        board.post("b".to_string());
        assert_eq!(waiting.join().expect("waited"), 2);
        assert!(posted.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn a_wait_ends_when_its_listener_stops() {
        let board = Arc::new(Board::default());
        let stopping = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let waiting = {
            let (board, stopping) = (Arc::clone(&board), Arc::clone(&stopping));
            std::thread::spawn(move || {
                board.wait(0, Duration::from_secs(30), &|| {
                    stopping.load(std::sync::atomic::Ordering::SeqCst)
                })
            })
        };
        std::thread::sleep(Duration::from_millis(20));
        let stopped = Instant::now();
        stopping.store(true, std::sync::atomic::Ordering::SeqCst);
        board.wake();
        assert_eq!(waiting.join().expect("waited"), 0);
        assert!(stopped.elapsed() < Duration::from_secs(1));
    }
}
