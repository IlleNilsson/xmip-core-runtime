//! The turn a receive's ordered arrivals tell their far ends in: one
//! after another, in the order they came, however their carries end.

use std::sync::{Arc, Condvar, Mutex, PoisonError};

/// Whose turn it is to tell its far end: the place, among one receive's
/// arrivals, of the next to be told.
#[derive(Default)]
pub(super) struct Turn {
    next: Mutex<usize>,
    moved: Condvar,
}

/// One arrival's place in its receive's turn. Its turn passes when it has
/// told its far end, or when it is dropped without — a carry that panicked
/// — so the arrivals after it are never left waiting.
pub(super) struct Ticket {
    pub(super) turn: Arc<Turn>,
    pub(super) place: usize,
    pub(super) passed: bool,
}

impl Ticket {
    /// `tell` once every arrival before this one has told, and then the
    /// next one's turn.
    pub(super) fn in_turn<T>(mut self, tell: impl FnOnce() -> T) -> T {
        self.wait();
        let told = tell();
        self.pass();
        told
    }

    fn wait(&self) {
        let next = self
            .turn
            .next
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        drop(
            self.turn
                .moved
                .wait_while(next, |next| *next != self.place)
                .unwrap_or_else(PoisonError::into_inner),
        );
    }

    fn pass(&mut self) {
        self.passed = true;
        *self
            .turn
            .next
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = self.place + 1;
        self.turn.moved.notify_all();
    }
}
impl Drop for Ticket {
    fn drop(&mut self) {
        if !self.passed {
            self.wait();
            self.pass();
        }
    }
}
