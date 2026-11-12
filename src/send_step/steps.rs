//! What each send took on this node, step by step, and the median of each
//! step over a Send Port's latest sends: what its snapshot publishes beside
//! its figures, so every surface shows where a delivery's time goes on the
//! sending node (open problem 46, 2026-11-12: *break the gap down per step,
//! with numbers per Storage call and per stage*).
//!
//! **Two ways a Message comes to be sent**, kept apart: handed in memory by
//! the node's own Publication, which claimed it in the same write, and
//! taken from its queue — woken by another node's write, or found by a
//! scan — which claims it and reads it back first. Each step is timed where
//! it is taken, each Storage call on its own: what is due, the claim, its
//! place, Journey and Message with its Stream's record — one request since
//! 2026-11-12 — its sequences, and the hand-on; and around them the stages:
//! the wake reaching the read of its queue, a send thread taking it up,
//! what it is sent under made durable — its Publication handed in memory,
//! its claim taken from its queue, the claim answered readable and its
//! sync waited on apart (ADR-0018, amendment 2026-11-12) — and the send
//! itself — its transform, its Stream's chunks, its transport, and the far
//! end's file made durable, after the far end can see it.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// How many of a Send Port's latest sends each way its medians are told
/// from.
pub const STEPS_KEPT: usize = 100;

/// One step of a send on this node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// From a wait's answer reaching the node to the read of its queue.
    Woken,
    /// The read of what is due in its queue: none where the wait's answer
    /// carried it.
    Due,
    /// From being found or handed to a send thread taking it up.
    Pool,
    /// The claim's answer, once readable: its sync is
    /// [`Step::Durable`]'s (ADR-0018, amendment 2026-11-12).
    Claim,
    /// The read under its claim of its place in its queue, its Journey and
    /// its Message with its Stream's record, as one request, and what of
    /// them was read apart.
    Read,
    /// The reads of whether it heads its sequences.
    Sequences,
    /// The wait for what it is sent under to be durable in the Ledger,
    /// beyond the send's own work meanwhile: its Publication, where it was
    /// handed before the Ledger synced it, or its claim, where it was taken
    /// ahead of its sync.
    Durable,
    /// The send apart from that wait: its transform, its Stream's chunks,
    /// its transport.
    Send,
    HandOn,
}

impl Step {
    /// Every step, in the order a send takes them.
    pub const ALL: [Self; 9] = [
        Self::Woken,
        Self::Due,
        Self::Pool,
        Self::Claim,
        Self::Read,
        Self::Sequences,
        Self::Durable,
        Self::Send,
        Self::HandOn,
    ];

    /// The step in words, as a Send Port's evidence says it.
    #[must_use]
    pub const fn words(self) -> &'static str {
        match self {
            Self::Woken => "the wake",
            Self::Due => "what is due",
            Self::Pool => "a send thread",
            Self::Claim => "the claim",
            Self::Read => "its place, Journey and Message",
            Self::Sequences => "its sequences",
            Self::Durable => "durable in the Ledger",
            Self::Send => "the send",
            Self::HandOn => "the hand-on",
        }
    }

    const fn at(self) -> usize {
        self as usize
    }
}

/// What one send took, step by step, and since when it waits for a send
/// thread.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Steps {
    took: [Option<Duration>; Step::ALL.len()],
    ready: Option<Instant>,
}

impl Steps {
    /// `step` took `took`.
    pub fn set(&mut self, step: Step, took: Duration) {
        self.took[step.at()] = Some(took);
    }

    /// `step` took `took` more than it took so far.
    pub fn add(&mut self, step: Step, took: Duration) {
        let so_far = self.took(step).unwrap_or_default();
        self.set(step, so_far + took);
    }

    /// What `step` took, where it was taken.
    #[must_use]
    pub fn took(&self, step: Step) -> Option<Duration> {
        self.took[step.at()]
    }

    /// Ready for a send thread from now on.
    pub fn ready(&mut self) {
        self.ready = Some(Instant::now());
    }

    /// A send thread took it up: how long it waited for one.
    pub fn taken_up(&mut self) {
        if let Some(ready) = self.ready.take() {
            self.set(Step::Pool, ready.elapsed());
        }
    }
}

/// A Send Port's latest sends each way, at most [`STEPS_KEPT`] of each.
#[derive(Clone, Debug, Default)]
pub(super) struct Kept {
    handed: VecDeque<Steps>,
    taken: VecDeque<Steps>,
}

impl Kept {
    /// One more send: handed in memory, or taken from its queue.
    pub(super) fn sent(&mut self, steps: Steps, handed: bool) {
        let kept = if handed {
            &mut self.handed
        } else {
            &mut self.taken
        };
        if kept.len() == STEPS_KEPT {
            kept.pop_front();
        }
        kept.push_back(steps);
    }

    /// The median of each step each way, in words; empty before a send
    /// timed any.
    pub(super) fn words(&self) -> String {
        [
            (&self.taken, "taken from its queue"),
            (&self.handed, "handed in memory"),
        ]
        .into_iter()
        .filter_map(|(kept, way)| {
            let steps: Vec<String> = Step::ALL
                .iter()
                .filter_map(|&step| {
                    median(kept.iter().filter_map(|steps| steps.took(step)))
                        .map(|took| format!("{} {}", step.words(), millis(took)))
                })
                .collect();
            (!steps.is_empty()).then(|| {
                format!(
                    "of its latest {} {way}, the median of each step here: {}",
                    kept.len(),
                    steps.join(", ")
                )
            })
        })
        .collect::<Vec<_>>()
        .join("; ")
    }
}

/// The median of `took`, where there is one.
fn median(took: impl Iterator<Item = Duration>) -> Option<Duration> {
    let mut took: Vec<Duration> = took.collect();
    took.sort();
    took.get(took.len() / 2).copied()
}

/// `took` in milliseconds, to a hundredth.
fn millis(took: Duration) -> String {
    format!("{:.2} ms", took.as_secs_f64() * 1000.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_way_says_the_median_of_each_step_it_took_and_keeps_its_latest() {
        let mut kept = Kept::default();
        assert_eq!(kept.words(), "", "before a send");
        for millis in [1, 3, 2] {
            let mut steps = Steps::default();
            steps.set(Step::Claim, Duration::from_millis(millis));
            steps.set(Step::Send, Duration::from_millis(10));
            kept.sent(steps, false);
        }
        let mut handed = Steps::default();
        handed.set(Step::Durable, Duration::from_micros(1500));
        kept.sent(handed, true);
        assert_eq!(
            kept.words(),
            "of its latest 3 taken from its queue, the median of each step here: the claim \
             2.00 ms, the send 10.00 ms; of its latest 1 handed in memory, the median of each \
             step here: durable in the Ledger 1.50 ms"
        );
        // Only the latest kept: the timed three gone, nothing said of them.
        for _ in 0..STEPS_KEPT {
            kept.sent(Steps::default(), false);
        }
        assert!(
            kept.words().starts_with("of its latest 1 handed in memory"),
            "{}",
            kept.words()
        );
    }

    #[test]
    fn a_send_thread_s_wait_is_from_ready_to_taken_up_once() {
        let mut steps = Steps::default();
        steps.taken_up();
        assert_eq!(steps.took(Step::Pool), None, "never ready");
        steps.ready();
        steps.taken_up();
        assert!(steps.took(Step::Pool).is_some());
        let took = steps.took(Step::Pool);
        steps.taken_up();
        assert_eq!(steps.took(Step::Pool), took, "once");
    }
}
