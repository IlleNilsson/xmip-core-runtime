//! What this node let go of while a read of a queue was under way: each
//! Message whose pass settled here, by its queue, and when, kept while a
//! read of that queue that began before it is under way (ADR-0018,
//! amendment 2026-11-15).
//!
//! **A scan never takes a Message this node settled after its read
//! began.** What the read showed of it — due, not failed, no claim — is
//! what the Ledger held while its pass was under way here: the read is that
//! pass's past. The next scan, whose read comes after, finds the Message as
//! the pass left it, and every settle that leaves it to be sent again asks
//! for that scan or wakes for it. Until 2026-11-15 such a scan claimed it
//! for a moment, to read it under that claim and give it back: an
//! operator's act on a failed Message in that moment was refused as
//! claimed by another, and another node could not claim a Message waiting
//! for its retry.
//!
//! **A read of a queue is under way** while a scan of it reads, while a page
//! a wake brought of it waits to be read, and while the step's watch waits:
//! what the answer brings was read by the Storage node no earlier than the
//! wait was asked (`crate::queue_watch`). A scan reading such a page tells
//! each of its entries apart from what was settled here since that wait
//! was asked, and reads from the page as it came: a Message sent while the
//! next is published, the next one's wait asked before the first settled,
//! is no reason to read the queue again. A page read before a settle no
//! longer kept is not read from; its queue is read again.
//!
//! **What is kept is bounded.** Of each queue, each settle at or after the
//! oldest read of it under way, none once none is, the rest let go of as
//! each settle of it is kept and as each scan of it ends. The watch asks a
//! wait anew within each `[tuning] send_scan`, its bound, and every queue
//! is scanned at that interval, so what is kept of a queue is at most what
//! this node settles of it within one wait of the watch and the scan that
//! reads past it: the Messages of that queue it sends in that time, never
//! another queue's.

use std::collections::{HashMap, VecDeque};

use xcore::JourneyId;

use super::{SendStep, State};
use crate::queue_watch::Woken;

/// The settles kept for the reads under way, each moment a reading of the
/// step's Clock (ADR-0068, amendment 2026-11-15).
#[derive(Debug, Default)]
pub(super) struct Settles {
    /// By queue, each Message of it let go of while a read of it was under
    /// way, and when, oldest first.
    kept: HashMap<u128, VecDeque<(i128, JourneyId)>>,
    /// Each scan under way: its number, its queue, and when its read began.
    scans: Vec<(u64, u128, i128)>,
    /// The pages wakes brought that the dispatching took to read: each
    /// one's queue, and when its wait was asked.
    taken: Vec<(u128, i128)>,
    /// The next scan's number.
    numbered: u64,
    /// By queue, the latest settle of it not kept, or let go of: a read of
    /// it begun no later cannot be told apart from it.
    forgot: HashMap<u128, i128>,
}

impl SendStep {
    /// What a Message let go of now is kept against: when the watch's wait
    /// under way was asked, where one is, and now, both on the step's Clock.
    pub(super) fn letting_go(&self) -> (Option<i128>, i128) {
        (self.watch.asked(), self.clock.monotonic_nanos())
    }
}

impl Settles {
    /// Whether `id`, of `queue`, was let go of at `from` or after.
    fn after(&self, (queue, from): (u128, i128), id: JourneyId) -> bool {
        self.kept.get(&queue).is_some_and(|kept| {
            kept.iter()
                .rev()
                .take_while(|(at, _)| *at >= from)
                .any(|(_, settled)| *settled == id)
        })
    }

    /// What is kept of `queue` from before `oldest` let go of, all of it
    /// where no read of it is under way.
    fn let_go_before(&mut self, queue: u128, oldest: Option<i128>) {
        let Self { kept, forgot, .. } = self;
        let Some(of) = kept.get_mut(&queue) else {
            return;
        };
        while let Some(&(at, _)) = of.front() {
            if oldest.is_some_and(|oldest| at >= oldest) {
                break;
            }
            of.pop_front();
            let latest = forgot.entry(queue).or_insert(at);
            *latest = (*latest).max(at);
        }
        if of.is_empty() {
            kept.remove(&queue);
        }
    }
}

impl State {
    /// When the oldest read of `queue` under way began: a scan of it, a
    /// page a wake brought of it, or the watch's wait, asked at `waiting`.
    fn oldest_read(&self, queue: u128, waiting: Option<i128>) -> Option<i128> {
        let settles = &self.settles;
        let scans = settles
            .scans
            .iter()
            .filter(|(_, of, _)| *of == queue)
            .map(|(_, _, from)| *from);
        let taken = settles
            .taken
            .iter()
            .filter(|(of, _)| *of == queue)
            .map(|(_, asked)| *asked);
        let pages = self
            .woken
            .iter()
            .filter(|(of, _)| *of == queue)
            .map(|(_, woken)| woken.asked);
        scans.chain(taken).chain(pages).chain(waiting).min()
    }

    /// The Message of the Journey `id`, of `queue`, this node held, let go
    /// of `now` — its pass settled, or its claim found another's — and kept
    /// while a read of `queue` begun before then is under way, the watch's
    /// wait asked at `waiting` among them ([`SendStep::letting_go`]).
    pub(super) fn let_go(
        &mut self,
        (id, queue): (JourneyId, u128),
        (waiting, now): (Option<i128>, i128),
    ) {
        self.owned.remove(&id);
        let oldest = self.oldest_read(queue, waiting);
        self.settles.let_go_before(queue, oldest);
        if oldest.is_some() {
            self.settles
                .kept
                .entry(queue)
                .or_default()
                .push_back((now, id));
        } else {
            self.settles.forgot.insert(queue, now);
        }
    }

    /// The pages wakes brought, `woken`, taken to be read: each a read under
    /// way until the dispatching takes the next.
    pub(super) fn took_pages(&mut self, woken: &[(u128, Woken)]) {
        self.settles.taken = woken
            .iter()
            .map(|(queue, woken)| (*queue, woken.asked))
            .collect();
    }
}

/// A scan's read of a queue, from when it began until the scan ends: what
/// this node settled of it since, told apart.
pub(super) struct ScanRead<'a> {
    step: &'a SendStep,
    number: u64,
    queue: u128,
    from: i128,
}

impl<'a> ScanRead<'a> {
    /// A scan of `queue` by `step`, its read beginning now.
    pub(super) fn begun(step: &'a SendStep, queue: u128) -> Self {
        let mut state = step.lock();
        let settles = &mut state.settles;
        let (number, from) = (settles.numbered, step.clock.monotonic_nanos());
        settles.numbered += 1;
        settles.scans.push((number, queue, from));
        Self {
            step,
            number,
            queue,
            from,
        }
    }

    /// Its read begun where a wake's page was read, its wait asked at
    /// `asked`: whether every settle of its queue since is kept, and then its
    /// read begins there; otherwise the page is not to be read from.
    pub(super) fn reads_wake(&mut self, asked: i128) -> bool {
        let mut state = self.step.lock();
        let settles = &mut state.settles;
        if settles
            .forgot
            .get(&self.queue)
            .is_some_and(|forgot| *forgot >= asked)
        {
            return false;
        }
        self.from = self.from.min(asked);
        if let Some(scan) = settles
            .scans
            .iter_mut()
            .find(|(number, _, _)| *number == self.number)
        {
            scan.2 = self.from;
        }
        true
    }

    /// Whether this node let go of the Message of the Journey `id` of its
    /// queue after this read began, as `state` holds it.
    pub(super) fn settled_since(&self, state: &State, id: JourneyId) -> bool {
        state.settles.after((self.queue, self.from), id)
    }
}

impl Drop for ScanRead<'_> {
    fn drop(&mut self) {
        let waiting = self.step.watch.asked();
        let mut state = self.step.lock();
        state
            .settles
            .scans
            .retain(|(number, _, _)| *number != self.number);
        let oldest = state.oldest_read(self.queue, waiting);
        state.settles.let_go_before(self.queue, oldest);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const QUEUE: u128 = 7;

    /// A reading of the step's clock, some way past its own moment.
    const NOW: i128 = 7_000_000_000;

    /// `n` milliseconds after `at`.
    fn later(at: i128, n: i128) -> i128 {
        at + n * 1_000_000
    }

    #[test]
    fn a_settle_after_a_read_began_is_told_and_one_before_it_is_not() {
        let at = NOW;
        let (first, second) = (JourneyId::new(1), JourneyId::new(2));
        let mut settles = Settles::default();
        let kept = VecDeque::from([(later(at, 1), first), (later(at, 2), second)]);
        settles.kept.insert(QUEUE, kept);
        assert!(
            settles.after((QUEUE, at), first),
            "settled after the read began"
        );
        assert!(
            settles.after((QUEUE, later(at, 2)), second),
            "at once is after"
        );
        assert!(
            !settles.after((QUEUE, later(at, 2)), first),
            "before that read"
        );
        assert!(
            !settles.after((QUEUE, at), JourneyId::new(3)),
            "never settled"
        );
        assert!(!settles.after((QUEUE + 1, at), first), "another queue's");
    }

    #[test]
    fn a_settle_is_kept_only_while_a_read_of_its_queue_is_under_way() {
        let id = JourneyId::new(1);
        let mut state = State::default();
        state.let_go((id, QUEUE), (None, NOW));
        assert!(
            state.settles.kept.is_empty(),
            "no read under way: none kept"
        );
        assert!(state.settles.forgot.contains_key(&QUEUE), "nor a read told");

        // The watch's wait under way, asked before it: kept for its page.
        let mut state = State::default();
        let asked = NOW;
        state.let_go((id, QUEUE), (Some(asked), later(asked, 1)));
        assert!(state.settles.after((QUEUE, asked), id), "kept for the wait");
        assert!(state.settles.forgot.is_empty());
    }

    #[test]
    fn what_is_kept_is_let_go_of_once_no_read_older_is_under_way() {
        let at = NOW;
        let id = JourneyId::new(1);
        let mut settles = Settles::default();
        let kept = VecDeque::from([(later(at, 2), id), (later(at, 4), id)]);
        settles.kept.insert(QUEUE, kept);
        settles.let_go_before(QUEUE, Some(later(at, 3)));
        assert_eq!(settles.kept[&QUEUE].len(), 1, "kept for the read under way");
        assert_eq!(settles.forgot[&QUEUE], later(at, 2), "the one let go of");
        settles.let_go_before(QUEUE, None);
        assert!(settles.kept.is_empty(), "none under way: none kept");
        assert_eq!(settles.forgot[&QUEUE], later(at, 4));
    }
}
