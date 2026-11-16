//! What the send step knows waits behind a Stream ahead of it in a
//! sequence (`crate::sequence`), its claim given back: a Message whose pass
//! found it does not head a sequence it holds a place in is taken up again
//! once it may — the moment what it waits on moves, never at every read of
//! its queue (`runtime-model.md` section 10; ADR-0018, amendment
//! 2026-11-15). Until 2026-11-15 every read of the queue claimed it again,
//! read it under the claim, found it still behind and gave the claim back:
//! a Message of eight senders at once was claimed three and a half times
//! and released three, each a write and a sync's wait, while the far end
//! waited.
//!
//! **Only the first behind a head that moved is taken up**, of each queue,
//! by a read of the queue begun after the move: a queue keeps its Messages
//! in the order the Ledger wrote them, the order of the places they hold in
//! each sequence, so the next of a sequence is the first of its queue
//! behind its head, and a read begun after the move meets it before the
//! rest. The rest wait for the head to move again. One taken up and found
//! behind waits as before, on the heads it read; one a read passes for
//! another reason — in a send here, being claimed, settled since the read
//! began — is taken up by the read its own pass or settle asks. A head this
//! node's own send heads is taken up by that send, as it heads and as it
//! ends (`super::beside`).
//!
//! **A read of every queue forgets it all** (`[tuning] send_scan`), the
//! bound on a wake that never came: what waits behind is claimed again
//! there, read, and found behind or sent.

use std::collections::HashMap;

use persist::storage::Watched;
use xcore::JourneyId;

/// The Messages known to wait behind a head, and the heads that moved.
#[derive(Debug, Default)]
pub(super) struct Behind {
    /// By Journey: the queue it waits in and the heads it waits on.
    waiting: HashMap<JourneyId, (u128, Vec<Watched>)>,
    /// Each head that moved, by a queue whose Messages wait on it, and the
    /// move the step was told it by ([`Behind::told`]): since a read of
    /// that queue last took up the first behind it.
    moved: HashMap<(u128, Watched), u64>,
    /// How many moves the step was told of: what tells a read begun before
    /// a move from one begun after it, an order kept under the step's lock
    /// and never a clock's reading (ADR-0068, amendment 2026-11-15).
    told: u64,
}

impl Behind {
    /// Where a read of a queue beginning now stands among the moves: one
    /// told from here on is the next read's to take up ([`Behind::takes`]).
    pub(super) const fn began(&self) -> u64 {
        self.told
    }

    /// The next move told.
    fn tell(&mut self) -> u64 {
        self.told += 1;
        self.told
    }

    /// The Message of `journey`, in `queue`, found waiting on `heads`.
    pub(super) fn waits(&mut self, journey: JourneyId, queue: u128, heads: Vec<Watched>) {
        self.waiting.insert(journey, (queue, heads));
    }

    /// `watched` moved, which a Message of `queue` waited on: whether more
    /// than one wait on it there, which the watch is then to wait on again
    /// from where it stands now — it let go of it as it moved, and the
    /// first, once taken up, names it no more.
    pub(super) fn moved(&mut self, queue: u128, watched: Watched) -> bool {
        let told = self.tell();
        self.moved.insert((queue, watched), told);
        self.more_than_one(queue, watched)
    }

    /// Whether more than one Message of `queue` waits on `watched`.
    pub(super) fn more_than_one(&self, queue: u128, watched: Watched) -> bool {
        self.waiting
            .values()
            .filter(|(kept, heads)| *kept == queue && heads.contains(&watched))
            .nth(1)
            .is_some()
    }

    /// `watched` taken as moved in every queue a Message waits on it in,
    /// which are said: the first behind it in each is taken up by the next
    /// read of that queue.
    pub(super) fn take_up(&mut self, watched: Watched) -> Vec<u128> {
        let mut queues: Vec<u128> = self
            .waiting
            .values()
            .filter(|(_, heads)| heads.contains(&watched))
            .map(|(queue, _)| *queue)
            .collect();
        queues.sort_unstable();
        queues.dedup();
        let told = self.tell();
        for queue in &queues {
            self.moved.insert((*queue, watched), told);
        }
        queues
    }

    /// Whether a read of `queue` begun where `began` says
    /// ([`Behind::began`]) takes up the Message of `journey` now: where it
    /// is not known to wait, or one of the heads it waits on moved before
    /// the read began and it is the first of the queue the read finds
    /// behind it — the move then taken, the rest behind it left to wait.
    pub(super) fn takes(&mut self, journey: JourneyId, queue: u128, began: u64) -> bool {
        let Some((_, heads)) = self.waiting.get(&journey) else {
            return true;
        };
        let Some(head) = heads.iter().copied().find(|head| {
            self.moved
                .get(&(queue, *head))
                .is_some_and(|moved| *moved <= began)
        }) else {
            return false;
        };
        self.moved.remove(&(queue, head));
        self.waiting.remove(&journey);
        true
    }

    /// Everything forgotten: a read of every queue takes it all up again.
    pub(super) fn forget(&mut self) {
        self.waiting.clear();
        self.moved.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const QUEUE: u128 = 7;
    const HEAD: Watched = Watched::Head(11);

    #[test]
    fn a_message_behind_is_taken_up_once_its_head_moves_and_only_the_first() {
        let (first, second) = (JourneyId::new(1), JourneyId::new(2));
        let mut behind = Behind::default();
        assert!(behind.takes(first, QUEUE, behind.began()), "not known");
        behind.waits(first, QUEUE, vec![HEAD]);
        behind.waits(second, QUEUE, vec![HEAD]);
        assert!(!behind.takes(first, QUEUE, behind.began()), "not moved");

        assert!(!behind.moved(QUEUE, Watched::Head(12)), "none waits on it");
        assert!(!behind.takes(first, QUEUE, behind.began()), "another moved");
        assert!(behind.moved(QUEUE, HEAD), "two wait on it");
        let read = behind.began();
        assert!(behind.takes(first, QUEUE, read), "the first behind it");
        assert!(!behind.takes(second, QUEUE, read), "the next waits for it");
        assert!(
            behind.takes(first, QUEUE, read),
            "taken up, no longer known"
        );

        assert!(!behind.moved(QUEUE, HEAD), "one waits on it now");
        assert!(behind.takes(second, QUEUE, behind.began()), "its turn");
    }

    #[test]
    fn a_head_that_moved_after_a_read_began_is_left_for_the_next() {
        let journey = JourneyId::new(1);
        let mut behind = Behind::default();
        behind.waits(journey, QUEUE, vec![HEAD]);
        let read = behind.began();
        behind.moved(QUEUE, HEAD);
        assert!(
            !behind.takes(journey, QUEUE, read),
            "it may have passed the first"
        );
        assert!(
            behind.takes(journey, QUEUE, behind.began()),
            "the next read's"
        );
    }

    #[test]
    fn a_head_moved_for_one_queue_takes_up_nothing_of_another() {
        let journey = JourneyId::new(1);
        let mut behind = Behind::default();
        behind.waits(journey, QUEUE, vec![HEAD]);
        behind.moved(QUEUE + 1, HEAD);
        assert!(!behind.takes(journey, QUEUE, behind.began()));
    }

    #[test]
    fn a_head_taken_up_is_moved_in_every_queue_that_waits_on_it() {
        let (here, there) = (JourneyId::new(1), JourneyId::new(2));
        let mut behind = Behind::default();
        behind.waits(here, QUEUE, vec![HEAD]);
        behind.waits(there, QUEUE + 1, vec![HEAD]);
        assert_eq!(behind.take_up(HEAD), vec![QUEUE, QUEUE + 1]);
        let read = behind.began();
        assert!(behind.takes(here, QUEUE, read) && behind.takes(there, QUEUE + 1, read));
        assert!(
            behind.take_up(Watched::Head(12)).is_empty(),
            "none waits on it"
        );
    }

    #[test]
    fn a_read_of_every_queue_forgets_what_waits() {
        let journey = JourneyId::new(1);
        let mut behind = Behind::default();
        behind.waits(journey, QUEUE, vec![HEAD]);
        behind.forget();
        assert!(behind.takes(journey, QUEUE, behind.began()));
    }
}
