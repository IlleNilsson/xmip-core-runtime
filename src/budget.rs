//! What a node holds at once across its pools, beside each pool's own bound
//! (`runtime-model.md` section 3, *Threads, pools and chunks*; open problem
//! 38): the arrivals its Receive Locations carry, the bytes of Streams
//! those carries hold, and the bytes of Messages its sends hold.
//!
//! **A pool bounds threads; a budget bounds what they hold.** Each Receive
//! Location keeps a pool of its own, its isolation, so a node of many
//! Locations had no ceiling of its own; the Send pool admitted a count of
//! Messages, whatever their size. A [`Budget`] is that ceiling: a carry or a
//! send holds its charge from it while it runs, and one with no room waits
//! for a holder to let go — nothing is dropped, refused or taken from a far
//! end that has no room. A charge above the whole budget waits until it is
//! alone and holds all of it, so nothing is too large to go: one at a time.
//!
//! Every budget is the node's `[tuning]`, a default only (`crate::tuning`):
//! per hardware thread, as the pools are, and in chunks, as the Ledger
//! writes and reads a Stream.

use std::sync::{Mutex, MutexGuard, PoisonError};

use xcore::wake::Wake;

use crate::tuning::Tuning;

/// The arrivals the node carries at once across all its Receive Locations
/// for each of the machine's hardware threads, where the node's `[tuning]
/// node_receive_threads_per_hardware_thread` does not say: four, twice one
/// Location's pool, so two Locations at their most still carry together —
/// the assistant's drafting, 2026-10-19, for the owner to overrule.
pub const NODE_RECEIVE_THREADS_PER_HARDWARE_THREAD: usize = 4;

/// The chunks of Streams the node's carries hold, for each arrival it
/// carries at once, where `[tuning] receive_chunks_per_thread` does not say:
/// what one carry holds ([`CARRY_CHUNKS`]), so by default the carries bound
/// the bytes, and a node set lower holds fewer bytes than carries.
pub const RECEIVE_CHUNKS_PER_THREAD: usize = CARRY_CHUNKS as usize;

/// The chunks of Messages the node's sends hold, for each thread of the
/// Send pool, where `[tuning] send_chunks_per_thread` does not say: sixteen,
/// about a mebibyte each, so a send that streams ([`STREAM_CHUNKS`]) never
/// waits for bytes before the pool is full, and Messages a transport gathers
/// whole wait for room once they hold that much — the assistant's
/// drafting, 2026-10-19, for the owner to overrule.
pub const SEND_CHUNKS_PER_THREAD: usize = 16;

/// The chunks one carry holds at most: the chunk it writes to the Ledger
/// and the one it reads ahead, and what Xmip Storage encodes and seals of
/// the chunk written — measured 2026-10-19 at seven chunks at most for a
/// Stream of 64 MiB (`tests/ledger/bounded.rs`), counted as eight.
pub const CARRY_CHUNKS: u64 = 8;

/// The chunks one send that streams holds at most, of a Message a chunk or
/// more long: what Xmip Storage reads, opens and decodes of a chunk, the
/// chunk lent to the transport, and the piece it writes on — measured
/// 2026-10-19 at a little over five chunks for a Message of 64 MiB
/// (`tests/ledger/send_streamed.rs`), counted as six.
pub const STREAM_CHUNKS: u64 = 6;

/// A quantity held at once — arrivals carried, bytes in memory — and at
/// most `most` of it.
#[derive(Debug)]
pub struct Budget {
    most: u64,
    held: Mutex<u64>,
    wake: Wake,
}

impl Budget {
    /// At most `most`, one at least, held at once.
    #[must_use]
    pub fn new(most: u64) -> Self {
        Self {
            most: most.max(1),
            held: Mutex::new(0),
            wake: Wake::new(),
        }
    }

    /// The most it lets be held at once.
    #[must_use]
    pub const fn most(&self) -> u64 {
        self.most
    }

    /// What is held now.
    #[must_use]
    pub fn held(&self) -> u64 {
        *self.lock()
    }

    /// `charge` held, once there is room for it: at once where there is,
    /// otherwise after holders let go. A charge above [`Budget::most`]
    /// waits until nothing else is held and holds all of it.
    #[must_use]
    pub fn hold(&self, charge: u64) -> Held<'_> {
        let charge = charge.min(self.most);
        let mut held = self.lock();
        while *held > 0 && *held + charge > self.most {
            held = self.wake.wait(&self.held, held);
        }
        *held += charge;
        Held {
            budget: self,
            charge,
        }
    }

    /// As much as there is room for now, up to `wanted`, waiting for room
    /// for one where there is none: what a receive asks before it takes at
    /// most that many arrivals.
    #[must_use]
    pub fn hold_up_to(&self, wanted: u64) -> Held<'_> {
        let wanted = wanted.clamp(1, self.most);
        let mut held = self.lock();
        while *held >= self.most {
            held = self.wake.wait(&self.held, held);
        }
        let charge = wanted.min(self.most - *held);
        *held += charge;
        Held {
            budget: self,
            charge,
        }
    }

    fn lock(&self) -> MutexGuard<'_, u64> {
        self.held.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn release(&self, charge: u64) {
        if charge == 0 {
            return;
        }
        let mut held = self.lock();
        *held = held.saturating_sub(charge);
        drop(held);
        self.wake.notify_all();
    }
}

/// A charge held from a [`Budget`], let go of when it is dropped.
#[derive(Debug)]
pub struct Held<'a> {
    budget: &'a Budget,
    charge: u64,
}

impl<'a> Held<'a> {
    /// What it holds.
    #[must_use]
    pub const fn charge(&self) -> u64 {
        self.charge
    }

    /// `charge` of it split off into a hold of its own, at most what it
    /// holds: one arrival's place out of those a receive was given.
    #[must_use]
    pub fn split(&mut self, charge: u64) -> Held<'a> {
        let charge = charge.min(self.charge);
        self.charge -= charge;
        Held {
            budget: self.budget,
            charge,
        }
    }
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        self.budget.release(self.charge);
    }
}

/// What a node holds at once, beside each pool's own bound: the arrivals
/// its Receive Locations carry and the bytes those carries hold, and the
/// bytes its sends hold beside the Send pool's count of Messages.
#[derive(Debug)]
pub struct NodeBudget {
    /// Arrivals carried at once across every Receive Location.
    pub carries: Budget,
    /// Bytes of Streams those carries hold.
    pub received: Budget,
    /// Bytes of Messages the sends hold.
    pub sent: Budget,
    /// The chunk a Stream is written to and read from the Ledger in: what
    /// a carry and a send that streams hold a few of at most.
    pub chunk: u64,
}

impl NodeBudget {
    /// The budgets `tuning` says, on this machine.
    #[must_use]
    pub fn of(tuning: &Tuning) -> Self {
        let chunk = tuning.chunk() as u64;
        let carries = tuning.node_receive().most as u64;
        let senders = tuning.send().most as u64;
        Self {
            carries: Budget::new(carries),
            received: Budget::new(carries * tuning.receive_chunks_per_thread as u64 * chunk),
            sent: Budget::new(senders * tuning.send_chunks_per_thread as u64 * chunk),
            chunk,
        }
    }

    /// What one carry holds of [`NodeBudget::received`]: [`CARRY_CHUNKS`].
    #[must_use]
    pub const fn carry(&self) -> u64 {
        CARRY_CHUNKS * self.chunk
    }

    /// What a send of `length` bytes holds of [`NodeBudget::sent`]: what
    /// reading it holds, [`STREAM_CHUNKS`] of the chunk it reads — of the
    /// Message, where it is shorter than a chunk — and where its transport
    /// gathers the body, the whole of it besides.
    #[must_use]
    pub fn send(&self, length: u64, gathered: bool) -> u64 {
        let reading = STREAM_CHUNKS * length.min(self.chunk);
        if gathered {
            length.saturating_add(reading)
        } else {
            reading
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    #[test]
    fn a_hold_waits_for_room_and_never_lets_more_be_held_than_the_most() {
        let budget = Budget::new(10);
        let most = AtomicU64::new(0);
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    for _ in 0..50 {
                        let held = budget.hold(4);
                        most.fetch_max(budget.held(), Ordering::Relaxed);
                        std::thread::yield_now();
                        drop(held);
                    }
                });
            }
        });
        assert!(most.load(Ordering::Relaxed) <= 10, "{most:?}");
        assert_eq!(budget.held(), 0, "every hold let go");
    }

    #[test]
    fn a_charge_above_the_whole_budget_goes_alone() {
        let budget = Budget::new(10);
        let small = budget.hold(3);
        std::thread::scope(|scope| {
            let large = scope.spawn(|| {
                let held = budget.hold(1_000);
                (held.charge(), budget.held())
            });
            std::thread::sleep(Duration::from_millis(20));
            assert!(!large.is_finished(), "it waits for the small one");
            drop(small);
            assert_eq!(large.join().expect("held"), (10, 10), "all of it, alone");
        });
    }

    #[test]
    fn as_much_as_there_is_room_for_is_held_and_split_one_by_one() {
        let budget = Budget::new(5);
        let first = budget.hold(3);
        let mut given = budget.hold_up_to(8);
        assert_eq!(given.charge(), 2, "the room there was");
        let one = given.split(1);
        assert_eq!((one.charge(), given.charge(), budget.held()), (1, 1, 5));
        drop(given);
        assert_eq!(budget.held(), 4, "what was not used, let go");
        drop((first, one));
        assert_eq!(budget.held(), 0);
    }

    #[test]
    fn a_node_budget_is_its_tuning_and_a_send_holds_as_its_transport_sends() {
        let tuning = Tuning::default();
        let budget = NodeBudget::of(&tuning);
        let chunk = tuning.chunk() as u64;
        assert_eq!(budget.carries.most(), tuning.node_receive().most as u64);
        assert_eq!(budget.carry(), CARRY_CHUNKS * chunk);
        assert_eq!(
            budget.received.most(),
            budget.carries.most() * budget.carry()
        );
        assert_eq!(
            budget.send(10, false),
            STREAM_CHUNKS * 10,
            "a small Message's reading"
        );
        assert_eq!(
            budget.send(1 << 30, false),
            STREAM_CHUNKS * chunk,
            "streamed: a few chunks, whatever its length"
        );
        assert_eq!(
            budget.send(1 << 30, true),
            (1 << 30) + STREAM_CHUNKS * chunk,
            "gathered: all of it besides"
        );
    }
}
