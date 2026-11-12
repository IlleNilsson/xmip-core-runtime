//! A step's watch on its queues in Xmip Storage (open problem 46; ADR-0018,
//! amendment 2026-11-12): what wakes the send step, and the Work Process
//! step, for a Message another node put in a queue it takes from, at once,
//! where until 2026-11-12 it was found at the step's next scan, a second by
//! default.
//!
//! The watch waits on every queue of the step at once, each with where it
//! saw it stand last (`persist::storage::Position`), and asks the step to
//! read each one that moved; the step's scan of every queue stays, at its
//! interval — `[tuning] send_scan` and `work_scan` — which is now only the
//! bound on one wait: what no write tells, a claim that lapsed on a node
//! that died, is found there. Three things keep it from asking without
//! pause, each found 2026-11-12: a wait no Storage node answers — each that
//! is stopping or the primary no more refuses it, and the next is asked at
//! once — rests its bound before it is asked again; one answered with
//! nothing before its bound — a Storage node holds none longer than its
//! `[tuning] storage_wait` — rests the rest of it; and a bound of nothing
//! is no watch at all, the configuration refusing one besides (`[tuning]`
//! takes no duration of nothing). The step's stop ends the watch at once
//! ([`Waiter::stop`]).

use std::sync::Arc;
use std::time::{Duration, Instant};

use persist::storage::{Position, Waiter, XmipStorage};

/// `queues` of `storage` watched as `waiter` until it is stopped, each wait
/// for at most `bound`: each queue a write moved past where the watch saw
/// it last handed to `ask`, at once. No queue, or a bound of nothing, no
/// watch.
pub(crate) fn watch(
    storage: &dyn XmipStorage,
    queues: &[u128],
    bound: Duration,
    waiter: &Arc<Waiter>,
    ask: &dyn Fn(u128),
) {
    if queues.is_empty() || bound.is_zero() {
        return;
    }
    // Where each was seen last: nowhere yet, so the first wait answers at
    // once with every queue that holds anything, read by the step's first
    // scan as well.
    let mut seen: Vec<Position> = queues
        .iter()
        .map(|&queue| Position { queue, next: 0 })
        .collect();
    while !waiter.is_stopped() {
        let asked = Instant::now();
        match storage.wait_queues(&seen, bound, waiter) {
            Ok(moved) if moved.is_empty() => waiter.rest(bound.saturating_sub(asked.elapsed())),
            Ok(moved) => {
                for position in moved {
                    for kept in seen.iter_mut().filter(|kept| kept.queue == position.queue) {
                        kept.next = position.next;
                    }
                    ask(position.queue);
                }
            }
            Err(_) => waiter.rest(bound),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::time::Instant;

    use persist::fixture::Memory;
    use persist::storage::{
        AuditEntry, AuditFacts, Embedded, Hold, JourneyFacts, JourneyRecord, MessageFacts,
        MessageRecord, Publication,
    };
    use secret::{Held, KekName};
    use xcore::lock::Locked;
    use xcore::{AuditId, JourneyId, MessageId};

    use super::*;
    use crate::fixture::{Failing, Operation};

    fn storage() -> Arc<dyn XmipStorage> {
        let keys = Held::new(secret::fixture::Memory::default());
        let kek = KekName::new("storage").expect("a name");
        let node = Embedded::open(
            Memory::default(),
            Memory::default(),
            Memory::default(),
            &keys,
            &kek,
        );
        Arc::new(node.expect("opened"))
    }

    /// The Message numbered `id` published, its Journey held in `queue`.
    fn publish(storage: &dyn XmipStorage, queue: u128, id: u128) {
        let journey = JourneyId::new(id);
        let published = storage.publish(Publication {
            message: MessageRecord {
                message: MessageId::new(id),
                body: Vec::new(),
                facts: MessageFacts::default(),
            },
            journeys: vec![JourneyRecord {
                journey,
                body: Vec::new(),
                facts: JourneyFacts::default(),
            }],
            held: vec![Hold {
                queue,
                journey,
                body: Vec::new(),
            }],
            dead: None,
            audit: AuditEntry {
                id: AuditId::new(id),
                body: Vec::new(),
                audited: None,
                facts: AuditFacts::default(),
            },
            claims: Vec::new(),
            lease_nanos: 0,
        });
        published.expect("published");
    }

    /// Wait, bounded, until `holds`.
    fn until(holds: impl Fn() -> bool, what: &str) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while !holds() {
            assert!(Instant::now() < deadline, "never: {what}");
            std::thread::yield_now();
        }
    }

    #[test]
    fn each_queue_another_writes_to_is_asked_at_once_and_a_stop_ends_the_watch() {
        let storage = storage();
        let asked = Mutex::new(Vec::new());
        let waiter = Arc::new(Waiter::new());
        // A bound of an hour: only a write wakes it.
        let bound = Duration::from_secs(3600);
        std::thread::scope(|scope| {
            let (storage, asked, waiter) = (&storage, &asked, &waiter);
            let watching = scope.spawn(move || {
                let ask = |queue| asked.locked().push(queue);
                watch(storage.as_ref(), &[7, 9], bound, waiter, &ask);
            });
            publish(storage.as_ref(), 9, 1);
            until(|| asked.locked().contains(&9), "the queue written to asked");
            publish(storage.as_ref(), 9, 2);
            until(|| asked.locked().len() == 2, "asked again");
            assert_eq!(*asked.locked(), [9, 9], "never the queue nothing moved");
            let stopping = Instant::now();
            waiter.stop();
            watching.join().expect("watched");
            assert!(
                stopping.elapsed() < Duration::from_secs(30),
                "not its bound"
            );
        });
    }

    #[test]
    fn a_wait_storage_does_not_answer_rests_its_bound_and_is_asked_again() {
        let failing = Failing::over(storage());
        failing.fail(Operation::WaitQueues, 2);
        let storage: Arc<dyn XmipStorage> = failing;
        let asked = Mutex::new(Vec::new());
        let waiter = Arc::new(Waiter::new());
        let bound = Duration::from_millis(20);
        publish(storage.as_ref(), 7, 1);
        let began = Instant::now();
        std::thread::scope(|scope| {
            let (storage, asked, waiter) = (&storage, &asked, &waiter);
            let watching = scope.spawn(move || {
                let ask = |queue| asked.locked().push(queue);
                watch(storage.as_ref(), &[7], bound, waiter, &ask);
            });
            until(|| !asked.locked().is_empty(), "asked once answered");
            waiter.stop();
            watching.join().expect("watched");
        });
        assert!(began.elapsed() >= bound * 2, "rested its bound twice");
        assert_eq!(*asked.locked(), [7]);
    }

    #[test]
    fn a_bound_of_nothing_asks_nothing_rather_than_without_pause() {
        let failing = Failing::over(storage());
        let waiter = Arc::new(Waiter::new());
        std::thread::scope(|scope| {
            let (failing, waiter) = (&failing, &waiter);
            let watching = scope.spawn(move || {
                watch(failing.as_ref(), &[7], Duration::ZERO, waiter, &|_| {});
            });
            until(
                || watching.is_finished() || failing.asked_times(Operation::WaitQueues) > 0,
                "returned or asked",
            );
            waiter.stop();
            watching.join().expect("watched");
        });
        assert_eq!(failing.asked_times(Operation::WaitQueues), 0, "never asked");
    }

    #[test]
    fn a_wait_answered_with_nothing_before_its_bound_rests_the_rest_of_it() {
        let failing = Failing::over(storage());
        failing.answer_waits_at_once();
        let waiter = Arc::new(Waiter::new());
        let bound = Duration::from_millis(50);
        let began = Instant::now();
        std::thread::scope(|scope| {
            let (failing, waiter) = (&failing, &waiter);
            let watching = scope.spawn(move || {
                watch(failing.as_ref(), &[7], bound, waiter, &|_| {});
            });
            until(
                || failing.asked_times(Operation::WaitQueues) >= 3,
                "asked thrice",
            );
            waiter.stop();
            watching.join().expect("watched");
        });
        // Asked again only once the rest of each bound had passed: never a
        // loop of waits answered at once.
        assert!(began.elapsed() >= bound * 2, "{:?}", began.elapsed());
    }
}
