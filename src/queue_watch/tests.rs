use std::sync::Mutex;
use std::time::Instant;

use persist::fixture::Memory;
use persist::storage::{
    AuditEntry, AuditFacts, Embedded, HandOn, Hold, JourneyFacts, JourneyRecord, MessageFacts,
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

/// The Message numbered `id`, held in `queue`, claimed and handed on out of
/// it: its place there let go of.
fn taken_out(storage: &dyn XmipStorage, queue: u128, id: u128) {
    let holder = configure::fixture::test_cluster().node_scope(0);
    let claim = storage.claim(JourneyId::new(id), &holder, id, Duration::from_secs(30));
    let handed = storage.hand_on(&HandOn {
        claim: claim.expect("asked").expect("claimed"),
        result: JourneyRecord {
            journey: JourneyId::new(id),
            body: Vec::new(),
            facts: JourneyFacts::default(),
        },
        messages: Vec::new(),
        next: Vec::new(),
        leaves: vec![queue],
        queued: Vec::new(),
        requeued: Vec::new(),
        failed: None,
        cleared: Vec::new(),
        waits: None,
        kept_for_nanos: None,
    });
    assert!(handed.expect("handed on"));
}

/// Wait, bounded, until `holds`.
fn until(holds: impl Fn() -> bool, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !holds() {
        assert!(Instant::now() < deadline, "never: {what}");
        std::thread::yield_now();
    }
}

/// A bound of an hour: only a write, or a renewal, wakes a wait.
const HOUR: Duration = Duration::from_secs(3600);

/// Each queue asked, and how many were due in it as the wait answered.
type Asked = Mutex<Vec<(u128, Option<usize>)>>;

fn asking(asked: &Asked) -> impl Fn(u128, Woken) + '_ {
    move |queue, woken: Woken| {
        let due = woken.due.map(|due| due.held.len());
        asked.locked().push((queue, due));
    }
}

#[test]
fn each_queue_another_writes_to_is_asked_at_once_with_what_is_due_and_a_stop_ends_it() {
    let storage = storage();
    let asked = Asked::default();
    let watch = QueueWatch::of("watching");
    std::thread::scope(|scope| {
        let (storage, asked, watch) = (&storage, &asked, &watch);
        let watching = scope.spawn(move || {
            watch.run(storage.as_ref(), &[7, 9], HOUR, &asking(asked));
        });
        publish(storage.as_ref(), 9, 1);
        until(|| !asked.locked().is_empty(), "the queue written to asked");
        publish(storage.as_ref(), 9, 2);
        until(|| asked.locked().len() == 2, "asked again");
        assert_eq!(
            *asked.locked(),
            [(9, Some(1)), (9, Some(2))],
            "never the queue nothing moved, each with what is due in it"
        );
        let stopping = Instant::now();
        watch.stop();
        watching.join().expect("watched");
        assert!(
            stopping.elapsed() < Duration::from_secs(30),
            "not its bound"
        );
    });
}

/// The owner, 2026-11-12, open problem 46: what a passed Journey waits on
/// another node moves, at once.
#[test]
fn a_head_named_while_waiting_is_waited_on_at_once_and_its_queue_asked_as_it_moves() {
    let failing = Failing::over(storage());
    publish(failing.as_ref(), 5, 1);
    let asked = Asked::default();
    let watch = QueueWatch::of("watching");
    std::thread::scope(|scope| {
        let (failing, asked, watch) = (&failing, &asked, &watch);
        let watching = scope.spawn(move || {
            watch.run(failing.as_ref(), &[7], HOUR, &asking(asked));
        });
        until(
            || failing.asked_times(Operation::WaitQueues) == 1,
            "the first wait",
        );
        let head = Position {
            watched: Watched::Head(5),
            at: 0,
        };
        watch.wait_on(&[head], 7);
        watch.wait_on(&[head], 7);
        assert_eq!(watch.waiting_on_more(), 1, "named once");
        // The wait under way renewed, and asked again naming the head.
        until(
            || failing.asked_times(Operation::WaitQueues) >= 2,
            "asked again",
        );
        taken_out(failing.as_ref(), 5, 1);
        until(|| !asked.locked().is_empty(), "its queue asked");
        assert_eq!(*asked.locked(), [(7, None)], "read by the step itself");
        assert_eq!(watch.waiting_on_more(), 0, "let go of once it moved");
        watch.stop();
        watching.join().expect("watched");
    });
}

#[test]
fn a_wait_storage_does_not_answer_rests_its_bound_and_is_asked_again() {
    let failing = Failing::over(storage());
    failing.fail(Operation::WaitQueues, 2);
    let storage: Arc<dyn XmipStorage> = failing;
    let asked = Asked::default();
    let watch = QueueWatch::of("watching");
    let bound = Duration::from_millis(20);
    publish(storage.as_ref(), 7, 1);
    let began = Instant::now();
    std::thread::scope(|scope| {
        let (storage, asked, watch) = (&storage, &asked, &watch);
        let watching = scope.spawn(move || {
            watch.run(storage.as_ref(), &[7], bound, &asking(asked));
        });
        until(|| !asked.locked().is_empty(), "asked once answered");
        watch.stop();
        watching.join().expect("watched");
    });
    assert!(began.elapsed() >= bound * 2, "rested its bound twice");
    assert_eq!(*asked.locked(), [(7, Some(1))]);
}

#[test]
fn a_bound_of_nothing_asks_nothing_rather_than_without_pause() {
    let failing = Failing::over(storage());
    let watch = QueueWatch::of("watching");
    std::thread::scope(|scope| {
        let (failing, watch) = (&failing, &watch);
        let watching = scope.spawn(move || {
            watch.run(failing.as_ref(), &[7], Duration::ZERO, &|_, _| {});
        });
        until(
            || watching.is_finished() || failing.asked_times(Operation::WaitQueues) > 0,
            "returned or asked",
        );
        watch.stop();
        watching.join().expect("watched");
    });
    assert_eq!(failing.asked_times(Operation::WaitQueues), 0, "never asked");
}

#[test]
fn a_wait_answered_with_nothing_before_its_bound_rests_the_rest_of_it() {
    let failing = Failing::over(storage());
    failing.answer_waits_at_once();
    let watch = QueueWatch::of("watching");
    let bound = Duration::from_millis(50);
    let began = Instant::now();
    std::thread::scope(|scope| {
        let (failing, watch) = (&failing, &watch);
        let watching = scope.spawn(move || {
            watch.run(failing.as_ref(), &[7], bound, &|_, _| {});
        });
        until(
            || failing.asked_times(Operation::WaitQueues) >= 3,
            "asked thrice",
        );
        watch.stop();
        watching.join().expect("watched");
    });
    // Asked again only once the rest of each bound had passed: never a
    // loop of waits answered at once.
    assert!(began.elapsed() >= bound * 2, "{:?}", began.elapsed());
}
