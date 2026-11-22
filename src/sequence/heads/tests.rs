use std::sync::Arc;
use std::time::Duration;

use persist::fixture::Memory;
use persist::storage::{
    AuditEntry, AuditFacts, Embedded, HandOn, Hold, JourneyFacts, JourneyRecord, MessageFacts,
    MessageRecord, Publication, Watched,
};
use secret::KekName;
use xcore::{AuditId, MessageId};

use super::*;
use crate::fixture::{Failing, Operation};

/// The sequence the tests' Messages wait in.
const SEQUENCE: u128 = 0x5e9;

/// Xmip Storage in memory, every request counted.
fn counted() -> Arc<Failing> {
    let keys = secret::Held::new(secret::fixture::Memory::default());
    let kek = KekName::new("storage").expect("a name");
    let node = Embedded::open(
        Memory::default(),
        Memory::default(),
        Memory::default(),
        &keys,
        &kek,
    );
    let beneath: Arc<dyn XmipStorage> = Arc::new(node.expect("opened"));
    Failing::over(beneath)
}

/// The Stream of origin `holder` holding the next place in [`SEQUENCE`].
fn placed(storage: &dyn XmipStorage, holder: u128) {
    let journey = JourneyId::new(holder);
    storage
        .publish(Publication {
            message: MessageRecord {
                message: MessageId::new(holder),
                body: Vec::new(),
                facts: MessageFacts::default(),
            },
            journeys: vec![JourneyRecord {
                journey,
                body: Vec::new(),
                facts: JourneyFacts::default(),
            }],
            held: vec![Hold {
                queue: SEQUENCE,
                journey,
                body: Vec::new(),
            }],
            dead: None,
            audit: AuditEntry {
                id: AuditId::new(holder),
                body: Vec::new(),
                audited: None,
                facts: AuditFacts::default(),
            },
            claims: Vec::new(),
            lease_nanos: 0,
        })
        .expect("published");
}

/// The place `holder` holds in [`SEQUENCE`] let go of: its head moves on.
fn let_go(storage: &dyn XmipStorage, holder: u128) {
    let journey = JourneyId::new(holder);
    let node = configure::fixture::test_cluster().node_scope(0);
    let claim = storage
        .claim(journey, &node, holder, Duration::from_secs(30))
        .expect("asked")
        .expect("claimed");
    let hand_on = HandOn {
        claim,
        result: JourneyRecord {
            journey,
            body: Vec::new(),
            facts: JourneyFacts::default(),
        },
        messages: Vec::new(),
        next: Vec::new(),
        leaves: vec![SEQUENCE],
        queued: Vec::new(),
        requeued: Vec::new(),
        failed: None,
        cleared: Vec::new(),
        waits: None,
        kept_for_nanos: None,
    };
    assert!(storage.hand_on(hand_on).expect("handed on").0);
}

/// The Message of the Journey `journey`, at `place` in its queue, of the
/// Stream of origin `holder`.
fn queued(journey: u128, place: u64, holder: u128) -> Queued {
    Queued {
        journey: JourneyId::new(journey),
        at: (0, place),
        places: vec![(SEQUENCE, holder)],
    }
}

/// The Journeys of `taken`.
fn journeys(taken: &[Queued]) -> Vec<u128> {
    taken.iter().map(|one| one.journey.value()).collect()
}

#[test]
fn a_backlog_behind_one_head_is_kept_its_head_read_once_and_each_next_handed_over() {
    let storage = counted();
    for holder in 1..=5 {
        placed(storage.as_ref(), holder);
    }
    let mut heads = Heads::default();
    let met = heads.met(storage.as_ref(), queued(101, 0, 1)).expect("met");
    assert_eq!(met, (Met::Goes, Vec::new()), "the first met, as before");
    let reads = storage.asked_times(Operation::ReadHeld);
    let (second, ahead) = heads.met(storage.as_ref(), queued(102, 1, 2)).expect("met");
    assert_eq!(second, Met::Waits);
    assert!(
        matches!(
            ahead[..],
            [Position {
                watched: Watched::Head(SEQUENCE),
                ..
            }]
        ),
        "its head waited on: {ahead:?}"
    );
    for (journey, holder) in (103..=105).zip(3..=5) {
        let place = u64::try_from(journey - 101).expect("small");
        let met = heads.met(storage.as_ref(), queued(journey, place, holder));
        assert_eq!(met.expect("met"), (Met::Waits, Vec::new()), "kept, unread");
    }
    assert_eq!(
        storage.asked_times(Operation::ReadHeld) - reads,
        1,
        "one head read"
    );
    assert_eq!(heads.kept(), 4);

    // Its head moves on: one read, the next handed over, no read of a queue.
    let_go(storage.as_ref(), 1);
    heads.ended(&queued(101, 0, 1), TakenUp::Gone);
    let (goes, _) = heads.handed(storage.as_ref()).expect("handed");
    assert_eq!(journeys(&goes), [102], "the next of it");
    assert_eq!(storage.asked_times(Operation::ReadHeld) - reads, 2);
    assert_eq!(
        storage.asked_times(Operation::ReadDue),
        0,
        "no read of a queue"
    );

    // Found behind after all, it is kept again, and handed over once it heads.
    heads.ended(&goes[0], TakenUp::Back);
    let (goes, _) = heads.handed(storage.as_ref()).expect("handed");
    assert_eq!(journeys(&goes), [102], "it heads: handed over again");
    let_go(storage.as_ref(), 2);
    heads.ended(&goes[0], TakenUp::Gone);
    let (goes, _) = heads.handed(storage.as_ref()).expect("handed");
    assert_eq!(journeys(&goes), [103]);
    assert_eq!(
        heads
            .met(storage.as_ref(), queued(104, 3, 4))
            .expect("met")
            .0,
        Met::Known,
        "a Message kept is passed when read again"
    );
}

#[test]
fn past_a_page_a_sequence_is_cut_and_read_on_from_where_it_was_cut() {
    let storage = counted();
    let count = u128::try_from(KEPT).expect("small") + 3;
    for holder in 1..=count {
        placed(storage.as_ref(), holder);
    }
    let mut heads = Heads::default();
    let all: Vec<Queued> = (1..=count)
        .map(|holder| queued(100 + holder, u64::try_from(holder).expect("small"), holder))
        .collect();
    let met: Vec<Met> = all
        .iter()
        .map(|one| heads.met(storage.as_ref(), one.clone()).expect("met").0)
        .collect();
    assert_eq!(met[0], Met::Goes);
    assert!(
        met[1..=KEPT].iter().all(|met| *met == Met::Waits),
        "a page kept"
    );
    assert_eq!(met[KEPT + 1..], [Met::Unkept, Met::Unkept], "the rest cut");
    assert_eq!(
        heads.refill(),
        None,
        "read on only once those kept are gone"
    );

    // Each kept handed over in turn as its head moves on.
    let mut ahead = all[0].clone();
    for next in &all[1..=KEPT] {
        let_go(storage.as_ref(), ahead.places[0].1);
        heads.ended(&ahead, TakenUp::Gone);
        let (goes, _) = heads.handed(storage.as_ref()).expect("handed");
        assert_eq!(goes, std::slice::from_ref(next));
        ahead = next.clone();
    }
    let cut = all[KEPT + 1].place();
    assert_eq!(
        heads.refill(),
        Some((SEQUENCE, cut)),
        "read on from where it was cut"
    );
    heads.refilled(SEQUENCE, &all, (None, u64::MAX));
    assert_eq!(heads.refill(), None, "read on to its end");
    let_go(storage.as_ref(), ahead.places[0].1);
    heads.ended(&ahead, TakenUp::Gone);
    let (goes, _) = heads.handed(storage.as_ref()).expect("handed");
    assert_eq!(
        goes,
        std::slice::from_ref(&all[KEPT + 1]),
        "the first past the cut heads now"
    );
}

#[test]
fn a_message_holding_no_place_goes_and_is_not_kept() {
    let storage = counted();
    let mut heads = Heads::default();
    let free = Queued {
        journey: JourneyId::new(1),
        at: (0, 0),
        places: Vec::new(),
    };
    assert_eq!(
        heads.met(storage.as_ref(), free.clone()).expect("met").0,
        Met::Goes
    );
    assert_eq!(heads.met(storage.as_ref(), free).expect("met").0, Met::Goes);
    assert_eq!(heads.kept(), 0);
    assert_eq!(storage.asked_times(Operation::ReadHeld), 0);
}
