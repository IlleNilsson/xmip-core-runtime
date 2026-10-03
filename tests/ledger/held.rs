//! What a paused Subscription holds, over Xmip Storage that fails on
//! demand (`xmip_core_runtime::fixture::Failing`): nothing held is lost to
//! a failure, and nothing is acknowledged that was not held.
//!
//! - a hold Xmip Storage does not take fails the receive cycle — not
//!   acknowledged — and nothing is held anywhere, in memory least of all;
//! - a held Journey whose send fails is written Failed and stays held, its
//!   Message and its Stream with it, and only a resume tries it again;
//! - a queue or a Journey that cannot be read is read again from its place:
//!   nothing after it is taken first and nothing is passed over.

use std::io::Cursor;
use std::sync::Arc;
use std::time::Duration;

use journey::{Journey, JourneyState};
use observe::Act;
use persist::fixture::Memory;
use persist::storage::{Embedded, XmipStorage, named};
use receive::ReceivedStream;
use secret::{Held, KekName};
use xmip_core_runtime::departure::Departed;
use xmip_core_runtime::fixture::{Failing, Operation};
use xmip_core_runtime::held_work::pick_up;
use xmip_core_runtime::ledger::CHUNK;
use xmip_core_runtime::message_path::{ReceiveCycle, carry};
use xmip_core_runtime::pickup::{Pickup, Released};

use super::receive_cycle::{node, on_runtime};

/// A wait long enough for a queue that could not be read to be read again.
const AGAIN: Duration = Duration::from_millis(500);

/// A test Storage node in memory, and Xmip Storage failing on demand over
/// it.
fn failing() -> (Arc<Failing>, Arc<dyn XmipStorage>) {
    let keys = Held::new(secret::fixture::Memory::default());
    let kek = KekName::new("storage").expect("a name");
    let node = Embedded::open(Memory::default(), Memory::default(), &keys, &kek).expect("opened");
    let failing = Failing::over(Arc::new(node));
    let storage: Arc<dyn XmipStorage> = failing.clone();
    (failing, storage)
}

fn order(number: u32) -> ReceivedStream {
    ReceivedStream::new(
        Cursor::new(format!("order {number}").into_bytes()),
        "tcp://127.0.0.1:1",
    )
}

/// What `onward`'s queue in the Ledger holds: how many, and their places.
fn queue(storage: &dyn XmipStorage) -> (u64, Vec<u64>) {
    let queue = named(&format!("{}/subscription/onward", node()));
    let read = storage.read_held(queue, 0, 64).expect("read");
    let places = read.held.iter().map(|held| held.sequence).collect();
    (read.count, places)
}

fn places(released: &[Released]) -> Vec<u64> {
    released.iter().map(|one| one.held.sequence).collect()
}

fn paused(pickup: &Pickup) {
    pickup
        .act("onward", Act::Pause, "an operator")
        .expect("paused");
}

fn resumed(pickup: &Pickup) {
    pickup
        .act("onward", Act::Resume, "an operator")
        .expect("resumed");
}

#[test]
fn a_hold_xmip_storage_does_not_take_fails_the_receive_cycle_and_holds_nothing() {
    let (failing, storage) = failing();
    on_runtime(&storage, CHUNK, |runtime, pickup, gate| {
        paused(pickup);
        failing.fail(Operation::Publish, 1);
        let refused = carry(runtime, pickup, gate, order(1));
        assert_eq!(refused.cycle(), ReceiveCycle::Failed, "not acknowledged");
        assert_eq!(refused.held, 0);
        assert_eq!(pickup.standing()[0].held, 0, "nothing held in memory");
        assert_eq!(
            queue(storage.as_ref()),
            (0, Vec::new()),
            "nor in the Ledger"
        );

        let again = carry(runtime, pickup, gate, order(1));
        assert_eq!(again.cycle(), ReceiveCycle::Completed, "sent again, held");
        assert_eq!((again.held, pickup.standing()[0].held), (1, 1));
        assert_eq!(queue(storage.as_ref()), (1, vec![0]));
    });
}

#[test]
fn a_held_journey_whose_send_fails_is_written_failed_and_stays_held_with_its_message() {
    let (_, storage) = failing();
    on_runtime(&storage, CHUNK, |runtime, pickup, gate| {
        paused(pickup);
        let carried = carry(runtime, pickup, gate, order(1));
        assert_eq!(
            (carried.cycle(), carried.held),
            (ReceiveCycle::Completed, 1)
        );
        resumed(pickup);
        let released = pickup.released(Duration::ZERO, 8);
        assert_eq!(places(&released), [0]);

        // No Location is bound to the Send Port it leads to: not sent.
        let departed = pick_up(runtime, pickup, &released[0]).expect("picked up");
        assert!(matches!(departed[..], [Departed::NoSuchDestination { .. }]));
        assert_eq!(queue(storage.as_ref()), (1, vec![0]), "still held");
        assert_eq!(pickup.standing()[0].held, 1);
        let id = released[0].held.hold.journey;
        let record = storage.read_journey(id).expect("read").expect("there");
        let journey = Journey::from_record(&record.body).expect("a Journey");
        assert_eq!(journey.state, JourneyState::Failed, "Failed stays with it");
        assert!(journey.entries()[0].outcome.contains("no Send Location"));
        let message = journey.messages()[0];
        assert!(
            storage
                .read_message(message.message_id)
                .expect("read")
                .is_some()
        );
        let chunk = storage.read_chunk(message.stream_id, 0).expect("read");
        assert_eq!(chunk.expect("its Stream").bytes, b"order 1");

        assert!(
            pickup.released(Duration::ZERO, 8).is_empty(),
            "a Failed Journey is not tried again by itself"
        );
        paused(pickup);
        resumed(pickup);
        let retried = pickup.released(Duration::ZERO, 8);
        assert_eq!(places(&retried), [0], "a resume is the operator's retry");
        assert!(retried[0].retry);
        pick_up(runtime, pickup, &retried[0]).expect("tried again");
        assert_eq!(queue(storage.as_ref()), (1, vec![0]), "failed again, held");
    });
}

#[test]
fn what_cannot_be_read_is_read_again_from_its_place_and_nothing_is_passed_over() {
    let (failing, storage) = failing();
    on_runtime(&storage, CHUNK, |runtime, pickup, gate| {
        paused(pickup);
        for number in 1..=2 {
            carry(runtime, pickup, gate, order(number));
        }
        resumed(pickup);

        failing.fail(Operation::ReadHeld, 1);
        assert!(pickup.released(Duration::ZERO, 8).is_empty(), "not read");
        assert_eq!(pickup.standing()[0].held, 2, "nothing settled");
        let released = pickup.released(AGAIN, 8);
        assert_eq!(places(&released), [0, 1], "read again from the first");

        // The first Journey cannot be read: it and what follows it are
        // read again, in their order, and neither is passed over.
        failing.fail(Operation::ReadJourney, 1);
        assert!(pick_up(runtime, pickup, &released[0]).is_err());
        for one in &released {
            pickup.again(one);
        }
        let again = pickup.released(AGAIN, 8);
        assert_eq!(places(&again), [0, 1], "nothing advanced");

        // A Failed Journey's write not taken: read again too.
        failing.fail(Operation::WriteJourney, 1);
        assert!(pick_up(runtime, pickup, &again[0]).is_err());
        for one in &again {
            pickup.again(one);
        }
        let last = pickup.released(AGAIN, 8);
        assert_eq!(places(&last), [0, 1]);
        for one in &last {
            pick_up(runtime, pickup, one).expect("picked up");
        }
        assert_eq!(
            queue(storage.as_ref()),
            (2, vec![0, 1]),
            "both held, Failed"
        );
    });
}
