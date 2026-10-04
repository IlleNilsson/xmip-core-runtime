//! The receive path the tests carry Streams through, into the Ledger: the
//! one a child runs until it is killed, one Stream after another, each
//! whose receive cycle completed said, and the one a Stream far larger than
//! a chunk is carried through.

use std::io::Cursor;
use std::sync::Arc;

use authenticate::{Acceptance, Authenticator};
use authorize::Authorizer;
use message::MessageTreatment;
use path::expression::Expression;
use persist::storage::XmipStorage;
use receive::ReceivedStream;
use route::{Gathering, Subscriber, Subscription};
use xcore::{SystemClock, UuidV7Generator, mechanism};
use xmip_core_runtime::configured_subscription::ConfiguredSubscription;
use xmip_core_runtime::fixture::{Always, Open, send_step_of};
use xmip_core_runtime::ledger::CHUNK;
use xmip_core_runtime::message_path::{Carried, Parties, ReceiveCycle, Runtime, carry};
use xmip_core_runtime::outcome::Arrived;
use xmip_core_runtime::pickup::Pickup;
use xmip_core_runtime::receiving::ReceiveGate;
use xmip_core_runtime::sending::Sends;
use xmip_core_runtime::tuning::Tuning;

use super::say;

/// The node the receive path runs on: the test cluster's receiving node,
/// `xmip:///<cluster>/node/<node>`.
pub fn node() -> String {
    let cluster = configure::fixture::test_cluster();
    format!(
        "{}/node/{}",
        cluster.scope(),
        cluster.with_role("receiving").name
    )
}

/// A receive path over `storage`, writing Streams in chunks of `chunk`,
/// with one Subscription, `onward`, matching everything to a Send Port this
/// node has no Location for — so nothing departs — its Runtime, its pickup
/// and its Receive Location's gate handed to `run`.
pub fn on_runtime<T>(
    storage: &Arc<dyn XmipStorage>,
    chunk: usize,
    run: impl FnOnce(&Runtime<'_>, &Pickup, &ReceiveGate) -> T,
) -> T {
    let subscriptions = [subscription(
        "onward",
        "xmip.transport.mechanism = 'circumstance'",
    )];
    on_runtime_with(storage, chunk, &subscriptions, run)
}

/// A Subscription called `name`, by `filter`, leading to a Send Port this
/// node has no Location for.
pub fn subscription(name: &str, filter: &str) -> Subscription {
    Subscription::new(
        name,
        Subscriber::SendPort("Out".to_string()),
        Expression::parse(filter).expect("compiles"),
    )
}

/// [`on_runtime`]'s receive path, routing by `subscriptions` instead.
pub fn on_runtime_with<T>(
    storage: &Arc<dyn XmipStorage>,
    chunk: usize,
    subscriptions: &[Subscription],
    run: impl FnOnce(&Runtime<'_>, &Pickup, &ReceiveGate) -> T,
) -> T {
    let sender = Sender {
        sends: Sends::default(),
        tuning: Tuning::default(),
        node: node(),
    };
    on_node(storage, (chunk, subscriptions), sender, run)
}

/// What a test node sends with: its Send Locations and Send Ports, its
/// `[tuning]`, and the node it is.
pub struct Sender {
    pub sends: Sends,
    pub tuning: Tuning,
    pub node: String,
}

/// [`on_runtime_with`]'s receive path, on a node sending as `sender`
/// says: what it publishes for its Send Ports it claims and hands to its
/// send step, which sends where the test dispatches it.
pub fn on_node<T>(
    storage: &Arc<dyn XmipStorage>,
    (chunk, subscriptions): (usize, &[Subscription]),
    sender: Sender,
    run: impl FnOnce(&Runtime<'_>, &Pickup, &ReceiveGate) -> T,
) -> T {
    let circumstance = Always::circumstance();
    let authenticators: [&dyn Authenticator; 1] = [&circumstance];
    let policies: [&dyn Authorizer; 1] = [&Open];
    let gathering = Gathering::of(&[], subscriptions);
    let parties = Parties::default();
    let Sender {
        sends,
        tuning,
        node,
    } = sender;
    let origin = xaudit::origin::Origin::here("ledger-test");
    let runtime = Runtime {
        ids: &UuidV7Generator,
        authenticators: &authenticators,
        parties: &parties,
        directory: &parties,
        subscriptions,
        gathering: &gathering,
        treatment: MessageTreatment::default(),
        sends: &sends,
        send: send_step_of(storage, &node, &tuning),
        transport_identifiers: &[],
        message_identifiers: &[],
        policies: &policies,
        clock: &SystemClock,
        storage,
        chunk,
        origin: &origin,
    };
    let configured = subscriptions
        .iter()
        .cloned()
        .map(ConfiguredSubscription::unfiled)
        .collect();
    let pickup = Pickup::open(&node, configured, Arc::clone(storage), None).expect("opened");
    let gate = ReceiveGate::new(
        "In",
        Acceptance::closed().accepting(&mechanism::circumstance()),
    );
    run(&runtime, &pickup, &gate)
}

/// [`on_runtime`]'s receive path, as one call a Stream is carried by.
pub fn receiving<T>(
    storage: &Arc<dyn XmipStorage>,
    chunk: usize,
    run: impl FnOnce(&dyn Fn(ReceivedStream) -> Carried) -> T,
) -> T {
    on_runtime(storage, chunk, |runtime, pickup, gate| {
        run(&|received| carry(runtime, pickup, gate, received))
    })
}

/// Carry Streams through the receive path into `storage`, one after
/// another, saying each whose receive cycle completed: what a Receive
/// Location acknowledges.
pub fn receive_until_killed(storage: &Arc<dyn XmipStorage>) {
    receiving(storage, CHUNK, |carry| {
        for number in 0..1_000_000u64 {
            let body = Cursor::new(format!("order {number}").into_bytes());
            let carried = carry(ReceivedStream::new(body, "tcp://127.0.0.1:1"));
            assert_eq!(
                carried.cycle(),
                ReceiveCycle::Completed,
                "{:?}",
                carried.arrived
            );
            let Arrived::Routed { work, .. } = &carried.arrived else {
                panic!("routed: {:?}", carried.arrived);
            };
            let journeys: Vec<String> = carried
                .journeys
                .iter()
                .map(|journey| journey.journey_id().value().to_string())
                .collect();
            say(&format!(
                "received {number} {} {}",
                work.message.message_id().value(),
                journeys.join(",")
            ));
        }
    });
}
