//! An operator's act asked at a node's door, written to Xmip Storage, taken
//! by the act watch of the node it is asked of, decided and answered
//! (ADR-0014, amendment 2026-11-13), held to the millisecond rule: the act
//! path's own share — the door's row, the act watch's pickup, judging it
//! again by name, the apply and the answer — beyond Xmip Storage's own
//! writes, reads and wakes.
//!
//! What is held is the fastest round in every five (`xcore::latency`) of a
//! pause of a Subscription already paused, which its node answers from
//! what it holds, so the round is the act's path and not Xmip Storage's
//! write of a pause. Beside it, round by round under the same load: the
//! four calls the path asks of Xmip Storage, asked of the same Storage node
//! directly — the act written, read by its node, decided, read by the door
//! — and the machine's own wake, which the path takes twice: the act
//! watch woken by the write, and the door by the decision. The write and
//! the pickup are said apart besides: the door's write against Xmip
//! Storage's own, and the act watch's pickup — woken and its act read —
//! against a wait woken by the same write.
//!
//! Each act is asked of an act watch done with the one before. The audit
//! record it writes of each act it decided comes after the decision is
//! written and the door answered, so it is its load and never the act's
//! path; it is said apart, and an act asked while the record before is
//! written waits that long for its pickup.

use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use authenticate::x509::Chain;
use node::{Capability, NodeRole};
use observe::{Act, Noun, Order};
use path::expression::Expression;
use persist::fixture::Memory;
use persist::storage::{ActOutcome, ActRecord, Embedded, Position, Waiter, Watched, XmipStorage};
use route::Subscriber;
use xaudit::program_audit::ProgramAudit;
use xcore::fastest::FIVE;
use xcore::latency::{PlainWake, spread};
use xmip_core_runtime::act_watch::{ActWatch, Asker, Door};
use xmip_core_runtime::configured_subscription::ConfiguredSubscription;
use xmip_core_runtime::fixture::Authority;
use xmip_core_runtime::pickup::Pickup;
use xmip_core_runtime::plane::grant::Presented;
use xmip_core_runtime::plane::{Grants, Role};

use super::sending::memory_node;

/// How many acts are measured.
const ROUNDS: usize = 8 * FIVE;

/// The bound: a millisecond.
const BOUND: Duration = Duration::from_millis(1);

/// The node the acts are asked of, named apart.
fn owner() -> String {
    format!("{}-acted", configure::fixture::test_cluster().node_scope(0))
}

/// Who asks every act measured, and how the door proved them.
const WHO: &str = "CN=alice";
const PROVEN: &str = "mutual-tls";

/// The certificate they present, from a test authority.
static PRESENTED: LazyLock<Presented> = LazyLock::new(|| {
    let (pem, _, _) = Authority::new().pem("alice");
    Presented::Certificate(Chain::from_pem(&pem).expect("a chain").leaf().to_vec())
});

/// alice, an Operator at the door.
fn alice() -> Asker<'static> {
    Asker {
        who: WHO,
        proven: PROVEN,
        presented: &PRESENTED,
        role: Some(Role::Operator),
        through: None,
    }
}

fn pause(node: &str) -> Order {
    Order {
        node: node.to_string(),
        noun: Noun::Subscription,
        target: "Orders".to_string(),
        act: Act::Pause,
        who: WHO.to_string(),
    }
}

/// A row as the door writes it, for Xmip Storage's own calls beside it.
fn row(node: &str) -> ActRecord {
    ActRecord {
        act: xcore::IdGenerator::next_u128(&xcore::UuidV7Generator),
        node: node.to_string(),
        noun: "subscription".to_string(),
        target: "Orders".to_string(),
        word: "pause".to_string(),
        who: WHO.to_string(),
        proven: PROVEN.to_string(),
        certificate: PRESENTED.certificate().map(<[u8]>::to_vec),
        role: "Operator".to_string(),
        door: node.to_string(),
        ..ActRecord::default()
    }
}

/// Xmip Storage's own four calls of one act, asked directly of `storage`
/// for a node no act watch takes: the write, its read, the decision and
/// its read.
fn storage_own(storage: &dyn XmipStorage, node: &str) -> Duration {
    let began = Instant::now();
    let asked = storage.ask_act(&row(node)).expect("written");
    let page = (asked.place - 1, 1);
    storage.read_acts(node, page, false).expect("read");
    let decided = (
        ActOutcome::Taken,
        "Subscription 'Orders' was already paused",
    );
    storage.decide_act(asked.act, decided).expect("decided");
    storage.read_acts(node, page, false).expect("read");
    began.elapsed()
}

/// Until the act watch of `node` waits on the acts asked of it again: the
/// act before decided, audited and done with.
fn idle(storage: &Embedded<Memory, Memory>, node: &str) {
    let watched = Watched::Acts(ActRecord::of_node(node));
    let deadline = Instant::now() + Duration::from_secs(5);
    while storage.waiting_on(watched) == 0 {
        assert!(
            Instant::now() < deadline,
            "the act watch never waited again"
        );
        std::thread::yield_now();
    }
}

/// A wait on the acts asked of `node`, woken by a write, as the act watch
/// is: from the write's answer to the wait's, and the write's own time.
fn woken_by_a_write(storage: &Arc<Embedded<Memory, Memory>>, node: &str) -> (Duration, Duration) {
    let key = ActRecord::of_node(node);
    let at = storage
        .read_acts(node, (0, u32::MAX), false)
        .expect("read")
        .last()
        .map_or(0, |act| act.place);
    let (held, waiter) = (Arc::clone(storage), Arc::new(Waiter::new()));
    let waiting = std::thread::spawn(move || {
        let seen = [Position {
            watched: Watched::Acts(key),
            at,
        }];
        held.wait_queues(&seen, (Duration::from_secs(5), 0), &waiter)
            .expect("answered");
        Instant::now()
    });
    // Listed before the write, so the write wakes it rather than its read.
    let deadline = Instant::now() + Duration::from_secs(5);
    while storage.waiting_on(Watched::Acts(key)) == 0 {
        assert!(Instant::now() < deadline, "never listed");
        std::thread::yield_now();
    }
    let began = Instant::now();
    storage.ask_act(&row(node)).expect("written");
    let written = Instant::now();
    let woke = waiting.join().expect("woken");
    (written - began, woke.saturating_duration_since(written))
}

#[test]
fn an_act_asked_at_a_door_is_taken_and_answered_within_a_millisecond_of_storages_own() {
    let embedded = memory_node();
    let storage: Arc<dyn XmipStorage> = Arc::clone(&embedded) as Arc<dyn XmipStorage>;
    let node = owner();
    let subscription = route::Subscription::new(
        "Orders",
        Subscriber::SendPort("Out".to_string()),
        Expression::parse("true").expect("compiles"),
    );
    let configured = vec![ConfiguredSubscription::unfiled(subscription)];
    let pickup = Pickup::open(&node, configured, Arc::clone(&storage), None).expect("opened");
    let operators = vec![WHO.to_string()];
    let at = std::env::temp_dir().join(format!("xmip-acted-audit-{}", std::process::id()));
    let audit = ProgramAudit::new("acted timing", Some(&at));
    let grants = Grants::listed([&[], &operators, &[]]);
    let watch = ActWatch::new(&node, Arc::clone(&storage), grants, &audit);
    let _watching = watch.start(Duration::from_secs(60)).expect("watching");
    let capability = Capability::of(&[NodeRole::Operational]);
    let door = Door::of(
        &node,
        &capability,
        Arc::clone(&storage),
        Duration::from_secs(5),
    );

    let (first, said) = door.ask(&pause(&node), alice());
    assert_eq!(first, ActOutcome::Taken, "{said}");
    assert!(pickup.standing().iter().any(|one| one.by == WHO));

    let plain = PlainWake::start();
    let beside = format!("{node}-beside");
    let (mut answered, mut own, mut woke) = (Vec::new(), Vec::new(), Vec::new());
    for _ in 0..ROUNDS {
        // Each act asked of an act watch done with the one before: decided,
        // audited and waiting again. Its audit record is the act watch's
        // load, said apart below, never the act's path.
        idle(&embedded, &node);
        let began = Instant::now();
        let (outcome, said) = door.ask(&pause(&node), alice());
        answered.push(began.elapsed());
        assert_eq!(outcome, ActOutcome::Taken, "{said}");
        own.push(storage_own(storage.as_ref(), &beside));
        woke.push(plain.round().0);
    }
    let answered = spread("an act asked at the door to its answer", answered);
    let own = spread("Xmip Storage's own four calls of it", own).fastest_of_five;
    let usual = spread("a plain channel beside it", woke).fastest_of_five;
    assert!(
        answered.fastest_of_five < BOUND + own + usual * 2,
        "the fastest of five {:?}, Storage's own {own:?}, the machine's own wake {usual:?}",
        answered.fastest_of_five
    );

    // The act watch's load, said apart: the audit record it writes of each
    // act it decided, after the decision is written and the door answered.
    let mut recorded = Vec::new();
    for _ in 0..FIVE * 4 {
        let began = Instant::now();
        let _ = audit.record(
            "act",
            xcore::ExecutionPhase::Finished,
            xcore::Severity::Information,
            Some("CN=alice asked to pause subscription 'Orders': taken"),
            std::collections::BTreeMap::new(),
        );
        recorded.push(began.elapsed());
    }
    let _ = spread("the act watch's audit record of an act, its load", recorded);

    // The write and the pickup apart: a wait on the acts asked of a node,
    // woken by the write, as the act watch is.
    let (mut writes, mut pickups, mut woke) = (Vec::new(), Vec::new(), Vec::new());
    for _ in 0..FIVE * 4 {
        let (write, pickup) = woken_by_a_write(&embedded, &format!("{node}-woken"));
        writes.push(write);
        pickups.push(pickup);
        woke.push(plain.round().0);
    }
    let _ = spread("an act's write, Xmip Storage's own", writes);
    let pickup = spread("its pickup by a wait on its node's acts", pickups).fastest_of_five;
    let usual = spread("a plain channel beside it", woke).fastest_of_five;
    assert!(
        pickup < BOUND + usual,
        "its pickup took {pickup:?}, the machine's own wake {usual:?}"
    );
}
