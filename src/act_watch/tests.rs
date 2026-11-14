//! The door and the act watch over one Xmip Storage in this process: an
//! act carried, judged again by the owning node, decided once, and asked
//! of a node that does not run until it does.

use std::sync::{Arc, LazyLock};
use std::time::Duration;

use node::{Capability, NodeRole};
use observe::{Act, Noun, Order};
use path::expression::Expression;
use persist::storage::{ActOutcome, ActRecord, Position, Waiter, Watched, XmipStorage};
use route::Subscriber;
use xaudit::program_audit::ProgramAudit;

use authenticate::x509::Chain;

use super::{ActWatch, Asker, Door};
use crate::configured_subscription::ConfiguredSubscription;
use crate::fixture::Authority;
use crate::pickup::Pickup;
use crate::plane::grant::Presented;
use crate::plane::{Grants, Role};

/// A node of the test cluster, named apart for `test`.
fn scope(test: &str) -> String {
    format!(
        "{}-act-{test}",
        configure::fixture::test_cluster().node_scope(0)
    )
}

/// One Xmip Storage in this process's memory, which a test's nodes and
/// doors share.
fn storage() -> Arc<dyn XmipStorage> {
    Arc::clone(crate::ledger::in_memory())
}

fn audit() -> ProgramAudit {
    let at = std::env::temp_dir().join(format!("xmip-act-watch-audit-{}", std::process::id()));
    ProgramAudit::new("xmip-core-runtime act watch tests", Some(&at))
}

/// The node at `node` routing by the Subscription `Orders` over `storage`,
/// its act watch running and listing `operators` as Operators.
fn owner(
    storage: &Arc<dyn XmipStorage>,
    node: &str,
    operators: &[&str],
) -> (Arc<Pickup>, super::ActWatching) {
    let subscription = route::Subscription::new(
        "Orders",
        Subscriber::SendPort("Out".to_string()),
        Expression::parse("true").expect("compiles"),
    );
    let configured = vec![ConfiguredSubscription::unfiled(subscription)];
    let pickup = Pickup::open(node, configured, Arc::clone(storage), None).expect("opened");
    let operators: Vec<String> = operators.iter().map(ToString::to_string).collect();
    let grants = Grants::listed([&[], &operators, &[]]);
    let watch = ActWatch::new(node, Arc::clone(storage), grants, &audit());
    let watching = watch.start(Duration::from_secs(30)).expect("watching");
    (pickup, watching)
}

/// A pause of `Orders` at `node`.
fn pause(node: &str) -> Order {
    Order {
        node: node.to_string(),
        noun: Noun::Subscription,
        target: "Orders".to_string(),
        act: Act::Pause,
        who: "CN=alice".to_string(),
    }
}

/// The certificate alice presents, from a test authority: subject
/// `CN=alice`, and `localhost` as an alternative name, as every fixture
/// certificate carries.
static ALICE: LazyLock<Presented> = LazyLock::new(|| {
    let (pem, _, _) = Authority::new().pem("alice");
    Presented::Certificate(Chain::from_pem(&pem).expect("a chain").leaf().to_vec())
});

/// alice, an Operator at the door, relayed through `CN=web`.
fn alice() -> Asker<'static> {
    Asker {
        who: "CN=alice",
        proven: "mutual-tls",
        presented: &ALICE,
        role: Some(Role::Operator),
        through: Some("CN=web"),
    }
}

/// The door of an operational node at `door`, writing through `storage`.
fn operational(storage: &Arc<dyn XmipStorage>, door: &str, within: Duration) -> Door {
    let capability = Capability::of(&[NodeRole::Operational, NodeRole::Monitoring]);
    Door::of(&scope(door), &capability, Arc::clone(storage), within)
}

/// Every act asked of `node` in `storage`, oldest first.
fn acts(storage: &Arc<dyn XmipStorage>, node: &str) -> Vec<ActRecord> {
    storage.read_acts(node, (0, 64), false).expect("read")
}

#[test]
fn a_node_without_the_operational_role_carries_no_act_and_says_so() {
    let storage = storage();
    let plain = Door::of(
        &scope("plain-door"),
        &Capability::none(),
        Arc::clone(&storage),
        super::OPERATE_ACT,
    );
    let absent = scope("absent");
    let (outcome, said) = plain.ask(&pause(&absent), alice());
    assert_eq!(outcome, ActOutcome::Refused);
    assert!(
        said.contains("declares no operational role, so it carries no act to another node"),
        "{said}"
    );
    assert!(said.contains("(ADR-0056)"), "{said}");
    assert_eq!(acts(&storage, &absent), [], "nothing is written");
    let (outcome, _) = Door::none().ask(&pause(&absent), alice());
    assert_eq!(outcome, ActOutcome::Refused, "the door of no node");
}

#[test]
fn an_act_through_an_operational_door_is_taken_by_its_node_and_says_who_and_through() {
    let storage = storage();
    let node = scope("taken");
    let (pickup, _watching) = owner(&storage, &node, &["CN=alice"]);
    let door = operational(&storage, "op-door", Duration::from_secs(5));
    let (outcome, said) = door.ask(&pause(&node), alice());
    assert_eq!(outcome, ActOutcome::Taken, "{said}");
    assert!(
        pickup.standing().iter().any(|one| one.by == "CN=alice"),
        "paused"
    );

    let kept = acts(&storage, &node);
    assert_eq!(kept.len(), 1);
    let act = &kept[0];
    assert_eq!(
        (act.outcome, act.said.as_str()),
        (ActOutcome::Taken, said.as_str())
    );
    assert_eq!(
        (act.who.as_str(), act.through.as_deref(), act.role.as_str()),
        ("CN=alice", Some("CN=web"), "Operator")
    );
    assert_eq!(act.door, scope("op-door"));
    assert!(act.decided_unix_nanos >= act.asked_unix_nanos);
}

#[test]
fn a_node_takes_acts_on_itself_without_the_operational_role() {
    let storage = storage();
    let node = scope("itself");
    let (_pickup, _watching) = owner(&storage, &node, &["CN=alice"]);
    // A door no operational node keeps, writing through the owning node's
    // Xmip Storage since that node runs here.
    let (outcome, said) = Door::none().ask(&pause(&node), alice());
    assert_eq!(outcome, ActOutcome::Taken, "{said}");
}

#[test]
fn the_owning_node_refuses_a_name_its_own_lists_do_not_grant() {
    let storage = storage();
    let node = scope("judged");
    let (pickup, _watching) = owner(&storage, &node, &["CN=bob"]);
    let door = operational(&storage, "judging-door", Duration::from_secs(5));
    let (outcome, said) = door.ask(&pause(&node), alice());
    assert_eq!(outcome, ActOutcome::Refused);
    assert!(
        said.starts_with("REFUSED. CN=alice holds no role at"),
        "{said}"
    );
    assert!(
        !pickup.standing().iter().any(|one| one.by == "CN=alice"),
        "nothing taken"
    );
}

#[test]
fn a_certificate_the_owning_node_grants_by_an_alternative_name_is_taken() {
    // The owning node judges by the rule the door admitted by: alice's
    // certificate carries `localhost`, and that is all its lists name.
    let storage = storage();
    let node = scope("alternative");
    let (pickup, _watching) = owner(&storage, &node, &["localhost"]);
    let door = operational(&storage, "alternative-door", Duration::from_secs(5));
    let (outcome, said) = door.ask(&pause(&node), alice());
    assert_eq!(outcome, ActOutcome::Taken, "{said}");
    assert!(
        pickup.standing().iter().any(|one| one.by == "CN=alice"),
        "paused"
    );
    let kept = acts(&storage, &node).remove(0);
    assert_eq!(
        kept.certificate.as_deref(),
        ALICE.certificate(),
        "its row keeps it"
    );
}

#[test]
fn an_act_for_a_node_not_running_stays_asked_and_is_taken_as_it_starts() {
    let storage = storage();
    let node = scope("later");
    let door = operational(&storage, "waiting-door", Duration::from_millis(50));
    let (outcome, said) = door.ask(&pause(&node), alice());
    assert_eq!(outcome, ActOutcome::Asked);
    assert!(said.contains("not taken yet"), "{said}");
    let asked = acts(&storage, &node).remove(0);
    assert!(asked.is_asked(), "kept asked");

    // Its decision waited on, as a door waits on one: told, never looked for.
    let (pickup, _watching) = owner(&storage, &node, &["CN=alice"]);
    let decided = [Position {
        watched: Watched::Act(asked.act),
        at: 0,
    }];
    let waiter = Arc::new(Waiter::new());
    let moved = storage
        .wait_queues(&decided, (Duration::from_secs(30), 0), &waiter)
        .expect("answered");
    assert_eq!(moved.len(), 1, "decided as its node started");
    assert_eq!(acts(&storage, &node)[0].outcome, ActOutcome::Taken);
    assert!(
        pickup.standing().iter().any(|one| one.by == "CN=alice"),
        "paused"
    );
}
