//! A Work Process's Instances from the Ledger (ADR-0066, amendment
//! 2026-11-25; open problems 191 to 194): an order delivered in parts,
//! carried through a node's receive path into a design that keeps what was
//! ordered and delivered across every Message and loops back to its wait
//! until every line is delivered, correlated by the order (the cluster's
//! Correlation by client, the client header the order's number):
//!
//! - the loop takes every delivery, counts it in the Instance's own
//!   values, and confirms the order once every line came (191, 194);
//! - the Work Process step lists the Instance as it stands — waiting for a
//!   Message of its key until its deadline, its values, its history of
//!   Messages, completed — from the Ledger and in what it publishes (192);
//! - a turn whose unit failed leaves the Instance as it stood, failed with
//!   its code and why, a later Message of its key waiting on it; Retry takes
//!   that turn again once the unit is mended, and the order completes in the
//!   order its deliveries came (193);
//! - Dismiss ends the Instance the Message failed, and an act on a Message
//!   that has not failed is refused in words (193);
//! - a deadline due raises the order overdue, and a Retry takes the timer's
//!   turn again, its Journey waiting as it did (193).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use observe::Act;
use xcore::JourneyId;
use xmip_core_runtime::message_path::Runtime;
use xmip_core_runtime::pickup::Pickup;
use xmip_core_runtime::work_step::{Turned, turn_due};

use super::sending::memory;
use super::work_design::published_to;
use super::work_in_parts::{carried, running, working};
/// Every turn due taken, each written.
fn turned(runtime: &Runtime<'_>, pickup: &Pickup) {
    let turned = turn_due(runtime, pickup);
    assert!(
        turned.iter().all(|turned| matches!(turned, Turned::Done)),
        "{turned:?}"
    );
}

/// The order's one Instance, as the Ledger keeps it.
fn the_instance(runtime: &Runtime<'_>) -> observe::WorkProcessInstance {
    let listed = runtime.work.instances("InParts", 0).expect("listed");
    let [one] = listed.instances.as_slice() else {
        panic!("{:?}", listed.instances);
    };
    one.clone()
}

fn value<'a>(instance: &'a observe::WorkProcessInstance, name: &str) -> Option<&'a str> {
    instance
        .values
        .iter()
        .find(|[known, _]| known == name)
        .map(|[_, value]| value.as_str())
}

fn history(instance: &observe::WorkProcessInstance) -> Vec<&str> {
    instance
        .history
        .iter()
        .map(|entry| entry.what.as_str())
        .collect()
}

#[test]
fn an_order_loops_back_to_its_wait_counting_its_deliveries_in_its_own_values() {
    let storage = memory();
    let broken = Arc::new(AtomicBool::new(false));
    working(&storage, running("PT1H", &broken), |on| {
        let (runtime, pickup, _) = on;
        carried(on, "A-1001", 3);
        turned(runtime, pickup);
        let ordered = the_instance(runtime);
        assert_eq!(ordered.state, "waiting");
        assert_eq!(
            ordered.waits_for, "message or time",
            "its key, until its deadline"
        );
        assert!(ordered.until_unix_nanos.is_some());
        assert_eq!(
            ordered.correlations,
            [["PerClient".to_string(), "A-1001".to_string()]]
        );
        assert_eq!(history(&ordered), ["started"]);

        carried(on, "A-1001", 1);
        turned(runtime, pickup);
        let part = the_instance(runtime);
        assert_eq!(
            (value(&part, "Ordered"), value(&part, "Delivered")),
            (Some("3"), Some("1"))
        );
        assert_eq!(part.state, "waiting", "back at its wait");
        assert_eq!(history(&part), ["started", "arrived", "made"]);

        carried(on, "A-1001", 2);
        turned(runtime, pickup);
        let done = the_instance(runtime);
        assert_eq!(done.state, "completed");
        assert_eq!(
            value(&done, "Delivered"),
            Some("3"),
            "counted across every Message"
        );
        assert_eq!(
            history(&done)[3..],
            ["arrived", "made", "made", "published"],
            "checked, marked and confirmed"
        );
        let published = runtime.work.published();
        assert_eq!(
            published[0].instances[0].instance, done.instance,
            "and published"
        );
    });
    assert_eq!(
        published_to(&storage, "Out").len(),
        1,
        "the order confirmed once"
    );
}

#[test]
fn a_failed_turn_keeps_its_instance_for_an_operator_and_a_retry_takes_it_again_in_order() {
    let storage = memory();
    let broken = Arc::new(AtomicBool::new(true));
    working(&storage, running("PT1H", &broken), |on| {
        let (runtime, pickup, _) = on;
        carried(on, "A-1001", 3);
        turned(runtime, pickup);
        let first = carried(on, "A-1001", 1).to_string();
        turned(runtime, pickup);
        let failed = the_instance(runtime);
        assert_eq!(
            (failed.state.as_str(), failed.code.as_str()),
            ("failed", "offline")
        );
        assert!(
            failed.reason.contains("cannot reach its stock"),
            "{}",
            failed.reason
        );
        assert_eq!(failed.failed_by, first, "the Journey whose turn failed it");
        assert_eq!(
            value(&failed, "Delivered"),
            Some("0"),
            "as it stood before that turn"
        );
        let listed = runtime.work.instances("InParts", 0).expect("listed");
        assert_eq!(listed.failed_count, 1);
        assert_eq!(
            listed.failed[0].journey, first,
            "what Retry and Dismiss name"
        );

        carried(on, "A-1001", 2);
        let waiting = turn_due(runtime, pickup);
        assert!(
            waiting.iter().any(|turned| matches!(
                turned,
                Turned::Waits { why, .. } if why.contains("failed and waits for an operator")
            )),
            "{waiting:?}"
        );

        broken.store(false, Ordering::Release);
        let said = runtime
            .work
            .act(&first, Act::Retry, "operator")
            .expect("retried");
        assert!(said.contains("retried by operator"), "{said}");
        // The later delivery waits on the Instance until the retried turn
        // takes it on: the next pass turns the retried, then the later.
        let _ = turn_due(runtime, pickup);
        let _ = turn_due(runtime, pickup);
        let done = the_instance(runtime);
        assert_eq!(done.state, "completed");
        assert_eq!(value(&done, "Delivered"), Some("3"));
        let whats = history(&done);
        assert!(whats.contains(&"retried"), "{whats:?}");
        let again = runtime.work.act(&first, Act::Retry, "operator");
        assert!(
            again.is_err_and(|said| said.starts_with("REFUSED")),
            "no longer failed"
        );
    });
    assert_eq!(published_to(&storage, "Out").len(), 1);
}

#[test]
fn a_dismiss_ends_the_instance_its_message_failed_and_keeps_its_history() {
    let storage = memory();
    let broken = Arc::new(AtomicBool::new(true));
    working(&storage, running("PT1H", &broken), |on| {
        let (runtime, pickup, _) = on;
        carried(on, "A-1001", 3);
        turned(runtime, pickup);
        let first = carried(on, "A-1001", 1).to_string();
        turned(runtime, pickup);
        assert!(
            runtime.work.holds(&first),
            "failed at a Work Process this node runs"
        );
        let said = runtime
            .work
            .act(&first, Act::Dismiss, "operator")
            .expect("dismissed");
        assert!(said.contains("the Instance it failed ended"), "{said}");
        let ended = the_instance(runtime);
        assert_eq!(ended.state, "dismissed");
        assert_eq!(history(&ended).last(), Some(&"dismissed"));
        let listed = runtime.work.instances("InParts", 0).expect("listed");
        assert_eq!(listed.failed_count, 0, "out of its queue's failed Messages");
        let again = runtime
            .work
            .act(&first, Act::Dismiss, "operator")
            .expect("said");
        assert!(again.contains("dismissed already"), "{again}");
        let none = runtime
            .work
            .act(&JourneyId::new(7).to_string(), Act::Retry, "operator");
        assert!(none.is_err_and(|said| said.contains("no Journey")));
    });
}

#[test]
fn a_deadline_due_raises_the_order_overdue_and_a_retry_takes_the_timers_turn_again() {
    let storage = memory();
    let broken = Arc::new(AtomicBool::new(false));
    working(&storage, running("PT0S", &broken), |on| {
        let (runtime, pickup, _) = on;
        let order = carried(on, "A-1001", 3).to_string();
        turned(runtime, pickup);
        turned(runtime, pickup);
        let overdue = the_instance(runtime);
        assert_eq!(
            (overdue.state.as_str(), overdue.code.as_str()),
            ("failed", "overdue")
        );
        assert_eq!(
            overdue.failed_by, order,
            "the order's Journey kept its timer"
        );
        assert_eq!(history(&overdue), ["started", "due", "failed"]);
        runtime
            .work
            .act(&order, Act::Retry, "operator")
            .expect("retried");
        turned(runtime, pickup);
        let again = the_instance(runtime);
        assert_eq!(
            history(&again),
            ["started", "due", "failed", "retried", "due", "failed"],
            "its timer's turn taken again, still overdue"
        );
    });
}
