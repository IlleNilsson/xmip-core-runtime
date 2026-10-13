//! What a node leaves published once it has stopped (ADR-0018, amendment
//! 2026-09-30): its last publication, with what ran Done.

use node::Stage;
use observe::{Health, HealthRecord, Publication, now_unix_nanos};

use super::{drawn, location};

/// What the node `node` of `cluster` leaves published once it has stopped:
/// `last`, its last publication while it ran, with the node, its System
/// Process, its modules and its Locations Done — the node saying `said`,
/// the rest that they stopped with it — and drawn again. What it declared,
/// its Subscriptions' standing and the Locations it never started stay as
/// they were: a pause outlives the stop (ADR-0013, amendment 2026-09-30),
/// and a Location the configuration does not start did not stop. A surface
/// over the file shows a stopped node, never a running one that went quiet.
#[must_use]
pub fn stopped(cluster: &str, node: &str, last: &Publication, said: &str) -> Publication {
    let at = location(cluster, node);
    let kept = [
        observe::capability::scope(&at),
        format!("{at}/{}/", Stage::Process.name()),
    ];
    let now = now_unix_nanos();
    let mut snapshot = last.snapshot();
    for record in &last.records {
        if record.evidence == configure::NOT_STARTED
            || kept
                .iter()
                .any(|kept| record.scope.starts_with(kept.as_str()))
        {
            continue;
        }
        let evidence = if record.scope == at {
            said.to_string()
        } else {
            "stopped with the node".to_string()
        };
        snapshot.record_health(HealthRecord {
            scope: record.scope.clone(),
            health: Health::Done,
            severity: 0,
            evidence,
            observed_unix_nanos: now,
        });
    }
    let topology = drawn(cluster, node, &snapshot);
    Publication::whole(&last.source, &last.node, &snapshot)
        .with_orders(last.orders.clone())
        .with_topology(Some(topology))
}

#[cfg(test)]
mod tests {
    use super::*;
    use observe::Snapshot;

    fn record(scope: &str, health: Health, evidence: &str) -> HealthRecord {
        HealthRecord {
            scope: scope.to_string(),
            health,
            severity: 0,
            evidence: evidence.to_string(),
            observed_unix_nanos: 1,
        }
    }

    #[test]
    fn a_stopped_node_is_done_and_keeps_what_it_declared_its_pauses_and_not_started() {
        let cluster = configure::fixture::test_cluster();
        let (name, node) = (&cluster.name, &cluster.node(0).name);
        let at = cluster.node_scope(0);
        let at = at.as_str();
        let mut snapshot = Snapshot::new();
        for (leaf, health, evidence) in [
            ("", Health::Fine, "said"),
            ("/system-process", Health::Fine, "said"),
            ("/capability", Health::Fine, "said"),
            ("/receive/In", Health::Fine, "said"),
            ("/receive/Off", Health::Done, configure::NOT_STARTED),
            ("/process/onward", Health::Paused, "said"),
        ] {
            snapshot.record_health(record(&format!("{at}{leaf}"), health, evidence));
        }
        let last = Publication::whole("xmip-service", at, &snapshot).with_orders("orders");

        let left = stopped(name, node, &last, "stopped by the console");
        let moods: Vec<(&str, Health)> = left
            .records
            .iter()
            .map(|record| (record.scope.as_str(), record.health))
            .collect();
        for (leaf, health) in [
            ("", Health::Done),
            ("/system-process", Health::Done),
            ("/receive/In", Health::Done),
            ("/capability", Health::Fine),
            ("/process/onward", Health::Paused),
        ] {
            let scope = format!("{at}{leaf}");
            assert!(
                moods.contains(&(scope.as_str(), health)),
                "{scope}: {moods:?}"
            );
        }
        let evidence = |scope: &str| {
            left.records
                .iter()
                .find(|record| record.scope == scope)
                .map(|record| record.evidence.as_str())
        };
        assert_eq!(evidence(at), Some("stopped by the console"));
        let off = format!("{at}/receive/Off");
        assert_eq!(evidence(&off), Some(configure::NOT_STARTED));
        assert_eq!(left.orders, "orders");
        let drawn = left.topology.expect("drawn again");
        let id = format!("node/{node}");
        assert!(drawn.nodes.iter().any(|drawn| drawn.id == id));
        assert!(
            (drawn.nodes[0].activity).abs() < f64::EPSILON,
            "no process alive"
        );
    }
}
