//! The send step held to what it can carry (`runtime-model.md` section 10,
//! *How a send runs*):
//!
//! - a send whose thread panics is settled all the same: written Failed
//!   with why, its claim ended, counted, never left owned and renewed;
//! - a scan claims no more than the Send pool can take, so a backlog
//!   waits unclaimed in its queue rather than behind the pool;
//! - so does a Publication: what the pool has no place for stays durable
//!   and unclaimed, never in memory, and is sent once a place frees;
//! - Journeys another node holds keep no place from those behind them;
//! - claims in flight are renewed while a scan is held up, however long;
//! - a Journey that failed before a restart is the Port's evidence again
//!   once a scan reads it, and is let go of when an operator acts on it.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use journey::JourneyState;
use observe::Act;
use xcore::JourneyId;
use xmip_core_runtime::fixture::{Answer, FarEnd, Operation};
use xmip_core_runtime::ledger::CHUNK;
use xmip_core_runtime::message_path::carry;
use xmip_core_runtime::pool::hardware_threads;

use super::receive_cycle::{node, on_node, on_runtime};
use super::sending::{
    dispatching, interleaving, journey, memory, onward, order, out, refusing, sender, taking, until,
};

/// A gate a test opens once: whatever waits on it goes on.
#[derive(Default)]
struct Gate(Mutex<bool>, Condvar);

impl Gate {
    fn wait(&self) {
        let mut open = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        while !*open {
            open = self.1.wait(open).unwrap_or_else(PoisonError::into_inner);
        }
    }

    fn open(&self) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = true;
        self.1.notify_all();
    }
}

/// A far end that counts every send it is asked and holds it at `gate`.
fn held_at(gate: &Arc<Gate>, entered: &Arc<AtomicUsize>) -> Answer {
    let (gate, entered) = (Arc::clone(gate), Arc::clone(entered));
    Box::new(move |_| {
        entered.fetch_add(1, Ordering::AcqRel);
        gate.wait();
        Ok(())
    })
}

/// Whether another node could take a claim on `id` now — given back at
/// once where it could.
fn free(storage: &dyn persist::storage::XmipStorage, id: JourneyId) -> bool {
    let other = configure::fixture::test_cluster().node_scope(1);
    let taken = storage
        .claim(id, &other, id.value() ^ 0xf1ee, Duration::from_secs(30))
        .expect("asked");
    taken.is_some_and(|claim| storage.release(&claim).expect("asked"))
}

#[test]
fn a_send_whose_thread_panics_is_written_failed_with_why_and_its_claim_ended() {
    let storage = memory();
    let (far, _) = FarEnd::answering(Box::new(|_| panic!("a transport that panics")));
    on_node(
        &storage,
        (CHUNK, &onward()),
        sender(node(), far, out(|_| {})),
        |runtime, pickup, gate| {
            dispatching(runtime, |told| {
                let id = carry(runtime, pickup, gate, order(1)).journeys[0].journey_id();
                told.wait_for(id, "failed");
                let failed = journey(storage.as_ref(), id);
                assert_eq!(failed.state, JourneyState::Failed);
                let said = &failed.entries().last().expect("its send").outcome;
                assert!(said.contains("panicked"), "{said}");
                assert!(free(storage.as_ref(), id), "its claim ended");
                assert_eq!(runtime.send.figures()["Out"].failed, 1);
            });
        },
    );
}

#[test]
fn a_scan_claims_no_more_than_the_send_pool_can_take() {
    let storage = memory();
    let most = hardware_threads();
    let count = u32::try_from(most + 8).expect("a count");
    let ids: Vec<JourneyId> = on_runtime(&storage, CHUNK, |runtime, pickup, gate| {
        (1..=count)
            .map(|n| carry(runtime, pickup, gate, order(n)).journeys[0].journey_id())
            .collect()
    });
    let (gate, entered) = (Arc::new(Gate::default()), Arc::new(AtomicUsize::new(0)));
    let (far, _) = FarEnd::answering(held_at(&gate, &entered));
    let mut sending = sender(node(), far, out(|_| {}));
    sending.tuning.send_threads_per_hardware_thread = 1;
    on_node(&storage, (CHUNK, &onward()), sending, |runtime, _, _| {
        dispatching(runtime, |told| {
            until(|| entered.load(Ordering::Acquire) == most, "the pool full");
            let held = ids
                .iter()
                .filter(|id| !free(storage.as_ref(), **id))
                .count();
            gate.open();
            for id in &ids {
                told.wait_for(*id, "completed");
            }
            assert_eq!(held, most, "claimed only what the pool could take");
        });
    });
}

#[test]
fn a_publication_claims_no_more_than_the_send_pool_can_take() {
    let storage = memory();
    let most = hardware_threads();
    let count = u32::try_from(most + 8).expect("a count");
    let (gate, entered) = (Arc::new(Gate::default()), Arc::new(AtomicUsize::new(0)));
    let (far, _) = FarEnd::answering(held_at(&gate, &entered));
    let mut sending = sender(node(), far, out(|_| {}));
    sending.tuning.send_threads_per_hardware_thread = 1;
    on_node(
        &storage,
        (CHUNK, &onward()),
        sending,
        |runtime, pickup, carrying| {
            dispatching(runtime, |told| {
                let ids: Vec<JourneyId> = (1..=count)
                    .map(|n| carry(runtime, pickup, carrying, order(n)).journeys[0].journey_id())
                    .collect();
                until(|| entered.load(Ordering::Acquire) == most, "the pool full");
                let held = ids
                    .iter()
                    .filter(|id| !free(storage.as_ref(), **id))
                    .count();
                gate.open();
                for id in &ids {
                    told.wait_for(*id, "completed");
                }
                assert_eq!(held, most, "the rest left durable and unclaimed");
            });
        },
    );
}

#[test]
fn journeys_another_node_holds_keep_no_place_from_those_behind_them() {
    let storage = memory();
    let most = hardware_threads();
    let count = u32::try_from(most + 8).expect("a count");
    let ids: Vec<JourneyId> = on_runtime(&storage, CHUNK, |runtime, pickup, gate| {
        (1..=count)
            .map(|n| carry(runtime, pickup, gate, order(n)).journeys[0].journey_id())
            .collect()
    });
    // The oldest, as many as the pool has places, held by a live node.
    let other = configure::fixture::test_cluster().node_scope(1);
    let held = |id: JourneyId| {
        let lease = Duration::from_secs(30);
        let claim = storage.claim(id, &other, id.value() ^ 0x07e5, lease);
        claim.expect("asked").is_some()
    };
    for id in &ids[..most] {
        until(|| held(*id), "held by another node");
    }
    let (far, _) = FarEnd::answering(taking());
    let mut sending = sender(node(), far, out(|_| {}));
    sending.tuning.send_threads_per_hardware_thread = 1;
    on_node(&storage, (CHUNK, &onward()), sending, |runtime, _, _| {
        dispatching(runtime, |told| {
            for id in &ids[most..] {
                told.wait_for(*id, "completed");
            }
        });
    });
}

#[test]
fn a_claim_in_flight_is_renewed_while_a_scan_is_held_up() {
    let (interleaved, storage) = interleaving();
    let (gate, entered) = (Arc::new(Gate::default()), Arc::new(AtomicUsize::new(0)));
    let (far, _) = FarEnd::answering(held_at(&gate, &entered));
    on_node(
        &storage,
        (CHUNK, &onward()),
        sender(node(), far, out(|_| {})),
        |runtime, pickup, carrying| {
            dispatching(runtime, |told| {
                let id = carry(runtime, pickup, carrying, order(1)).journeys[0].journey_id();
                until(|| entered.load(Ordering::Acquire) == 1, "sending");
                let (scanning, stuck) =
                    (Arc::new(Gate::default()), Arc::new(AtomicBool::new(false)));
                let (held, at) = (Arc::clone(&scanning), Arc::clone(&stuck));
                interleaved.before(
                    Operation::ReadHeld,
                    Box::new(move || {
                        at.store(true, Ordering::Release);
                        held.wait();
                    }),
                );
                until(|| stuck.load(Ordering::Acquire), "a scan held up");
                // Three leases pass with the dispatching held in its scan.
                let lapsed = Instant::now() + runtime.send.lease() * 3;
                until(|| Instant::now() >= lapsed, "three leases");
                let renewed = !free(storage.as_ref(), id);
                scanning.open();
                gate.open();
                told.wait_for(id, "completed");
                assert!(renewed, "renewed while the scan was held up");
            });
        },
    );
}

#[test]
fn a_journey_that_failed_before_a_restart_is_its_ports_evidence_until_acted_on() {
    let storage = memory();
    let (far, _) = FarEnd::answering(refusing("the far end refused it", false));
    let id = on_node(
        &storage,
        (CHUNK, &onward()),
        sender(node(), far, out(|_| {})),
        |runtime, pickup, gate| {
            let (id, _) = dispatching(runtime, |told| {
                let id = carry(runtime, pickup, gate, order(1)).journeys[0].journey_id();
                told.wait_for(id, "failed");
                id
            });
            id
        },
    );
    // The node restarted: nothing of its figures is in memory any more.
    let (far, _) = FarEnd::answering(taking());
    on_node(
        &storage,
        (CHUNK, &onward()),
        sender(node(), far, out(|_| {})),
        |runtime, _, _| {
            dispatching(runtime, |_| {
                let failing = || runtime.send.figures().get("Out").map(|f| f.failing);
                until(|| failing() == Some(1), "found failing again");
                let figures = runtime.send.figures()["Out"].clone();
                assert_eq!(figures.oldest_failing[0].journey, id);
                assert!(
                    figures.oldest_failing[0].reason.contains("refused it"),
                    "{:?}",
                    figures.oldest_failing
                );
                assert_eq!(
                    figures.last_failure, None,
                    "what failed now is not history: none failed since the restart"
                );
                assert!(!figures.blocked, "not a Sequential Port");
                let page = runtime.send.failed_journeys("Out", 0, 10).expect("read");
                assert_eq!(page.journeys.len(), 1, "read from Xmip Storage too");
                assert_eq!(page.journeys[0].journey, id);
                runtime
                    .send
                    .act(&id.to_string(), Act::Dismiss, "ilian")
                    .expect("dismissed");
                assert_eq!(failing(), Some(0), "acted on, let go of");
            });
        },
    );
}
