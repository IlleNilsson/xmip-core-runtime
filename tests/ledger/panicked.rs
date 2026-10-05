//! A carry that panics, settled as failed (`runtime-model.md` section 5,
//! *How a receive runs*): its far end is told `Failed` and keeps the
//! Stream to send again, the Receive Location settles the arrival and goes
//! on, and its serving returns when the node stops. Until 2026-10-03 the
//! Location waited for that arrival's telling for good, and so did the
//! node's stop.

use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use transport::{Acknowledgement, Arrivals, Directions, Transport, Verdict};
use xmip_core_runtime::ledger::CHUNK;
use xmip_core_runtime::message_path::ReceiveCycle;
use xmip_core_runtime::receiving::Receiving;

use super::receive_cycle::on_runtime;
use super::{directory, test_node};

/// A body whose first read panics: a defect anywhere in the carry.
struct Panics;

impl Read for Panics {
    fn read(&mut self, _into: &mut [u8]) -> std::io::Result<usize> {
        panic!("a carry that panics");
    }
}

/// One arrival with a panicking body, then nothing; what its far end was
/// told is kept in `told`.
struct Once {
    given: AtomicBool,
    told: Arc<Mutex<Vec<Verdict>>>,
}

impl Transport for Once {
    fn name(&self) -> &'static str {
        "once"
    }

    fn directions(&self) -> Directions {
        Directions::RECEIVE
    }

    fn arrivals(&self) -> Arrivals {
        Arrivals::Ordered("one arrival, told before the next receive")
    }

    fn receive(&self) -> transport::Result<Vec<transport::Arrived>> {
        if self.given.swap(true, Ordering::AcqRel) {
            return Ok(Vec::new());
        }
        let told = Arc::clone(&self.told);
        let acknowledgement = Acknowledgement::deferred(move |verdict| {
            told.lock().expect("the far end").push(verdict);
            Ok(())
        });
        Ok(vec![transport::Arrived::new(
            "once://in/1",
            Panics,
            acknowledgement,
        )])
    }

    fn send(&self, _target: &str, _bytes: &[u8]) -> transport::Result<()> {
        Ok(())
    }
}

#[test]
fn a_carry_that_panics_settles_as_failed_and_the_location_stops() {
    let told = Arc::new(Mutex::new(Vec::new()));
    let far_end = Arc::clone(&told);
    let (done, finished) = mpsc::channel();
    // On a thread of its own, so a Location left waiting fails the test
    // rather than hanging it.
    std::thread::spawn(move || {
        let storage = test_node(&directory("panicked"));
        let served = on_runtime(&storage, CHUNK, |runtime, pickup, gate| {
            let location = Receiving {
                configured: configure::ConfiguredLocation {
                    name: "In".to_string(),
                    start: true,
                    transport: "once".to_string(),
                    address: "once://in".to_string(),
                    credentials: None,
                    contract: None,
                    settings: configure::LocationSettings::default(),
                    contract_settings: configure::LocationSettings::default(),
                    accept: configure::Accept::default(),
                },
                gate: gate.clone(),
                transport: Box::new(Once {
                    given: AtomicBool::new(false),
                    told: far_end,
                }),
                limits: xmip_core_runtime::tuning::Tuning::default().receive(),
                audit: None,
            };
            let stopping = AtomicBool::new(false);
            let mut cycles = Vec::new();
            let ended = std::thread::scope(|scope| {
                location.serve(scope, runtime, pickup, &stopping, |carried| {
                    cycles.push(carried.cycle());
                    stopping.store(true, Ordering::Release);
                })
            });
            (ended, cycles)
        });
        let _ = done.send(served);
    });

    let (ended, cycles) = finished
        .recv_timeout(Duration::from_secs(10))
        .expect("the Location stops: a panicked carry left it waiting");
    ended.expect("the Location stopped cleanly");
    assert_eq!(cycles, [ReceiveCycle::Failed], "settled as failed");
    assert_eq!(
        *told.lock().expect("the far end"),
        [Verdict::Failed],
        "the far end keeps it to send again"
    );
}
