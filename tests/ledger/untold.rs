//! A far end that could not be told, in a way asking again may mend
//! (`runtime-model.md` section 5, *How a receive runs*): the Receive
//! Location goes on — what it was sent is kept for it to send again — and
//! the failure is audited once for each reason, with the Location and
//! why. Until 2026-10-05 such a failure was dropped unseen.

use std::io::Cursor;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use transport::{Acknowledgement, Arrivals, Directions, Transport, TransportError};
use xaudit::program_audit::ProgramAudit;
use xmip_core_runtime::ledger::CHUNK;
use xmip_core_runtime::receiving::Receiving;

use super::receive_cycle::on_runtime;
use super::{directory, test_node};

/// Why each of three arrivals' far end could not be told: two alike.
const WHY: [&str; 3] = [
    "returning a.xml: a file of that name was dropped since; held as a.xml.held",
    "returning a.xml: a file of that name was dropped since; held as a.xml.held",
    "returning b.xml: the share did not answer",
];

/// Three arrivals, then nothing; each telling fails as [`WHY`] says, in a
/// way asking again may mend.
struct Untold {
    given: AtomicBool,
}

impl Transport for Untold {
    fn name(&self) -> &'static str {
        "untold"
    }

    fn directions(&self) -> Directions {
        Directions::RECEIVE
    }

    fn arrivals(&self) -> Arrivals {
        Arrivals::Ordered("three arrivals, told before the next receive")
    }

    fn receive(&self) -> transport::Result<Vec<transport::Arrived>> {
        if self.given.swap(true, Ordering::AcqRel) {
            return Ok(Vec::new());
        }
        Ok(WHY
            .iter()
            .enumerate()
            .map(|(place, why)| {
                let acknowledgement = Acknowledgement::deferred(move |_| {
                    Err(TransportError {
                        message: (*why).to_string(),
                        retryable: true,
                    })
                });
                transport::Arrived::new(
                    format!("untold://in/{place}"),
                    Cursor::new(format!("arrival {place}").into_bytes()),
                    acknowledgement,
                )
            })
            .collect())
    }

    fn send(&self, _target: &str, _bytes: &[u8]) -> transport::Result<()> {
        Ok(())
    }
}

#[test]
fn a_telling_that_may_mend_is_audited_once_for_each_reason_and_the_location_goes_on() {
    let at = directory("untold");
    let storage = test_node(&at.join("node"));
    let audited = at.join("audit");
    let ended = on_runtime(&storage, CHUNK, |runtime, pickup, gate| {
        let location = Receiving {
            configured: configure::ConfiguredLocation {
                name: "In".to_string(),
                start: true,
                transport: "untold".to_string(),
                address: "untold://in".to_string(),
                credentials: None,
                contract: None,
                settings: configure::LocationSettings::default(),
                contract_settings: configure::LocationSettings::default(),
                accept: configure::Accept::default(),
            },
            gate: gate.clone(),
            transport: Box::new(Untold {
                given: AtomicBool::new(false),
            }),
            limits: xmip_core_runtime::tuning::Tuning::default().receive(),
            audit: Some(ProgramAudit::new(
                "xmip-runtime untold tests",
                Some(&audited),
            )),
        };
        let stopping = AtomicBool::new(false);
        let carried = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            location.serve(scope, runtime, pickup, &stopping, |_| {
                if carried.fetch_add(1, Ordering::AcqRel) + 1 == WHY.len() {
                    stopping.store(true, Ordering::Release);
                }
            })
        })
    });
    ended.expect("the Location went on, and stopped when asked");
    xaudit::keeper::settle();
    let text =
        std::fs::read_to_string(audited.join(xaudit::file_sink::FILE_NAME)).expect("audited");
    let told = text.matches("could not tell its far end").count();
    assert_eq!(told, 2, "once for each reason: {text}");
    assert!(text.contains("Receive Location 'In'"), "{text}");
    assert!(text.contains("held as a.xml.held"), "{text}");
    assert!(text.contains("the share did not answer"), "{text}");
    let _ = std::fs::remove_dir_all(&at);
}
