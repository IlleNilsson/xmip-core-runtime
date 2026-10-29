//! How soon a Receive Location asks its transport again
//! (`runtime-model.md` section 5, *How a receive runs*): a polled one that
//! found nothing rests its poll interval, one that failed in a way asking
//! again may mend rests its backoff, one whose receive waits by itself is
//! asked again at once, and a stop ends a rest the moment it is raised.
//! Until 2026-10-12 every Location was asked again at once, and an idle
//! polled one — a drop directory, a table — spun.
//!
//! Each rest is held to a floor, never to the machine's speed: receives a
//! rest apart cannot come sooner on any machine, however fast. The rest
//! that must not be taken is a minute, so a Location that took it shows as
//! a run of a minute, not as a test that never ends.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use transport::{Arrivals, Directions, Transport, TransportError, Waiting};
use xmip_core_runtime::ledger::CHUNK;
use xmip_core_runtime::receiving::{Pace, Receiving};
use xmip_core_runtime::stopping::Stopping;
use xmip_core_runtime::tuning::Tuning;

use super::receive_cycle::on_runtime;
use super::{directory, test_node};

/// A rest no passing Location may take.
const NEVER: Duration = Duration::from_secs(60);

/// A short rest the Location must take.
const REST: Duration = Duration::from_millis(40);

/// The receives a Location is held to before it is stopped.
const RECEIVES: usize = 4;

/// A far end with nothing for its Location: every receive finds nothing,
/// or fails in a way asking again may mend. It raises the node's stop at
/// its [`RECEIVES`]th receive where told to, and says when its first came.
struct Idle {
    waiting: Waiting,
    fails: bool,
    asked: Arc<AtomicUsize>,
    stop_at: Option<usize>,
    stopping: Arc<Stopping>,
    first: Mutex<Option<mpsc::Sender<()>>>,
}

impl Transport for Idle {
    fn name(&self) -> &'static str {
        "idle"
    }

    fn directions(&self) -> Directions {
        Directions::RECEIVE
    }

    fn arrivals(&self) -> Arrivals {
        Arrivals::Ordered("nothing ever arrives")
    }

    fn waiting(&self) -> Waiting {
        self.waiting
    }

    fn receive_up_to(&self, _most: usize) -> transport::Result<Vec<transport::Arrived>> {
        let asked = self.asked.fetch_add(1, Ordering::AcqRel) + 1;
        if let Some(first) = self.first.lock().expect("lock").take() {
            let _ = first.send(());
        }
        if self.stop_at == Some(asked) {
            self.stopping.raise();
        }
        if self.fails {
            Err(TransportError::retryable("the far end did not answer"))
        } else {
            Ok(Vec::new())
        }
    }

    fn sending(&self) -> transport::Sending {
        transport::Sending::Streamed("it sends nothing")
    }

    fn send_from(&self, _: &str, _: transport::Outgoing<'_>) -> transport::Result<()> {
        Ok(())
    }
}

/// What one Location's serve did: how many receives, how long it took.
struct Served {
    asked: usize,
    took: Duration,
}

/// Serve a Location over [`Idle`] at `pace`, stopped at its
/// [`RECEIVES`]th receive where `stop_at_last`, otherwise as soon as its
/// first receive has come.
fn serve(test: &str, waiting: Waiting, fails: bool, pace: Pace, stop_at_last: bool) -> Served {
    let at = directory(test);
    let storage = test_node(&at.join("node"));
    let stopping = Arc::new(Stopping::default());
    let (first, came) = mpsc::channel();
    let asked = Arc::new(AtomicUsize::new(0));
    let idle = Idle {
        waiting,
        fails,
        asked: Arc::clone(&asked),
        stop_at: stop_at_last.then_some(RECEIVES),
        stopping: Arc::clone(&stopping),
        first: Mutex::new(Some(first)),
    };
    let served = on_runtime(&storage, CHUNK, |runtime, pickup, gate| {
        let location = Receiving {
            configured: configure::ConfiguredLocation {
                name: "In".to_string(),
                start: true,
                address: "idle://in".to_string(),
                secret: None,
                contract: None,
                settings: configure::LocationSettings::default(),
                contract_settings: configure::LocationSettings::default(),
                accept: configure::Accept::default(),
                prepare: Vec::new(),
                transform: None,
                promote: None,
                demote: None,
                debatch: None,
                correlation: None,
            },
            gate: gate.clone(),
            transport: Box::new(idle),
            limits: Tuning::default().receive(),
            pace,
            audit: None,
        };
        let began = Instant::now();
        let ended = std::thread::scope(|scope| {
            let serving = scope.spawn(|| {
                std::thread::scope(|pool| location.serve(pool, runtime, pickup, &stopping, |_| {}))
            });
            if !stop_at_last {
                came.recv().expect("the first receive comes");
                stopping.raise();
            }
            serving.join().expect("the Location serves")
        });
        let took = began.elapsed();
        ended.expect("the Location stopped when asked");
        Served {
            asked: asked.load(Ordering::Acquire),
            took,
        }
    });
    let _ = std::fs::remove_dir_all(&at);
    served
}

#[test]
fn an_idle_polled_location_rests_its_poll_between_receives() {
    let pace = Pace {
        poll: REST,
        backoff: NEVER,
        ..Pace::default()
    };
    let served = serve("paced-poll", Waiting::Polled("listed"), false, pace, true);
    assert_eq!(served.asked, RECEIVES);
    // Four receives, each after the one before by a poll at least.
    let floor = REST * u32::try_from(served.asked - 1).expect("few");
    assert!(served.took >= floor, "{:?} under {floor:?}", served.took);
    assert!(served.took < NEVER, "it backed off: {:?}", served.took);
}

#[test]
fn a_polled_location_backs_off_after_a_failure_that_may_mend() {
    let pace = Pace {
        poll: NEVER,
        backoff: REST,
        ..Pace::default()
    };
    let served = serve("paced-backoff", Waiting::Polled("listed"), true, pace, true);
    let floor = REST * u32::try_from(served.asked - 1).expect("few");
    assert!(served.took >= floor, "{:?} under {floor:?}", served.took);
    assert!(served.took < NEVER, "it rested its poll: {:?}", served.took);
}

#[test]
fn a_location_whose_receive_waits_is_asked_again_at_once() {
    let pace = Pace {
        poll: NEVER,
        backoff: NEVER,
        ..Pace::default()
    };
    let quiet = serve("paced-waits", Waiting::Waits("accepts"), false, pace, true);
    assert!(quiet.took < NEVER, "it rested: {:?}", quiet.took);
    let failed = serve(
        "paced-waits-ran-out",
        Waiting::Waits("accepts"),
        true,
        pace,
        true,
    );
    assert!(failed.took < NEVER, "it backed off: {:?}", failed.took);
}

#[test]
fn a_stop_ends_a_rest_at_once() {
    let pace = Pace {
        poll: NEVER,
        backoff: NEVER,
        ..Pace::default()
    };
    let served = serve("paced-stop", Waiting::Polled("listed"), false, pace, false);
    // Stopped in its first rest, of a minute: it did not wait it out.
    assert_eq!(served.asked, 1);
    assert!(
        served.took < NEVER,
        "the stop waited for the rest: {:?}",
        served.took
    );
}
