//! A test node that sends: its Send Port `Out` to a far end in the test,
//! its policy and `[tuning]`, its send step dispatched while a test runs,
//! and what each pass of a send ended as — what `send.rs` and
//! `send_killed.rs` run their nodes with.

use std::io::Cursor;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use configure::{DesignedSendPort, SendPortGroup};
use journey::Journey;
use persist::fixture::Memory;
use persist::storage::{Embedded, XmipStorage};
use receive::ReceivedStream;
use route::Subscriber;
use secret::{Held, KekName};
use transport::TransportError;
use xcore::JourneyId;
use xmip_core_runtime::fixture::{Answer, FarEnd};
use xmip_core_runtime::message_path::Runtime;
use xmip_core_runtime::send_step::{Departure, Ended, dispatch};
use xmip_core_runtime::sending::Sends;
use xmip_core_runtime::tuning::Tuning;

use super::receive_cycle::{Sender, subscription};

/// How long a test waits for what it expects before it fails.
const PATIENCE: Duration = Duration::from_secs(10);

/// A test Storage node in memory.
pub fn memory() -> Arc<dyn XmipStorage> {
    let keys = Held::new(secret::fixture::Memory::default());
    let kek = KekName::new("storage").expect("a name");
    Arc::new(Embedded::open(Memory::default(), Memory::default(), &keys, &kek).expect("opened"))
}

/// The Stream `order <number>`.
pub fn order(number: u32) -> ReceivedStream {
    ReceivedStream::new(
        Cursor::new(format!("order {number}").into_bytes()),
        "tcp://127.0.0.1:1",
    )
}

/// The Send Port `Out`, its policy what `shaped` makes of none.
pub fn out(shaped: impl FnOnce(&mut DesignedSendPort)) -> DesignedSendPort {
    port("Out", shaped)
}

/// The Send Port `name`, its policy what `shaped` makes of none.
pub fn port(name: &str, shaped: impl FnOnce(&mut DesignedSendPort)) -> DesignedSendPort {
    let mut port = DesignedSendPort {
        name: name.to_string(),
        send_locations: Vec::new(),
        retry: None,
        failover: None,
        execution_style: None,
        order_key: None,
        on_failure: None,
    };
    shaped(&mut port);
    port
}

/// The `[tuning]` the tests' nodes send by: a lease and a scan short
/// enough for a test to see a claim lapse and be taken up.
pub fn quick() -> Tuning {
    Tuning {
        send_lease: Duration::from_millis(300),
        send_scan: Duration::from_millis(20),
        ..Tuning::default()
    }
}

/// The node at `node` sending `Out` to `far` by `port`.
pub fn sender(node: String, far: FarEnd, port: DesignedSendPort) -> Sender {
    senders(node, vec![(far, port)], Vec::new())
}

/// The node at `node` sending each Send Port to its far end, by its
/// policy, with the Send Port Groups `groups`.
pub fn senders(
    node: String,
    ports: Vec<(FarEnd, DesignedSendPort)>,
    groups: Vec<SendPortGroup>,
) -> Sender {
    let (locations, ports) = ports
        .into_iter()
        .map(|(far, port)| (far.at(&port.name), port))
        .unzip();
    Sender {
        sends: Sends {
            locations,
            ports,
            groups,
        },
        tuning: quick(),
        node,
        audit: None,
    }
}

/// How each pass of a send ended, by Journey, in the order they ended.
#[derive(Default)]
pub struct Told(Mutex<Vec<(JourneyId, &'static str)>>);

impl Told {
    fn tell(&self, departure: &Departure, ended: &Ended) {
        let said = match ended {
            Ended::Completed(_) => "completed",
            Ended::Waiting { .. } => "waiting",
            Ended::Failed { .. } => "failed",
            Ended::Lost(_) => "lost",
            Ended::Unwritten(_) => "unwritten",
        };
        let id = departure.work.journey.journey_id();
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((id, said));
    }

    fn has(&self, id: JourneyId, said: &'static str) -> bool {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(&(id, said))
    }

    /// Wait, bounded, until `id`'s send ended as `said`.
    pub fn wait_for(&self, id: JourneyId, said: &'static str) {
        until(|| self.has(id, said), &format!("{id} {said}"));
    }
}

/// Wait, bounded and never a sleep, until `holds`.
pub fn until(holds: impl Fn() -> bool, what: &str) {
    let deadline = Instant::now() + PATIENCE;
    while !holds() {
        assert!(Instant::now() < deadline, "never: {what}");
        std::thread::yield_now();
    }
}

/// The send step of `runtime` dispatching while `run` runs, closed after:
/// what `run` returns, and how long the close took.
pub fn dispatching<T>(runtime: &Runtime<'_>, run: impl FnOnce(&Told) -> T) -> (T, Duration) {
    let told = Told::default();
    let tell = |departure: &Departure, ended: &Ended| told.tell(departure, ended);
    let tell = &tell;
    std::thread::scope(|scope| {
        let dispatched = scope.spawn(move || dispatch(scope, runtime, tell));
        let returned = run(&told);
        let closing = Instant::now();
        runtime.send.close();
        dispatched.join().expect("dispatched");
        (returned, closing.elapsed())
    })
}

/// The Journey `id` as the Ledger keeps it.
pub fn journey(storage: &dyn XmipStorage, id: JourneyId) -> Journey {
    let record = storage
        .read_journey(id)
        .expect("read")
        .expect("in the Ledger");
    Journey::from_record(&record.body).expect("a Journey")
}

/// The Journeys waiting in `Out`'s queue, oldest first.
pub fn waiting(runtime: &Runtime<'_>) -> Vec<JourneyId> {
    waiting_in(runtime, "Out")
}

/// The Journeys waiting in the queue of the Send Port `port`, oldest first.
pub fn waiting_in(runtime: &Runtime<'_>, port: &str) -> Vec<JourneyId> {
    let queue = runtime.send.queue(&Subscriber::SendPort(port.to_string()));
    let read = runtime.storage.read_held(queue, 0, 64).expect("read");
    read.held.iter().map(|held| held.hold.journey).collect()
}

/// What the far end took, as text.
pub fn took(taken: &Mutex<Vec<Vec<u8>>>) -> Vec<String> {
    taken
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
        .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
        .collect()
}

pub fn refusing(why: &'static str, retryable: bool) -> Answer {
    Box::new(move |_| {
        Err(TransportError {
            message: why.to_string(),
            retryable,
        })
    })
}

pub fn taking() -> Answer {
    Box::new(|_| Ok(()))
}

pub fn onward() -> [route::Subscription; 1] {
    [subscription(
        "onward",
        "xmip.transport.mechanism = 'circumstance'",
    )]
}
