//! A Message's hand-on is in its own share (ADR-0018, amendment
//! 2026-11-15): the send thread's work on it, and its share of the Storage
//! node's batch. Until 2026-11-15 the share was read once the far end had
//! the Message, before its hand-on, and held none of it.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use net::fixture::unheld;
use tcp::TcpTransport;
use xcore::processor_time::ProcessorTime;
use xmip_core_runtime::fixture::{Failing, Operation, started};

use super::node::{deliver, linked, node, path_text, written};

/// How long Xmip Storage spins the sending thread's processor before each
/// hand-on is asked.
const SPIN: Duration = Duration::from_millis(3);

/// Xmip Storage spins [`SPIN`] of the sending thread's processor before
/// each hand-on is asked, and the node's own share of a Message, the
/// fastest of five, holds it.
#[test]
fn a_message_s_hand_on_is_counted_in_its_own_share() {
    let far = TcpTransport::loopback();
    let (listener, far_address) = far.bind().expect("the far end binds");
    let receive = unheld().to_string();
    let path = written("handed-on", &node(&receive, &far_address));
    let failing: Arc<Mutex<Option<Arc<Failing>>>> = Arc::default();
    let running = started(path_text(&path), || {
        let mut linked = linked(&path);
        let beneath = linked.storage.take().expect("its Storage node");
        let spinning = Failing::over(beneath);
        *failing.lock().expect("held") = Some(Arc::clone(&spinning));
        linked.storage = Some(spinning);
        linked
    })
    .expect("the node starts");
    let failing = failing.lock().expect("held").clone().expect("opened");
    let mut answered = 0;
    for message in 0..5 {
        failing.before(
            Operation::HandOn,
            Box::new(|| {
                let began = ProcessorTime::thread();
                while ProcessorTime::thread().since(began) < SPIN {
                    std::hint::spin_loop();
                }
            }),
        );
        deliver(&TcpTransport::loopback(), &receive, b"an order");
        far.accept_one(&listener)
            .expect("it reaches the far end")
            .taken()
            .expect("read whole");
        // Its hand-on answered, the spin it ran taken: the next is told.
        let deadline = Instant::now() + Duration::from_secs(10);
        while answered <= message {
            answered += failing.taken(Operation::HandOn).len();
            assert!(Instant::now() < deadline, "its hand-on is answered");
            std::thread::yield_now();
        }
    }
    let outcomes = running.stop();
    assert_eq!(outcomes.sent, 5, "{outcomes:?}");
    let own = outcomes.own_share.expect("measured");
    assert!(own >= SPIN, "its hand-on counted: {own:?}");
    let _ = std::fs::remove_dir_all(path.parent().expect("its directory"));
}
