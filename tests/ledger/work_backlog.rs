//! A backlog behind its Receive Location's sequences, drained through a
//! Work Process (open problem 93; ADR-0066, amendment 2026-11-22): a pass of
//! its queue takes a turn of the Message heading each sequence only, each
//! sequence's head read once, and passes every Message behind one — not
//! claimed, its Journey not read, no turn — so a backlog of a thousand over
//! four sequences drains claiming each Message once, each in its sequence's
//! order. Until 2026-11-22 every pass claimed every entry, read it, asked
//! the Ledger whether its Stream headed and gave it back, and completed one
//! Message a sequence: on the Hyper-V environment 10,777 sales orders went
//! through at two to four a minute.

use std::io::Read;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use journey::JourneyState;
use message::Message;
use persist::storage::XmipStorage;
use process::program::Call;
use xcore::lock::Locked;
use xcore::{IdGenerator, JourneyId, MessageId};
use xmip_core_runtime::fixture::{Failing, Operation};
use xmip_core_runtime::ledger::CHUNK;
use xmip_core_runtime::split::Split;
use xmip_core_runtime::work_step::{NoUnits, Thrown, WorkUnits};

use super::receive_cycle::on_working_node;
use super::sending::{PATIENCE, journey, memory};
use super::work_bounded::PAGE;
use super::work_design::{CALLS, carried_through, compiled, opened, routes_to, running_as};
use super::work_turning::{counted_node, turning};

/// The sequences: one a client, each client's Streams one at a time.
const CLIENTS: usize = 4;

/// The Messages of each client.
const EACH: usize = 250;

/// Units that record the text of each Message they are called with, in the
/// order called, and answer it assigned to a new one.
#[derive(Default)]
struct Recording(Mutex<Vec<String>>);

impl WorkUnits for Recording {
    fn call(
        &self,
        _: &Call,
        message: &Message,
        ids: &dyn IdGenerator,
    ) -> Result<Vec<Message>, Thrown> {
        let mut text = String::new();
        let section = &message.sections()[0];
        let mut reader = section.stream.reader().expect("its Stream");
        reader.read_to_string(&mut text).expect("text");
        self.0.locked().push(text);
        let id = MessageId::new(ids.next_u128());
        Ok(vec![message.assigned(id, message.context().clone())])
    }

    fn splitter(&self, call: &Call) -> Result<Box<dyn Split>, Thrown> {
        NoUnits.splitter(call)
    }
}

#[test]
fn a_backlog_over_a_few_sequences_drains_claiming_each_message_once_in_its_order() {
    let beneath = memory();
    let failing = Failing::over(Arc::clone(&beneath));
    let storage: Arc<dyn XmipStorage> = Arc::clone(&failing) as _;
    let recording = Arc::new(Recording::default());
    let units: Arc<dyn WorkUnits> = Arc::clone(&recording) as _;
    let calls = running_as("Calls", Box::new(compiled(CALLS)), units);
    let routes = routes_to(&["Calls"]);
    let runs = (counted_node(), vec![calls]);
    on_working_node(&storage, (CHUNK, &routes), runs, |works, pickup, gate| {
        // Each client's Streams one at a time through its Receive Location.
        let gate = opened(gate);
        let mut ids = Vec::with_capacity(CLIENTS * EACH);
        for number in 0..EACH {
            for client in 0..CLIENTS {
                let who = format!("C{client}");
                let text = format!("{who} {number}");
                ids.push(carried_through(
                    (works, pickup),
                    &gate,
                    "Calls",
                    (&who, &text),
                ));
            }
        }
        let asked = |operation| failing.asked_times(operation);
        let before = (asked(Operation::Claim), asked(Operation::ReadJourney));
        let heads_before = asked(Operation::ReadHeld);
        let pages_before = asked(Operation::ReadDue);
        let completed =
            |id: &JourneyId| journey(beneath.as_ref(), *id).state == JourneyState::Completed;
        turning(works, pickup, || {
            let deadline = Instant::now() + PATIENCE;
            let mut done = 0;
            while done < ids.len() {
                if completed(&ids[done]) {
                    done += 1;
                    continue;
                }
                if Instant::now() >= deadline {
                    let turned = ids.iter().filter(|id| completed(id)).count();
                    panic!(
                        "never every Message turned: {turned} of {}, the first waiting {done}",
                        ids.len()
                    );
                }
                std::thread::yield_now();
            }
        });
        let count = ids.len() as u64;
        let claims = asked(Operation::Claim) - before.0;
        let read = asked(Operation::ReadJourney) - before.1;
        let heads = asked(Operation::ReadHeld) - heads_before;
        let pages = asked(Operation::ReadDue) - pages_before;
        eprintln!(
            "{count} Messages over {CLIENTS} sequences: {claims} claims, {read} Journeys read, \
             {heads} heads read, {pages} pages of the queue read"
        );
        // Each Message claimed and read once, as it heads its sequence; the
        // first of a sequence met before its head was read is taken up as
        // before, and may be given back once.
        let sequences = CLIENTS as u64;
        let most = count + 2 * sequences;
        assert!(claims <= most, "{claims} claims for {count} Messages");
        assert!(read <= most, "{read} Journeys read for {count} Messages");
        // Each its sequence's head read as it is handed over, its entry read
        // again then, and its head asked under its claim: three a Message,
        // never a read a Message behind it.
        assert!(
            heads <= 3 * most,
            "{heads} heads and entries read for {count} Messages"
        );
        // The queue read once, and each sequence read on from where it was
        // cut: a few times its length over a page, never a pass a Message.
        let page = PAGE as u64;
        let pages_most = (sequences + 1) * count.div_ceil(page) + 2 * sequences;
        assert!(
            pages <= pages_most,
            "{pages} pages read for {count} Messages"
        );
    });
    let recorded = recording.0.locked().clone();
    assert_eq!(recorded.len(), CLIENTS * EACH, "each Message turned once");
    for client in 0..CLIENTS {
        let who = format!("C{client}");
        let numbers: Vec<usize> = recorded
            .iter()
            .filter_map(|text| text.strip_prefix(&format!("{who} ")))
            .map(|number| number.parse().expect("a number"))
            .collect();
        let ordered: Vec<usize> = (0..EACH).collect();
        assert_eq!(
            numbers, ordered,
            "{who}'s Messages in their sequence's order"
        );
    }
}
