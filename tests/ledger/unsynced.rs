//! A receive killed between its Publication's answer and its sync: the
//! Publication is decided, written into the engine and answered, its sync
//! held (`persist::fixture::Hooks`), and the process killed there — on
//! Windows by `TerminateProcess`, as `Child::kill` ends it. The Ledger
//! opened again holds exactly what was durable before: the Message
//! received before it, every record as it was, and nothing of the one
//! answered and never synced, which went with the process (ADR-0018,
//! amendment 2026-10-20: the write-ahead log is written to its file by a
//! sync).

use std::io::Cursor;
use std::path::Path;
use std::sync::Arc;

use persist::Engine;
use persist::fixture::{Hooked, Hooks};
use persist::storage::{Embedded, XmipStorage};
use receive::ReceivedStream;
use rocksdb::RocksDb;
use secret::KekName;
use sqlite::Sqlite;
use xcore::MessageId;
use xmip_core_runtime::ledger::CHUNK;
use xmip_core_runtime::message_path::ReceiveCycle;
use xmip_core_runtime::outcome::Arrived;

use super::child_process::ChildProcess;
use super::receive_cycle::receiving;
use super::{STARTED, directory, keys, say, test_node};

/// The engine key after every key an engine keeps.
const LAST: [u8; 1024] = [0xff; 1024];

/// How many keys `engine` holds, every one.
fn entries(engine: &dyn Engine) -> usize {
    engine
        .scan(&[], &LAST, usize::MAX, false)
        .expect("scanned")
        .len()
}

/// In a child: one Stream received and durable, said with how many keys
/// the runtime database holds then; every sync held from there, and a
/// second Stream received until its Publication is answered and its sync
/// waits, said with how many it holds then; then it waits to be killed.
pub fn answered_until_killed(place: &Path) {
    std::fs::create_dir_all(place).expect("its directory");
    let hooks = Arc::new(Hooks::default());
    let runtime = RocksDb::open(&place.join("runtime")).expect("the runtime database");
    let node = Arc::new(
        Embedded::open(
            Hooked::new(runtime, &hooks),
            Sqlite::in_memory().expect("the administration database"),
            Sqlite::in_memory().expect("the audit database"),
            keys(&place.join("key")).as_ref(),
            &KekName::new("storage").expect("a name"),
        )
        .expect("the test Storage node"),
    );
    let storage: Arc<dyn XmipStorage> = Arc::clone(&node) as Arc<dyn XmipStorage>;
    let received = |body: &str| {
        ReceivedStream::new(Cursor::new(body.as_bytes().to_vec()), "tcp://127.0.0.1:1")
    };
    receiving::<()>(&storage, CHUNK, |carry| {
        let first = carry(received("order 0"));
        assert_eq!(
            first.cycle(),
            ReceiveCycle::Completed,
            "{:?}",
            first.arrived
        );
        let Arrived::Routed { work, .. } = &first.arrived else {
            panic!("routed: {:?}", first.arrived);
        };
        hooks.hold_syncs();
        let durable = entries(node.runtime().engine());
        say(&format!(
            "durable {} {durable}",
            work.message.message_id().value()
        ));
        let (held, watched) = (Arc::clone(&hooks), Arc::clone(&node));
        std::thread::spawn(move || {
            if held.wait_held(STARTED) {
                say(&format!("held {}", entries(watched.runtime().engine())));
            }
        });
        // Answered, then waits for a sync that never comes.
        let _ = carry(received("order 1"));
        panic!("the second receive ended with its sync held");
    });
}

#[test]
fn a_receive_killed_between_its_answer_and_its_sync_leaves_exactly_what_was_durable() {
    let place = directory("unsynced");
    let child = ChildProcess::start("unsynced", &place);
    let said = child.heard("durable ", STARTED);
    let (message, durable) = said.split_once(' ').expect("a Message and a count");
    let message = MessageId::new(message.parse().expect("a Message"));
    let durable: usize = durable.parse().expect("a count");
    let held: usize = child.heard("held ", STARTED).parse().expect("a count");
    assert!(
        held > durable,
        "the second Publication was written and answered before its sync: {held} after {durable}"
    );
    child.killed();

    let runtime = RocksDb::open(&place.join("runtime")).expect("opened again");
    assert_eq!(
        entries(&runtime),
        durable,
        "exactly what was durable: nothing of what was answered and never synced"
    );
    drop(runtime);
    let node = test_node(&place);
    assert!(
        node.read_message(message).expect("read").is_some(),
        "the Message durable before is there"
    );
    drop(node);
    let _ = std::fs::remove_dir_all(&place);
}
