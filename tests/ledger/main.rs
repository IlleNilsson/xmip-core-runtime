//! The receive path through the Ledger, killed hard (`runtime-model.md`
//! section 3, *What proves it*: *a kill at each step: nothing lost*):
//!
//! - a receive killed after its Stream's chunks are written and before its
//!   Publication leaves the chunks and no Message;
//! - a Message whose receive cycle completed — what the sender is
//!   acknowledged for — is in the Ledger after the process is killed, its
//!   Journeys with it, and reads back as it was received.
//!
//! The test Storage node is the owner's (2026-10-01: *for testing purposes
//! the Xmip Nodes of Storage type can use SQLite in memory for
//! administration and `RocksDB` for runtime*), sealed under the platform's
//! key store so the test reopens what a killed child wrote. A child is this
//! test program started again with [`CHILD`] naming what it does, as the
//! estate root's `storage` test does it; the kill is the operating system's.
//!
//! What each file holds: this one the harness — the test Storage node, a
//! child started and killed, what it says — and the child itself;
//! `receive_cycle.rs` the receive a child runs; `halts_at_publication.rs`
//! the Xmip Storage that stops a receive at its Publication; `killed.rs`
//! the two kill tests, and what they read back; `bounded.rs` a Stream far
//! larger than a chunk carried in bounded memory; `held.rs` what a paused
//! Subscription holds, over Xmip Storage that fails on demand;
//! `dead_message_queue.rs` a Message nothing matched, kept with why and
//! replayed; `panicked.rs` a carrying thread that panics, settled as failed;
//! `send.rs` the send step reading its Journeys from the Ledger — Failed
//! and Completed written, a retry's backoff holding no thread and its count
//! surviving a restart, a Sequential Send Port's order; `send_group.rs` a
//! Send Port Group's one Journey per Port, and the deduplication key every
//! send carries; `journey_act.rs` an operator's Retry and Dismiss of a
//! Journey that failed; `send_killed.rs` the send step killed before it sent
//! and mid-send, and what another node, or the node restarted, sends;
//! `send_raced.rs` another writer landing between a read and a claim;
//! `send_bounded.rs` a panicking send, a scan and a Publication bounded by
//! the pool, Journeys another node holds keeping no place, renewal while a
//! scan is held up, and failure evidence after a restart;
//! `sending.rs` the test node that sends they run, and its far end;
//! `untold.rs` a far end that could not be told, audited once per reason.

mod bounded;
mod dead_message_queue;
mod halts_at_publication;
mod held;
mod journey_act;
mod killed;
mod panicked;
mod receive_cycle;
mod send;
mod send_bounded;
mod send_group;
mod send_killed;
mod send_raced;
mod sending;
mod untold;

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use persist::storage::{Embedded, XmipStorage};
use rocksdb::RocksDb;
use secret::{Held, KekName, KeyStore};
use sqlite::Sqlite;

use halts_at_publication::halting;
use receive_cycle::receive_until_killed;

/// The environment variable naming what a child does.
const CHILD: &str = "XMIP_LEDGER_CHILD";
/// The environment variable naming the directory a child keeps its Ledger in.
const PLACE: &str = "XMIP_LEDGER_PLACE";
/// How long a child is given to show it is working.
const STARTED: Duration = Duration::from_secs(60);

/// A directory of a test's own, empty.
fn directory(test: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("xmip-ledger-{test}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("directory");
    path
}

/// The platform's key store over `keys` (ADR-0063 clause 4).
fn keys(keys: &Path) -> Box<dyn KeyStore> {
    #[cfg(windows)]
    let store = Held::new(secret_dpapi::Dpapi::new(keys));
    #[cfg(unix)]
    let store = Held::new(secret_file::KeyFile::new(keys));
    Box::new(store)
}

/// The test Storage node in `place`.
fn test_node(place: &Path) -> Arc<dyn XmipStorage> {
    std::fs::create_dir_all(place.join("key")).expect("its directory");
    let runtime = RocksDb::open(&place.join("runtime")).expect("the runtime database");
    let administration = Sqlite::in_memory().expect("the administration database");
    let kek = KekName::new("storage").expect("a name");
    Arc::new(
        Embedded::open(
            runtime,
            administration,
            keys(&place.join("key")).as_ref(),
            &kek,
        )
        .expect("the test Storage node"),
    )
}

/// A line said and on its way at once.
fn say(line: &str) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

/// The child: does what [`CHILD`] names, and nothing where nothing is named.
#[test]
fn child() {
    let (Ok(what), Ok(place)) = (std::env::var(CHILD), std::env::var(PLACE)) else {
        return;
    };
    let place = PathBuf::from(place);
    match what.as_str() {
        "receive" => receive_until_killed(&test_node(&place)),
        "halt" => receive_until_killed(&halting(test_node(&place))),
        "publish" => send_killed::publish_until_killed(&test_node(&place)),
        "sending" => send_killed::send_until_killed(&test_node(&place)),
        other => panic!("no child does '{other}'"),
    }
}

/// This test program started again as a child doing `what` in `place`, and
/// what it says, line by line.
fn spawn(what: &str, place: &Path) -> (Child, Receiver<String>) {
    let mut child = Command::new(std::env::current_exe().expect("this program"))
        .args(["child", "--exact", "--nocapture", "--test-threads=1"])
        .env(CHILD, what)
        .env(PLACE, place)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("a child");
    let output = child.stdout.take().expect("its output");
    let (tell, told) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(output).lines().map_while(Result::ok) {
            if tell.send(line).is_err() {
                return;
            }
        }
    });
    (child, told)
}

/// What follows `opening` in the next line a child says with it.
fn heard(lines: &Receiver<String>, opening: &str, within: Duration) -> String {
    let deadline = std::time::Instant::now() + within;
    loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        let line = lines
            .recv_timeout(left)
            .unwrap_or_else(|_| panic!("the child never said '{opening}'"));
        // The harness says `test child ... ` before the child's first line.
        if let Some(at) = line.find(opening) {
            return line[at + opening.len()..].trim().to_string();
        }
    }
}

/// The child killed, and every line it said before it died.
fn killed(mut child: Child, lines: &Receiver<String>) -> Vec<String> {
    child.kill().expect("killed");
    let _ = child.wait();
    let mut said = Vec::new();
    while let Ok(line) = lines.recv_timeout(Duration::from_secs(1)) {
        said.push(line);
    }
    said
}
