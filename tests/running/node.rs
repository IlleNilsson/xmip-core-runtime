//! A node as its tests start it (`xmip_core_runtime::running`): the test
//! cluster's first node taking both ends of the Loopback Application, the
//! transports and test Storage node its program links, and the senders
//! and far ends a test carries Messages between. What the running tests
//! and the module's timing program (`tests/measured`) both stand up.

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use http::HttpTransport;
use tcp::TcpTransport;
use transport::{Configured, Transport};
use xcore::settings::{Applies, Given};
use xmip_core_runtime::fixture::{Always, Open};
use xmip_core_runtime::linked::{Linked, LinkedTransport, OnNode, Opened};

thread_local! {
    /// The node each transport this test's thread built was given, one
    /// entry a transport: startup runs on the thread that calls it, so each
    /// test counts its own.
    static GIVEN: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

/// The node each transport this test's thread built was given, since
/// [`count_anew`]: one entry a transport built.
pub fn given() -> Vec<String> {
    GIVEN.with(|nodes| nodes.borrow().clone())
}

/// What this test's thread built forgotten.
pub fn count_anew() {
    GIVEN.with(|nodes| nodes.borrow_mut().clear());
}

fn counted<T: Configured + Send + Sync + 'static>(
    address: &str,
    side: Applies,
    given: &[(String, Given)],
    on: OnNode<'_>,
) -> Opened {
    GIVEN.with(|nodes| nodes.borrow_mut().push(on.0.to_string()));
    xmip_core_runtime::linked::open::<T>(address, side, given, on)
}

/// What the tests' program links, and the test Storage node it opened
/// beside the configuration at `file`: `RocksDB` on disk for the runtime
/// database, `SQLite` in memory for the administration and the audit
/// databases.
pub fn linked(file: &Path) -> Linked {
    static PLACES: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let place = file.parent().expect("its directory").join(format!(
        "ledger-{}",
        PLACES.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    Linked {
        transports: vec![
            LinkedTransport::opened_by::<TcpTransport>(counted::<TcpTransport>),
            LinkedTransport::opened_by::<HttpTransport>(counted::<HttpTransport>),
        ],
        authenticators: vec![Box::new(Always::circumstance())],
        policies: vec![Box::new(Open)],
        storage: Some(Arc::new(test_storage(&place))),
        ..Linked::default()
    }
}

/// The Loopback Application, as its section of the node's configuration.
const APPLICATION: &str = r#"
[[xmip_applications]]
name = "Loopback"

[[xmip_applications.receive_ports]]
name = "Loopback"

[[xmip_applications.receive_locations]]
name = "In"
receive_port = "Loopback"
depth = "light"

[[xmip_applications.send_ports]]
name = "Out"

[[xmip_applications.subscriptions]]
id = "onward"
destination = { send-port = "Out" }
filter = "xmip.transport.mechanism = 'circumstance'"
"#;

/// The test cluster's first node, and its scope.
pub fn first() -> (String, String) {
    let cluster = configure::fixture::test_cluster();
    let node = cluster.node(0).name.clone();
    let scope = format!("xmip:///{}/node/{node}", cluster.name);
    (node, scope)
}

/// The test cluster's first node takes both ends of the Application: a
/// tcp Receive Location on `receive`, and a tcp Send Port to `far`.
pub fn node(receive: &str, far: &str) -> String {
    let cluster = configure::fixture::test_cluster();
    let (node, _) = first();
    format!(
        r#"[service]
name = "xmip"
cluster_name = "{cluster}"
node_name = "{node}"

[[applications]]
name = "Loopback"

[[applications.receive_locations]]
name = "In"
node = "{node}"
start = true
address = "tcp://{receive}"
[applications.receive_locations.settings]
timeout = "100ms"
[applications.receive_locations.accept]
mechanism = ["circumstance"]
transport = "claimed"

[[applications.send_ports]]
name = "Out"
node = "{node}"
start = true
address = "tcp://{far}"
{APPLICATION}"#,
        cluster = cluster.name
    )
}

/// [`node`], its Send Port `Out` stating `policy` — its `retry`, its
/// `correlation` and the rest, one key a line.
pub fn node_sending(receive: &str, far: &str, policy: &str) -> String {
    node(receive, far).replace(
        "[[xmip_applications.send_ports]]\nname = \"Out\"\n",
        &format!("[[xmip_applications.send_ports]]\nname = \"Out\"\n{policy}\n"),
    )
}

/// A test Storage node at `place`, its key-encryption key in memory and
/// so as new as the node: a database already at `place` was sealed under
/// a key that ended with whatever opened it.
pub fn test_storage(place: &Path) -> persist::storage::Embedded<rocksdb::RocksDb, sqlite::Sqlite> {
    let keys = secret::Held::new(secret::fixture::Memory::default());
    persist::storage::Embedded::open(
        rocksdb::RocksDb::open(place).expect("the runtime database"),
        sqlite::Sqlite::in_memory().expect("the administration database"),
        sqlite::Sqlite::in_memory().expect("the audit database"),
        &keys,
        &secret::KekName::new(xmip_core_runtime::storage::KEK).expect("a name"),
    )
    .expect("the test Storage node")
}

/// A directory of its own holding `configuration` and nothing else, and
/// the configuration's path. Emptied first: it is named for the process,
/// and an earlier process of the same id may have left it.
pub fn written(test: &str, configuration: &str) -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("xmip-running-{test}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).expect("a directory");
    let path = directory.join("node.xmip");
    xmip_core_runtime::fixture::write_signed(&path, configuration);
    path
}

pub fn path_text(path: &Path) -> &str {
    path.to_str().expect("a UTF-8 path")
}

/// Send `payload` to the node at `target` by `sender`, asking again while
/// its Receive Location has not yet bound — it binds on its first receive,
/// and nothing else says when that was. Bounded, and never a sleep.
pub fn deliver(sender: &dyn Transport, target: &str, payload: &[u8]) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match sender.send(target, payload) {
            Ok(()) => return,
            Err(refused) if refused.retryable && Instant::now() < deadline => {
                std::thread::yield_now();
            }
            Err(failed) => panic!("the node took nothing at {target}: {failed:?}"),
        }
    }
}
