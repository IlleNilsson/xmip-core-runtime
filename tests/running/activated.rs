//! A node trusts a slice before it runs it, and keeps the last one that ran
//! (ADR-0031, amendment 2026-11-12): a correctly signed candidate the node
//! cannot start leaves its active configuration running and pinned as
//! seen; a candidate refused at accept-work lets go of what it opened, so
//! the active configuration starts over the same embedded Storage node; and
//! starting alone writes nothing, only activation replaces the active
//! configuration.

use std::path::Path;

use configure::signed::{Pin, active_at, pin_at};
use net::fixture::unheld;
use observe::Health;
use persist::{Engine, PersistError};
use secret::{Held, KeyStore};
use tcp::TcpTransport;
use xmip_core_runtime::fixture::{started, unsigned, write_signed};
use xmip_core_runtime::linked::{Linked, LinkedEngine, LinkedKeyStore};
use xmip_core_runtime::running::activation::{self, Attempt, Standing, Tried};
use xmip_core_runtime::running::{Refusal, Running};
use xmip_core_runtime::service::StartupPhase;
use xmip_core_runtime::signed;

use crate::node::{deliver, first, linked, node, path_text, written};

/// The record `running` publishes at `<node>/configuration`.
fn standing(running: &Running) -> (Health, String) {
    let scope = format!("{}/{}", first().1, activation::CONFIGURATION);
    let snapshot = running.snapshot();
    let found = snapshot
        .health(&scope)
        .into_iter()
        .find(|r| r.scope == scope);
    let record = found.expect("its configuration standing is published");
    (record.health, record.evidence)
}

/// What is kept at `at`.
fn kept(at: &Path) -> String {
    std::fs::read_to_string(at).expect("kept")
}

/// The serial of the slice at `path`.
fn serial(path: &Path) -> u64 {
    let file = kept(path);
    configure::signed::split(&file)
        .expect("reads")
        .1
        .expect("signed")
        .serial
}

#[test]
fn a_correctly_signed_candidate_the_node_cannot_start_leaves_its_active_configuration_running() {
    let far = TcpTransport::loopback();
    let (listener, far_address) = far.bind().expect("the far end binds");
    let receive = unheld().to_string();
    let path = written("candidate", &node(&receive, &far_address));
    started(path_text(&path), || linked(&path))
        .expect("the node starts")
        .stop();
    let active = kept(&active_at(&path));
    assert_eq!(active, kept(&path), "the slice that ran is the active one");

    // Correctly signed, and naming a scheme no transport this program
    // links declares: refused at phase 3, after trust admitted it.
    let unusable = unsigned(&path).replacen("address = \"tcp://", "address = \"sftp://", 1);
    write_signed(&path, &unusable);
    let running = started(path_text(&path), || linked(&path)).expect("the active one runs");
    deliver(
        &TcpTransport::loopback(),
        &receive,
        b"by the active configuration",
    );
    far.accept_one(&listener)
        .expect("it reaches the far end")
        .taken()
        .expect("read whole");

    let (health, evidence) = standing(&running);
    assert_eq!(health, Health::Stressed, "{evidence}");
    for words in [
        "candidate refused: node.xmip, serial",
        "refused at validate-startup",
        "sftp://",
        "the node runs its active configuration, serial",
        "tries the candidate again",
    ] {
        assert!(evidence.contains(words), "{words}: {evidence}");
    }
    running.stop();
    assert_eq!(
        kept(&active_at(&path)),
        active,
        "the active one is not replaced"
    );
    let pin = Pin::read(&kept(&pin_at(&path))).expect("pinned");
    assert_eq!(pin.serial, serial(&path), "the candidate is pinned as seen");
    let _ = std::fs::remove_dir_all(path.parent().and_then(Path::parent).expect("its own"));
}

#[test]
fn starting_alone_writes_nothing_and_only_activation_replaces_the_active_configuration() {
    let path = written(
        "activate",
        &node(&unheld().to_string(), &unheld().to_string()),
    );
    let file = kept(&path);
    let admitted = signed::admitted(&path, &file).expect("trusted");
    let slice = admitted.candidate.expect("admitted").expect("a candidate");
    let attempt = Attempt {
        slice,
        tried: Tried::Candidate { replacing: None },
    };
    let mut running = Running::start(path_text(&path), attempt, linked(&path)).expect("starts");
    assert!(!active_at(&path).exists(), "started, not activated");
    assert_eq!(running.standing(), None);

    running.activate();
    assert_eq!(kept(&active_at(&path)), file);
    assert!(
        matches!(
            running.standing(),
            Some(Standing::Activated {
                replacing: None,
                ..
            })
        ),
        "{:?}",
        running.standing()
    );
    assert_eq!(standing(&running).0, Health::Fine);
    running.stop();
    let _ = std::fs::remove_dir_all(path.parent().and_then(Path::parent).expect("its own"));
}

#[test]
fn a_candidate_refused_at_accept_work_lets_go_so_the_active_one_starts_over_its_storage_node() {
    let stored = format!(
        "roles = \"executing, storage\"\n{}",
        node(&unheld().to_string(), &unheld().to_string())
    );
    let path = written("let-go", &stored);
    started(path_text(&path), || embedded(&path))
        .expect("the node starts")
        .stop();
    let active = kept(&active_at(&path));
    let changed = unsigned(&path).replace("timeout = \"100ms\"", "timeout = \"200ms\"");
    write_signed(&path, &changed);

    // The program's own step refuses the candidate's attempt after it
    // reached its own Storage node, and takes the next.
    let mut tried = 0;
    let (running, ()) = activation::started(
        path_text(&path),
        || embedded(&path),
        |_| {
            tried += 1;
            if tried == 1 {
                let said = "the program's own listener did not bind".to_string();
                return Err(Refusal::at(StartupPhase::AcceptWork, vec![said]));
            }
            Ok(())
        },
    )
    .expect("the active configuration starts over the same Storage node");

    assert_eq!(tried, 2, "the candidate, then the active configuration");
    let said = running.storage().said();
    assert!(said.starts_with("its own Storage node"), "{said}");
    let (health, evidence) = standing(&running);
    assert_eq!(health, Health::Stressed, "{evidence}");
    assert!(
        evidence.contains("refused at accept-work: the program's own listener did not bind"),
        "{evidence}"
    );
    running.stop();
    assert_eq!(kept(&active_at(&path)), active);
    let _ = std::fs::remove_dir_all(path.parent().and_then(Path::parent).expect("its own"));
}

/// What the tests' program links, keeping Xmip Storage itself as a node
/// with the storage role does: `RocksDB` and `SQLite` on disk under the
/// node's data directory, sealed under the platform's key store, so a
/// second attempt in the process opens what the first let go of.
fn embedded(path: &Path) -> Linked {
    Linked {
        storage: None,
        engine: Some(LinkedEngine::new(configure::store::ENGINE, runtime)),
        administration: Some(LinkedEngine::new(
            xmip_core_runtime::storage::ADMINISTRATION,
            administration,
        )),
        key_stores: vec![LinkedKeyStore::new(
            configure::store::PLATFORM_KEY_STORE,
            platform,
        )],
        ..linked(path)
    }
}

fn runtime(place: &Path) -> Result<Box<dyn Engine>, PersistError> {
    Ok(Box::new(rocksdb::RocksDb::open(place)?))
}

fn administration(place: &Path) -> Result<Box<dyn Engine>, PersistError> {
    Ok(Box::new(sqlite::Sqlite::open(place)?))
}

/// The platform's key store over `keys` (ADR-0063 clause 4).
fn platform(keys: &Path) -> Box<dyn KeyStore> {
    cfg_select! {
        windows => Box::new(Held::new(secret_dpapi::Dpapi::new(keys))),
        unix => Box::new(Held::new(secret_file::KeyFile::new(keys))),
    }
}
