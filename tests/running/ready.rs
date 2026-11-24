//! A node is ready only by what its latest start published (open problem
//! 137; ADR-0056, amendment 2026-11-24): a publication the node wrote
//! before its start now — a process killed, crashed or stopped past its
//! service manager's bound leaves its last one saying its Storage stands
//! Fine — never says it is ready, and the first one the node writes since
//! does. Until 2026-11-24 readiness read the last publication as it lay,
//! and the deploy went on to the next Storage node while this one was not
//! following.

use configure::start::{Start, start_at};
use file::temporary::Folder;
use net::fixture::unheld;
use observe::topology::window::Window;
use xmip_core_runtime::fixture::started;
use xmip_core_runtime::running::Running;
use xmip_core_runtime::running::activation::readiness;
use xmip_core_runtime::running::publication::SNAPSHOT;

use crate::node::{linked, node, path_text, written};

/// `running`'s publication written where it publishes, as its program
/// writes it.
fn published(running: &Running) {
    let publication = running.publication("xmip-service", &mut Window::new());
    publication
        .write(&running.data().join(SNAPSHOT))
        .expect("published");
}

#[test]
fn a_publication_of_an_earlier_start_never_says_the_node_is_ready() {
    let folder = Folder::new("runtime-running-ready");
    let path = written(&folder, &node(&unheld().to_string(), &unheld().to_string()));
    let configuration = path_text(&path);
    let running = started(configuration, || linked(&path)).expect("the node starts");
    published(&running);
    let ready = readiness(configuration);
    assert!(ready.is_ok(), "{ready:?}");

    // Killed, never stopped in order: its last publication still says its
    // Storage stands Fine. Its next process numbers its start as its first
    // act, before it publishes anything.
    let next = u64::try_from(observe::now_unix_nanos()).expect("after 1970");
    let start = Start { start: next };
    std::fs::write(start_at(&path), start.written()).expect("a later start");
    let stale = readiness(configuration);
    let said = stale.expect_err("ready by a publication of an earlier start");
    assert!(said.contains("before its start"), "{said}");

    // Its first publication since says it.
    published(&running);
    let ready = readiness(configuration);
    assert!(ready.is_ok(), "{ready:?}");
    running.stop();
}
