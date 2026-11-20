//! A drop directory's watch (`xmip_core_runtime::directory_watch`),
//! measured: dropped, it ends its thread at once.

use std::sync::mpsc;
use std::time::{Duration, Instant};

use xcore::fastest::FIVE;
use xcore::latency::{PlainWake, spread, woke_beside_a_plain_wake};
use xmip_core_runtime::directory_watch::DirectoryWatch;

/// What a drop wakes where a plain wake wakes one: the watching thread,
/// and this one as it joins.
const WAKES: u32 = 2;

#[test]
fn a_dropped_watch_ends_its_thread_at_once() {
    // Held by the wall-clock half of the rule beside the machine's own
    // wake, round by round (`xcore::latency::woke_beside_a_plain_wake`):
    // the fastest of five under the millisecond plus a plain wake for each
    // of the two threads a drop wakes; until 2026-11-15 a copy of it
    // here. Each watch is dropped once its thread is watching, as a watch
    // is when a Location stops: told of a change first, so what is
    // measured is the drop, never the thread's start on a machine with no
    // processor free for it.
    let directory = file::temporary::Folder::new("runtime-directory-watch-dropped");
    let plain = PlainWake::start();
    let (mut ended, mut woke) = (Vec::new(), Vec::new());
    for round in 0..4 * FIVE {
        let (told, tells) = mpsc::channel();
        let watch = DirectoryWatch::spawn(&directory, move || {
            let _ = told.send(());
        })
        .expect("watched");
        std::fs::write(directory.join(format!("round-{round}")), "").expect("written");
        tells
            .recv_timeout(Duration::from_secs(5))
            .expect("its thread watches");
        let asked = Instant::now();
        drop(watch);
        ended.push(asked.elapsed());
        woke.push(plain.round().0);
    }
    let ended = spread("a watch dropped to its thread joined", ended);
    let usual = spread("a plain channel beside it", woke).fastest_of_five;
    woke_beside_a_plain_wake(
        "a watch dropped to its thread joined",
        ended.fastest_of_five,
        usual,
        WAKES,
    );
}
