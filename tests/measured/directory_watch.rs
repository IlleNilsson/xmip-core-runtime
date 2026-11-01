//! A drop directory's watch (`xmip_core_runtime::directory_watch`),
//! measured: dropped, it ends its thread at once.

use std::sync::mpsc;
use std::time::{Duration, Instant};

use xcore::fastest::FIVE;
use xcore::latency::{PlainWake, spread};
use xmip_core_runtime::directory_watch::DirectoryWatch;

#[test]
fn a_dropped_watch_ends_its_thread_at_once() {
    // Held as the fastest of five beside the machine's own wake, round by
    // round (`xcore::latency`): a drop wakes the watching thread and then
    // this one as it joins, two wakes, under about a millisecond. Each
    // watch is dropped once its thread is watching, as a watch is when a
    // Location stops: told of a change first, so what is measured is the
    // drop, never the thread's start on a machine with no processor free
    // for it.
    let directory = std::env::temp_dir().join(format!(
        "xmip-directory-watch-dropped-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).expect("a directory");
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
    assert!(
        ended.fastest_of_five < Duration::from_millis(1) + usual * 2,
        "the fastest of five {:?}, the machine's own wake {usual:?}",
        ended.fastest_of_five
    );
    let _ = std::fs::remove_dir_all(&directory);
}
