//! A start's number: above the last kept whatever the clock says, above
//! every start before it after its node's store is lost or restored, and
//! floored where Xmip Storage refused a start below a later one.

use std::path::PathBuf;

use file::temporary::Folder;
use xcore::clock::Stepped;

use super::*;

/// The configuration of a node in `folder`: its place finds its start file.
fn configured(folder: &Folder) -> PathBuf {
    folder.join("config").join("node.xmip")
}

/// Each start numbered above the one before it, whatever the clock says:
/// a clock set back across a crash numbers the next start one above the
/// last kept, never below it.
#[test]
fn a_start_is_numbered_above_the_last_kept_whatever_the_clock_says() {
    let folder = Folder::new("runtime-start-numbered");
    let configuration = configured(&folder);
    let clock = Stepped::at(1_000);
    assert_eq!(numbered(&configuration, &clock), Ok(1_000), "the clock");
    clock.set_wall(10);
    assert_eq!(
        numbered(&configuration, &clock),
        Ok(1_001),
        "above the last kept, the clock set back"
    );
    clock.set_wall(5_000);
    assert_eq!(numbered(&configuration, &clock), Ok(5_000));
    let kept = std::fs::read_to_string(start_at(&configuration)).expect("kept");
    assert_eq!(Start::read(&kept), Ok(Start { start: 5_000 }));
}

/// A store restored from a backup keeps an older number, and one lost
/// none: the clock puts the next start above every start before it. Where
/// the clock is behind too, the start is numbered below a later start
/// Xmip Storage holds and refused there; floored at that start's number,
/// the node's next start is above it.
#[test]
fn a_start_after_its_store_is_restored_or_lost_is_numbered_above_every_start_before() {
    let folder = Folder::new("runtime-start-restored");
    let configuration = configured(&folder);
    let at = start_at(&configuration);
    let clock = Stepped::at(1_000);
    assert_eq!(numbered(&configuration, &clock), Ok(1_000));
    let backup = std::fs::read(&at).expect("backed up");
    clock.set_wall(2_000);
    assert_eq!(numbered(&configuration, &clock), Ok(2_000));

    std::fs::write(&at, &backup).expect("restored");
    clock.set_wall(3_000);
    assert_eq!(numbered(&configuration, &clock), Ok(3_000), "restored");
    std::fs::remove_file(&at).expect("lost");
    clock.set_wall(4_000);
    assert_eq!(numbered(&configuration, &clock), Ok(4_000), "lost");

    std::fs::remove_file(&at).expect("lost again");
    clock.set_wall(100);
    let behind = numbered(&configuration, &clock).expect("numbered");
    assert!(behind < 4_000, "the clock behind, the store lost: {behind}");
    floored(&configuration, 4_000).expect("floored at the later start");
    floored(&configuration, 50).expect("a lower floor keeps the higher");
    assert_eq!(
        numbered(&configuration, &clock),
        Ok(4_001),
        "the node's next start above the later start"
    );
}
