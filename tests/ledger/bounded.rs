//! A Stream far larger than a chunk carried through the receive path in
//! bounded memory (`runtime-model.md` section 3, *What proves it*: *a
//! Stream far larger than the memory allowed passes, with memory bounded*):
//! its body is a reader that makes its bytes as they are read, the Ledger
//! keeps it in chunks, and nothing on the way — the gates, Message
//! creation, promotion, Publication — holds it whole. What this process
//! allocates is counted while it is carried.
//!
//! The count is the whole process's: one allocator, every thread. A test
//! that holds a figure of it to a bound runs [`alone`], in a process of its
//! own with no other test beside it, so what tests running in parallel
//! allocate never reaches its figure.

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::Read;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use receive::ReceivedStream;
use xmip_core_runtime::ledger::CHUNK;
use xmip_core_runtime::message_path::ReceiveCycle;
use xmip_core_runtime::outcome::Arrived;

use super::receive_cycle::receiving;
use super::{directory, test_node};

/// The system's allocator, counting what is held and the most held since
/// the count was last reset.
struct Counted;

static HELD: AtomicUsize = AtomicUsize::new(0);
static MOST: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every call is the system allocator's own, with the same layout;
// the counts only watch.
#[allow(unsafe_code)]
unsafe impl GlobalAlloc for Counted {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let held = HELD.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
        MOST.fetch_max(held, Ordering::Relaxed);
        // SAFETY: as the caller promised the layout.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, at: *mut u8, layout: Layout) {
        HELD.fetch_sub(layout.size(), Ordering::Relaxed);
        // SAFETY: `at` came from `alloc` with `layout`.
        unsafe { System.dealloc(at, layout) }
    }
}

#[global_allocator]
static COUNTED: Counted = Counted;

/// The Stream's length: 64 MiB, four thousand chunks of the smallest size.
const LENGTH: u64 = 64 * 1024 * 1024;

/// A body that makes its bytes as they are read, `length` of them: byte
/// `n` is `n % 251`. What the tests of what is held carry and send.
pub(super) struct Made {
    at: u64,
    length: u64,
}

impl Made {
    /// `length` bytes, made as they are read.
    pub(super) const fn of(length: u64) -> Self {
        Self { at: 0, length }
    }
}

impl Read for Made {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let left = self.length - self.at;
        let taken = out.len().min(usize::try_from(left).unwrap_or(usize::MAX));
        for byte in &mut out[..taken] {
            *byte = u8::try_from(self.at % 251).unwrap_or_default();
            self.at += 1;
        }
        Ok(taken)
    }
}

/// The environment variable naming the one test a process of its own runs
/// [`alone`].
const ALONE: &str = "XMIP_LEDGER_ALONE";

/// Run `run`, the body of the test `test` (its path in this program, as
/// `--exact` takes it), alone: in this process where this process was
/// started for it, and otherwise in this test program started again for
/// that one test, on one test thread, its outcome this test's.
pub(super) fn alone(test: &str, run: impl FnOnce()) {
    if std::env::var(ALONE).is_ok_and(|named| named == test) {
        run();
        return;
    }
    let output = Command::new(std::env::current_exe().expect("this program"))
        .args([test, "--exact", "--nocapture", "--test-threads=1"])
        .env(ALONE, test)
        .output()
        .expect("this program, started again");
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    eprintln!("{said}");
    assert!(output.status.success(), "{test}, alone, failed");
    assert!(said.contains("1 passed"), "{test}, alone, ran no test");
}

/// What `run` returns, and the most this process held at once while it
/// ran, beyond what it held as it began: the allocator's count, measured.
/// A figure held to a bound is measured [`alone`].
pub(super) fn measured<T>(run: impl FnOnce() -> T) -> (T, usize) {
    let before = HELD.load(Ordering::Relaxed);
    MOST.store(before, Ordering::Relaxed);
    let returned = run();
    (
        returned,
        MOST.load(Ordering::Relaxed).saturating_sub(before),
    )
}

#[test]
fn a_stream_far_larger_than_a_chunk_is_carried_in_bounded_memory() {
    alone(
        "bounded::a_stream_far_larger_than_a_chunk_is_carried_in_bounded_memory",
        carried_in_bounded_memory,
    );
}

fn carried_in_bounded_memory() {
    let place = directory("bounded");
    let node = test_node(&place);
    let (carried, most) = receiving(&node, CHUNK, |carry| {
        measured(|| carry(ReceivedStream::new(Made::of(LENGTH), "tcp://127.0.0.1:1")))
    });
    assert_eq!(
        carried.cycle(),
        ReceiveCycle::Completed,
        "{:?}",
        carried.arrived
    );
    // Four MiB is some sixty-five chunks: what the whole path held at its
    // most, against a Stream of sixty-four.
    eprintln!("BOUNDED a Stream of {LENGTH} bytes held {most} bytes at most");
    assert!(most < 4 * 1024 * 1024, "{most} bytes held at once");

    let Arrived::Routed { work, .. } = &carried.arrived else {
        panic!("routed: {:?}", carried.arrived);
    };
    let stream = &work.message.sections()[0].stream;
    assert_eq!(stream.length(), LENGTH);
    let mut read = stream.reader().expect("read back a chunk at a time");
    let mut piece = vec![0u8; 1 << 20];
    let mut at = 0u64;
    loop {
        let taken = read.read(&mut piece).expect("read");
        if taken == 0 {
            break;
        }
        for byte in &piece[..taken] {
            assert_eq!(u64::from(*byte), at % 251, "byte {at}");
            at += 1;
        }
    }
    assert_eq!(at, LENGTH, "every byte, as it arrived");
    drop(read);
    drop(carried);
    drop(node);
    let _ = std::fs::remove_dir_all(&place);
}
