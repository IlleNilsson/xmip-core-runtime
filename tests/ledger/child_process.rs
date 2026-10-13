//! A child: this test program started again with [`CHILD`] naming what it
//! does, and ended on every path its test takes. A test that passes kills
//! it; a test that fails or panics drops it, and the drop kills it and waits
//! for it; a test program that ends without either — killed itself, its
//! landing stopped — closes the child's input, and a child ends when its
//! input closes. Nothing a test starts outlives the test.

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use super::{CHILD, PLACE, STARTED, directory};

/// The children started and not yet waited for, by process identifier.
static LIVE: Mutex<BTreeSet<u32>> = Mutex::new(BTreeSet::new());

/// How long a child whose input closed is given to end.
const ENDING: Duration = Duration::from_secs(5);

/// A child doing what it was started for, and what it says, line by line.
pub struct ChildProcess {
    process: Child,
    /// Held open while the test lives; closed, the child ends.
    input: Option<ChildStdin>,
    lines: Receiver<String>,
    ended: Option<ExitStatus>,
}

impl ChildProcess {
    /// This test program started again as a child doing `what` in `place`.
    pub fn start(what: &str, place: &Path) -> Self {
        let mut process = Command::new(std::env::current_exe().expect("this program"))
            .args(["child", "--exact", "--nocapture", "--test-threads=1"])
            .env(CHILD, what)
            .env(PLACE, place)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("a child");
        live().insert(process.id());
        let input = process.stdin.take();
        let output = process.stdout.take().expect("its output");
        let (tell, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(output).lines().map_while(Result::ok) {
                if tell.send(line).is_err() {
                    return;
                }
            }
        });
        Self {
            process,
            input,
            lines,
            ended: None,
        }
    }

    /// Whether the child `id` was started and not yet waited for.
    pub fn is_live(id: u32) -> bool {
        live().contains(&id)
    }

    /// The child's process identifier.
    pub fn id(&self) -> u32 {
        self.process.id()
    }

    /// What follows `opening` in the next line the child says with it.
    pub fn heard(&self, opening: &str, within: Duration) -> String {
        let deadline = Instant::now() + within;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let line = self
                .lines
                .recv_timeout(left)
                .unwrap_or_else(|_| panic!("the child never said '{opening}'"));
            // The harness says `test child ... ` before the child's first line.
            if let Some(at) = line.find(opening) {
                return line[at + opening.len()..].trim().to_string();
            }
        }
    }

    /// The child killed, and every line it said before it died.
    pub fn killed(mut self) -> Vec<String> {
        self.end();
        // Its output closed with it, so this ends once what it said is read.
        self.lines.iter().collect()
    }

    /// The child's input closed, as the test program's end closes it, and
    /// how the child ended; none if it did not end within [`ENDING`].
    pub fn closed(&mut self) -> Option<ExitStatus> {
        drop(self.input.take());
        let deadline = Instant::now() + ENDING;
        while Instant::now() < deadline {
            if let Some(status) = self.process.try_wait().expect("its state") {
                self.waited(status);
                return Some(status);
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        None
    }

    /// The child killed, unless it has ended, and waited for.
    fn end(&mut self) {
        if self.ended.is_some() {
            return;
        }
        // An error here is a child already ended; the wait says which.
        let _ = self.process.kill();
        match self.process.wait() {
            Ok(status) => self.waited(status),
            Err(error) if !std::thread::panicking() => {
                panic!("the child {} was not waited for: {error}", self.id())
            }
            Err(_) => {}
        }
    }

    fn waited(&mut self, status: ExitStatus) {
        self.ended = Some(status);
        live().remove(&self.process.id());
    }
}

impl Drop for ChildProcess {
    fn drop(&mut self) {
        self.end();
    }
}

fn live() -> std::sync::MutexGuard<'static, BTreeSet<u32>> {
    LIVE.lock().unwrap_or_else(PoisonError::into_inner)
}

/// In a child: the process ended when the test that started it closes its
/// input — on purpose, or because the test program ended however it did.
pub fn ending_with_its_test() {
    std::thread::spawn(|| {
        let _ = std::io::stdin().lines().count();
        std::process::exit(0);
    });
}

#[test]
fn a_child_is_ended_when_its_test_panics_and_when_its_test_program_ends() {
    let place = directory("ended-on-panic");
    let mut started = None;
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let child = ChildProcess::start("receive", &place);
        started = Some(child.id());
        child.heard("received ", STARTED);
        panic!("a test failing while its child runs");
    }));
    assert!(caught.is_err(), "the test panicked");
    let id = started.expect("the child started");
    assert!(
        !ChildProcess::is_live(id),
        "the child {id} was killed and waited for as the panic left its test"
    );
    let _ = std::fs::remove_dir_all(&place);

    let place = directory("ended-on-close");
    let mut child = ChildProcess::start("receive", &place);
    child.heard("received ", STARTED);
    let ended = child.closed();
    assert!(
        ended.is_some(),
        "the child ended within {ENDING:?} of its input closing"
    );
    assert!(!ChildProcess::is_live(child.id()));
    drop(child);
    let _ = std::fs::remove_dir_all(&place);
}
