//! The operate plane, measured: a follower told as the publication
//! advances, over loopback TLS and on the local endpoint; a connection on
//! the local endpoint proven and answered; and a read of a node known
//! unreachable said at once.

use std::net::TcpListener;
use std::sync::Arc;
use std::time::{Duration, Instant};

use xaudit::program_audit::ProgramAudit;
use xcore::latency::{PlainWake, at_once, spread};
use xcore::processor_time::ProcessorTime;
use xmip_core_runtime::fixture::Authority;
use xmip_core_runtime::plane::{Board, Listener, Remote, Role};

use super::{certified, endpoint};

/// The bound: about a millisecond.
const BOUND: Duration = Duration::from_millis(1);

/// The wait a surface states: the node's default.
const WAIT: Duration = Duration::from_secs(2);

/// A follow's rounds and a plain wake beside each, held to the millisecond
/// rule by what is Xmip's alone, each figure the fastest round in every
/// five (`xcore::latency`): a poll or a missed notify is in every round, a
/// wake that waited its turn for a processor in some only. **The wake is a
/// wake**: from post to follower told is under the millisecond plus a
/// plain wake, three times — the notice wakes the node's follow, the
/// connection's reader and the surface where the plain wake wakes one
/// thread. **Xmip's own work is under the millisecond**: this process's
/// processor time across a round — the node's side and the surface's —
/// is under the millisecond plus the process's across the plain wake,
/// which counts what the rest of the process runs beside it. The median and
/// the tail are printed and held by nothing: on a machine busy on every
/// processor they measure the scheduler.
struct Rounds {
    took: Vec<Duration>,
    worked: Vec<Duration>,
    plain: PlainWake,
    woke: Vec<Duration>,
    idle: Vec<Duration>,
}

impl Default for Rounds {
    fn default() -> Self {
        Self {
            took: Vec::new(),
            worked: Vec::new(),
            plain: PlainWake::start(),
            woke: Vec::new(),
            idle: Vec::new(),
        }
    }
}

impl Rounds {
    /// One plain wake, after a round.
    fn beside(&mut self) {
        let (woke, idle) = self.plain.round();
        self.woke.push(woke);
        self.idle.push(idle);
    }

    fn hold(self, what: &str) {
        let took = spread(what, self.took).fastest_of_five;
        let usual = spread("a plain wake beside it", self.woke).fastest_of_five;
        let worked = spread("the process's processor time for a round", self.worked);
        let idle = spread("the process's processor time for a plain wake", self.idle);
        assert!(
            took < BOUND + usual * 3,
            "{what}: the fastest of five {took:?}, the machine's own {usual:?}"
        );
        assert!(
            worked.fastest_of_five < BOUND + idle.fastest_of_five,
            "{what}: the process's processor time {:?}, for a plain wake {:?}",
            worked.fastest_of_five,
            idle.fastest_of_five
        );
    }
}

#[test]
fn a_surface_reads_the_publication_and_is_told_as_it_advances() {
    let authority = Authority::new();
    let board = Arc::new(Board::default());
    board.post("source = \"one\"\n".to_string());
    let watching = endpoint::listing(Role::Observer, &["CN=surface"]);
    let (listener, _) = certified::node(&authority, &board, watching);
    let surface = certified::remote(&authority, &listener);

    assert_eq!(
        surface.publication().expect("it answers"),
        (1, "source = \"one\"\n".to_string())
    );

    let reached = surface.wait(0, Duration::from_secs(5));
    assert!(reached.reachable, "{}", reached.reason);
    assert_eq!(reached.revision, 1);

    // The millisecond rule: a follow notification over loopback, measured
    // from the post to the follower told, over many rounds, each beside a
    // plain wake (Rounds::hold says what is held).
    let mut seen = reached.told;
    let mut rounds = Rounds::default();
    for round in 2..=201u64 {
        let posted = Instant::now();
        let from = ProcessorTime::process();
        board.post(format!("source = \"{round}\"\n"));
        let told = surface.wait(seen, Duration::from_secs(5));
        rounds.took.push(posted.elapsed());
        rounds.worked.push(from.elapsed());
        assert_eq!(told.revision, round);
        seen = told.told;
        rounds.beside();
    }
    rounds.hold("follow notification over loopback");
}

#[test]
fn a_read_after_the_node_was_not_there_says_so_at_once_and_the_loop_finds_it() {
    let authority = Authority::new();
    let address = net::fixture::unheld();
    let surface = Remote::retrying(
        &address.to_string(),
        &authority.identity("surface"),
        vec![Duration::from_millis(50)],
    )
    .expect("a remote");

    let first = surface.publication().expect_err("nothing there");
    assert!(first.contains("unreachable"), "{first}");
    // Said at once from what the surface holds, no connection tried: the
    // fastest of five under the millisecond, and no more than that of the
    // caller's processor time in any (xcore::latency::at_once).
    let (again, fastest, spent) = at_once("a node known unreachable, asked again", || {
        surface.publication()
    });
    let again = again.expect_err("still nothing");
    assert!(fastest < BOUND, "said in {fastest:?}, the fastest of five");
    assert!(spent < BOUND, "{spent:?} of processor time");
    assert!(again.contains("unreachable"), "{again}");

    let board = Arc::new(Board::default());
    board.post("source = \"back\"\n".to_string());
    let audit = ProgramAudit::new("plane-test", Some(&authority.directory));
    let _back = Listener::start(
        TcpListener::bind(address).expect("the same port"),
        &authority.identity("node"),
        Arc::clone(&board) as Arc<dyn xmip_core_runtime::plane::Published>,
        endpoint::listing(Role::Observer, &["CN=surface"]),
        &audit,
    )
    .expect("it serves");
    let mut state = surface.state();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !state.reachable && Instant::now() < deadline {
        state = surface.wait(state.told, Duration::from_secs(1));
    }
    assert!(state.reachable, "{}", state.reason);
    assert_eq!(
        surface.publication().expect("back").1,
        "source = \"back\"\n"
    );
}

#[test]
fn a_surface_on_this_machine_reads_the_publication_and_is_told_as_it_advances() {
    let board = Arc::new(Board::default());
    board.post("source = \"one\"\n".to_string());
    let watching = endpoint::account_as(Role::Observer, &[]);
    let (_listener, _, called) = endpoint::node(&board, watching);
    let surface = endpoint::surface(&called);

    assert_eq!(
        surface.publication().expect("it answers"),
        (1, "source = \"one\"\n".to_string())
    );
    let reached = surface.wait(0, Duration::from_secs(5));
    assert!(reached.reachable, "{}", reached.reason);

    // The millisecond rule: a follow notification on the local endpoint,
    // measured from the post to the follower told, over many rounds, each
    // beside a plain wake (Rounds::hold says what is held).
    let mut seen = reached.told;
    let mut rounds = Rounds::default();
    for round in 2..=201u64 {
        let posted = Instant::now();
        let from = ProcessorTime::process();
        board.post(format!("source = \"{round}\"\n"));
        let told = surface.wait(seen, Duration::from_secs(5));
        rounds.took.push(posted.elapsed());
        rounds.worked.push(from.elapsed());
        assert_eq!(told.revision, round);
        seen = told.told;
        rounds.beside();
    }
    rounds.hold("follow notification on the local endpoint");
}

#[test]
fn a_connection_on_this_machine_is_proven_and_answered_within_the_millisecond() {
    let board = Arc::new(Board::default());
    board.post("source = \"one\"\n".to_string());
    let watching = endpoint::account_as(Role::Observer, &[]);
    let (_listener, _, called) = endpoint::node(&board, watching);
    assert!(
        endpoint::surface(&called).publication().is_ok(),
        "the first answers"
    );

    // The millisecond rule: a surface's connection, from nothing to its
    // first answer — the endpoint opened, the caller's account read from
    // the operating system, HTTP/2 agreed and one call answered — over
    // many rounds, each beside a plain wake (Rounds::hold says what is held).
    // The surface states its wait, so what is measured is the connection:
    // a surface that states none first lists the node declarations to
    // learn the node's (`deadline::declared`), which on this machine's
    // temporary folder alone took 0.4 to 0.6 ms of processor time
    // (2026-10-21, open problem 35).
    let mut rounds = Rounds::default();
    for _ in 0..200 {
        let opened = Instant::now();
        let from = ProcessorTime::process();
        let answered = Remote::local_retrying(&called, WAIT, vec![Duration::from_millis(50)])
            .and_then(|surface| surface.publication());
        rounds.took.push(opened.elapsed());
        rounds.worked.push(from.elapsed());
        assert!(answered.is_ok(), "{answered:?}");
        rounds.beside();
    }
    rounds.hold("a connection on the local endpoint, proven and answered");
}
