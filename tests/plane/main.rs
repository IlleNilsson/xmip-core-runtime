//! The operate plane end to end over loopback (ADR-0014, amendment
//! 2026-10-12): a node's operate listener and a remote surface, each with
//! a certificate from one test authority, over gRPC inside Xmip's mutual
//! TLS — the publication read, a follower told as it advances and how
//! fast, an act gated by the caller's role and audited, a stranger
//! refused, and a node lost and found again on the recovery loop.

mod local;

use std::net::TcpListener;
use std::sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, Instant};

use xaudit::program_audit::ProgramAudit;
use xcore::latency::{PlainWake, at_once, spread};
use xcore::processor_time::ProcessorTime;
use xmip_core_runtime::fixture::{Authority, absent_node};
use xmip_core_runtime::plane::{Board, Listener, Outcome, Remote, Role};

/// The machine, as the tests here share it: a test that measures how long
/// Xmip takes holds it whole ([`alone`]) and every other shares it
/// ([`sharing`]), so the process's processor time a round is held to is
/// Xmip's work and not a neighboring test's, as the service's tests do.
static MACHINE: RwLock<()> = RwLock::new(());

fn alone() -> RwLockWriteGuard<'static, ()> {
    MACHINE.write().unwrap_or_else(PoisonError::into_inner)
}

fn sharing() -> RwLockReadGuard<'static, ()> {
    MACHINE.read().unwrap_or_else(PoisonError::into_inner)
}

/// A node's listener over `board` on a loopback port, holding `role`.
fn node(authority: &Authority, board: &Arc<Board>, role: Option<Role>) -> (Listener, ProgramAudit) {
    let audit = ProgramAudit::new("plane-test", Some(&authority.directory));
    let listener = TcpListener::bind("127.0.0.1:0").expect("an operate listener");
    let served = Listener::start(
        listener,
        &authority.identity("node"),
        Arc::clone(board) as Arc<dyn xmip_core_runtime::plane::Published>,
        role,
        &audit,
    )
    .expect("it serves");
    (served, audit)
}

fn remote(authority: &Authority, listener: &Listener) -> Remote {
    let address = listener.address();
    Remote::retrying(
        &address,
        &authority.identity("surface"),
        vec![Duration::from_millis(50)],
    )
    .expect("a remote")
}

#[test]
fn a_surface_reads_the_publication_and_is_told_as_it_advances() {
    let _alone = alone();
    let authority = Authority::new();
    let board = Arc::new(Board::default());
    board.post("source = \"one\"\n".to_string());
    let (listener, _) = node(&authority, &board, None);
    let surface = remote(&authority, &listener);

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

/// The bound: about a millisecond.
const BOUND: Duration = Duration::from_millis(1);

#[test]
fn an_act_is_the_certificates_and_is_refused_to_an_observer() {
    let _sharing = sharing();
    let authority = Authority::new();
    let board = Arc::new(Board::default());
    let (listener, audit) = node(&authority, &board, None);
    let surface = remote(&authority, &listener);

    let (outcome, said) = surface
        .act(&absent_node(), "subscription", "orders", "pause")
        .expect("it answers");
    assert_eq!(outcome, Outcome::Denied);
    assert!(
        // Decided by its method before the call is read (ADR-0009, amendment
        // 2026-10-29), so the refusal names the method, not the Subscription.
        said.starts_with("REFUSED. CN=surface may not act on this node"),
        "{said}"
    );
    let file = audit.file().expect("an audit file");
    let kept = std::fs::read_to_string(file).expect("the audit file");
    assert!(
        kept.contains("CN=surface") && kept.contains("Observer"),
        "{kept}"
    );

    let (outcome, said) = surface
        .act(&absent_node(), "subscription", "orders", "remove")
        .expect("it answers");
    // Who may ask is decided first: an Observer is told so, whatever it asks.
    assert_eq!(outcome, Outcome::Denied, "{said}");
}

#[test]
fn an_operator_acts_as_the_certificate_and_the_node_answers() {
    let _sharing = sharing();
    let authority = Authority::new();
    let board = Arc::new(Board::default());
    let (listener, _) = node(&authority, &board, Some(Role::Operator));
    let surface = remote(&authority, &listener);

    let (outcome, said) = surface
        .act(&absent_node(), "journey", "j1", "retry")
        .expect("it answers");
    assert_eq!(outcome, Outcome::Refused);
    assert_eq!(
        said,
        format!("REFUSED: no node at {} runs in this process", absent_node())
    );
}

#[test]
fn a_surface_whose_certificate_the_node_does_not_trust_is_refused() {
    let _sharing = sharing();
    let ours = Authority::new();
    let theirs = Authority::new();
    let board = Arc::new(Board::default());
    let (listener, _) = node(&ours, &board, None);
    let stranger = remote(&theirs, &listener);

    let refused = stranger.publication().expect_err("refused");
    assert!(refused.contains("unreachable"), "{refused}");
}

#[test]
fn a_node_lost_is_told_and_found_again_on_the_recovery_loop() {
    let _sharing = sharing();
    let authority = Authority::new();
    let board = Arc::new(Board::default());
    board.post("source = \"one\"\n".to_string());
    let (mut listener, _) = node(&authority, &board, None);
    let port = listener
        .address()
        .parse::<std::net::SocketAddr>()
        .expect("host:port")
        .port();
    let surface = remote(&authority, &listener);

    let reached = surface.wait(0, Duration::from_secs(5));
    assert!(reached.reachable);

    let stopped = Instant::now();
    listener.stop();
    let lost = surface.wait(reached.told, Duration::from_secs(5));
    assert!(!lost.reachable, "told it is lost");
    assert!(
        stopped.elapsed() < Duration::from_secs(1),
        "{:?}",
        stopped.elapsed()
    );
    let unanswered = surface.publication().expect_err("not answered as current");
    assert!(unanswered.contains("unreachable"), "{unanswered}");

    let again = TcpListener::bind(("127.0.0.1", port)).expect("the same port");
    let audit = ProgramAudit::new("plane-test", Some(&authority.directory));
    let _back = Listener::start(
        again,
        &authority.identity("node"),
        Arc::clone(&board) as Arc<dyn xmip_core_runtime::plane::Published>,
        None,
        &audit,
    )
    .expect("it serves again");
    let mut found = lost;
    let deadline = Instant::now() + Duration::from_secs(5);
    while !found.reachable && Instant::now() < deadline {
        found = surface.wait(found.told, Duration::from_secs(1));
    }
    assert!(found.reachable, "{}", found.reason);
    assert!(surface.publication().is_ok());
}

#[test]
fn a_read_after_the_node_was_not_there_says_so_at_once_and_the_loop_finds_it() {
    let _alone = alone();
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
        None,
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
