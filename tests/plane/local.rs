//! The operate plane on this machine (ADR-0014, amendment 2026-10-13): a
//! node's local endpoint — a named pipe on Windows, a Unix domain socket
//! elsewhere — and the surface over it, with no certificate: the
//! publication read, a follower told as it advances and how fast, an act
//! taken as the operating system user this test runs as and refused to an
//! Observer, and a stop and a drop that end a follow waiting on the
//! endpoint at once.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use xaudit::program_audit::ProgramAudit;
use xcore::processor_time::ProcessorTime;
use xmip_core_runtime::fixture::absent_node;
use xmip_core_runtime::plane::{Board, Listener, Outcome, Published, Remote, Role};

/// An endpoint no other test or run uses.
fn endpoint() -> String {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let next = NEXT.fetch_add(1, Ordering::SeqCst);
    format!("xmip-operate-test-{}-{next}", std::process::id())
}

fn audit() -> (ProgramAudit, std::path::PathBuf) {
    let directory = std::env::temp_dir().join(endpoint());
    std::fs::create_dir_all(&directory).expect("an audit directory");
    (
        ProgramAudit::new("plane-local-test", Some(&directory)),
        directory,
    )
}

/// A node's local endpoint over `board`, holding `role`.
fn node(board: &Arc<Board>, role: Option<Role>) -> (Listener, ProgramAudit, String) {
    let (audit, _) = audit();
    let called = endpoint();
    let published = Arc::clone(board) as Arc<dyn Published>;
    let admitting = xmip_core_runtime::plane::local::Admitting::default();
    let listener = Listener::local(&called, admitting, published, role, &audit).expect("it serves");
    (listener, audit, called)
}

/// The wait a surface states: the node's default.
const WAIT: Duration = Duration::from_secs(2);

fn surface(called: &str) -> Remote {
    Remote::local_retrying(called, Duration::ZERO, vec![Duration::from_millis(50)])
        .expect("a surface")
}

/// The user this test runs as, as the system names it in a login.
fn user() -> String {
    std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_default()
        .to_lowercase()
}

#[test]
fn a_surface_on_this_machine_reads_the_publication_and_is_told_as_it_advances() {
    let _alone = super::alone();
    let board = Arc::new(Board::default());
    board.post("source = \"one\"\n".to_string());
    let (_listener, _, called) = node(&board, None);
    let surface = surface(&called);

    assert_eq!(
        surface.publication().expect("it answers"),
        (1, "source = \"one\"\n".to_string())
    );
    let reached = surface.wait(0, Duration::from_secs(5));
    assert!(reached.reachable, "{}", reached.reason);

    // The millisecond rule: a follow notification on the local endpoint,
    // measured from the post to the follower told, over many rounds, each
    // beside a plain wake (super::hold says what is held).
    let mut seen = reached.told;
    let mut rounds = super::Rounds::default();
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
    let _alone = super::alone();
    let board = Arc::new(Board::default());
    board.post("source = \"one\"\n".to_string());
    let (_listener, _, called) = node(&board, None);
    assert!(surface(&called).publication().is_ok(), "the first answers");

    // The millisecond rule: a surface's connection, from nothing to its
    // first answer — the endpoint opened, the caller's account read from
    // the operating system, HTTP/2 agreed and one call answered — over
    // many rounds, each beside a plain wake (super::hold says what is held).
    // The surface states its wait, so what is measured is the connection:
    // a surface that states none first lists the node declarations to
    // learn the node's (`deadline::declared`), which on this machine's
    // temporary folder alone took 0.4 to 0.6 ms of processor time
    // (2026-10-21, open problem 35).
    let mut rounds = super::Rounds::default();
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

#[test]
fn an_act_on_this_machine_is_the_users_and_is_refused_to_an_observer() {
    let _sharing = super::sharing();
    let board = Arc::new(Board::default());
    let (_listener, audit, called) = node(&board, None);
    let surface = surface(&called);

    let (outcome, said) = surface
        .act(&absent_node(), "subscription", "orders", "pause")
        .expect("it answers");
    assert_eq!(outcome, Outcome::Denied);
    assert!(said.starts_with("REFUSED. "), "{said}");
    assert!(said.to_lowercase().contains(&user()), "{said}");
    let kept = std::fs::read_to_string(audit.file().expect("an audit file")).expect("read");
    assert!(kept.contains("Observer"), "{kept}");
    assert!(
        kept.contains("operate.local"),
        "the plain text is said: {kept}"
    );
}

#[test]
fn an_operator_on_this_machine_acts_and_the_node_answers() {
    let _sharing = super::sharing();
    let board = Arc::new(Board::default());
    let (_listener, _, called) = node(&board, Some(Role::Operator));
    let surface = surface(&called);

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
fn a_secret_is_set_through_the_endpoint_as_an_act_and_never_said_back() {
    let _sharing = super::sharing();
    let board = Arc::new(Board::default());
    let (_listener, _, called) = node(&board, Some(Role::Operator));
    let operator = surface(&called);
    let drawn = format!("drawn-{}", std::process::id());

    let (outcome, said) = operator
        .set_secret(&absent_node(), ("partner-x", "password", &drawn))
        .expect("it answers");
    assert_eq!(outcome, Outcome::Refused);
    assert_eq!(
        said,
        format!("REFUSED: no node at {} runs in this process", absent_node())
    );
    assert!(!said.contains(&drawn));
    let listed = operator.secrets(&absent_node()).expect_err("no such node");
    assert!(listed.starts_with("REFUSED: no node at"), "{listed}");

    let (_watching, _, watched) = node(&board, Some(Role::Observer));
    let (outcome, said) = surface(&watched)
        .set_secret(&absent_node(), ("partner-x", "password", &drawn))
        .expect("it answers");
    assert_eq!(outcome, Outcome::Denied, "{said}");
}

#[test]
fn a_stop_ends_a_follow_waiting_on_the_endpoint_and_it_is_told() {
    let _sharing = super::sharing();
    let board = Arc::new(Board::default());
    board.post("source = \"one\"\n".to_string());
    let (mut listener, _, called) = node(&board, None);
    let surface = surface(&called);
    let reached = surface.wait(0, Duration::from_secs(5));
    assert!(reached.reachable, "{}", reached.reason);
    // The follow now waits on the node, which holds its wait.
    std::thread::sleep(Duration::from_millis(20));

    let stopped = Instant::now();
    listener.stop();
    assert!(
        stopped.elapsed() < Duration::from_secs(1),
        "the stop took {:?}",
        stopped.elapsed()
    );
    let lost = surface.wait(reached.told, Duration::from_secs(5));
    assert!(!lost.reachable, "told it is lost");
    assert!(stopped.elapsed() < Duration::from_secs(1));
}

#[test]
fn a_surface_dropped_while_its_follow_waits_ends_at_once() {
    let _sharing = super::sharing();
    let board = Arc::new(Board::default());
    let (_listener, _, called) = node(&board, None);
    let surface = surface(&called);
    assert!(surface.wait(0, Duration::from_secs(5)).reachable);
    std::thread::sleep(Duration::from_millis(20));

    let dropped = Instant::now();
    drop(surface);
    assert!(
        dropped.elapsed() < Duration::from_secs(1),
        "the drop took {:?}",
        dropped.elapsed()
    );
}

#[test]
fn a_surface_with_no_node_at_the_endpoint_says_so() {
    let _sharing = super::sharing();
    let surface = surface(&endpoint());
    let said = surface.publication().expect_err("nothing there");
    assert!(said.contains("unreachable"), "{said}");
    assert!(Remote::local(" ", Duration::ZERO).is_err());
}
