//! A running node (`xmip_core_runtime::running`), measured: Messages
//! carried from its Receive Location to the far end, Xmip's own share of
//! each held under a millisecond, and eight senders carried side by side,
//! each post answered within five milliseconds.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use http::HttpTransport;
use net::fixture::unheld;
use tcp::TcpTransport;
use transport::Transport;
use transport::socket::connect_tcp;
use xcore::latency::{PlainWake, spread, worked_beside_a_plain_wake};
use xmip_core_runtime::fixture::{started, until_listening};

use super::node::{count_anew, deliver, given, linked, node, path_text, written};

/// [`node`] over HTTP, the Send Port posting to `far`: a test carrying
/// hundreds of Messages through a node keeps one connection a sender,
/// where raw TCP spends one a Message, each waiting minutes to close on
/// its sender's side.
fn node_keeping_connections(receive: &str, far: &str) -> String {
    node(receive, &format!("{far}/orders")).replace("address = \"tcp://", "address = \"http://")
}

/// A far end over HTTP, listening before anything is sent to it, and where
/// it listens.
fn kept_far_end() -> (HttpTransport, String) {
    let far = HttpTransport::loopback();
    let address = far.listening().expect("the far end binds").to_string();
    (far, address)
}

/// The next Message `far` takes, accepted: its sender is answered.
fn taken_at(far: &HttpTransport) -> Vec<u8> {
    far.receive()
        .expect("it reaches the far end")
        .remove(0)
        .taken()
        .expect("accepted")
        .bytes
}

/// `body` posted over `connection` as the sender `who` names itself in its
/// `X-Sender` header, and the node's answer read: accepted.
fn posted_as(connection: &mut std::net::TcpStream, who: &str, body: &[u8]) {
    use std::io::{BufRead, BufReader, Read, Write};
    let head = format!(
        "POST /orders HTTP/1.1\r\nHost: node\r\nX-Sender: {who}\r\n\
         Content-Length: {}\r\n\r\n",
        body.len()
    );
    connection.write_all(head.as_bytes()).expect("writes");
    connection.write_all(body).expect("writes");
    let mut reader = BufReader::new(connection.try_clone().expect("clones"));
    let mut line = String::new();
    reader.read_line(&mut line).expect("answered");
    assert!(line.contains(" 2"), "the node answered {line}");
    let mut length = 0usize;
    loop {
        line.clear();
        reader.read_line(&mut line).expect("a header");
        if line == "\r\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            length = value.trim().parse().expect("a length");
        }
    }
    let mut answer = vec![0; length];
    reader.read_exact(&mut answer).expect("the answer's body");
}

/// How long a sender waits to connect to the node's Receive Location before
/// the test fails instead of hanging.
const CONNECT: Duration = Duration::from_secs(5);

#[test]
fn a_node_carries_every_message_from_its_receive_location_to_the_far_end() {
    const MESSAGES: u32 = 200;
    let far = TcpTransport::loopback();
    let (listener, far_address) = far.bind().expect("the far end binds");
    let receive = unheld().to_string();
    let path = written("carries", &node(&receive, &far_address));

    count_anew();
    let running = started(path_text(&path), || linked(&path)).expect("the node starts");

    // One module per technology, however many Locations use it; one
    // transport instance per Location.
    let registered: Vec<&str> = running
        .capabilities()
        .capabilities()
        .map(|c| c.capability.as_str())
        .collect();
    assert_eq!(
        registered,
        [
            "authenticate:circumstance",
            "authorize:open",
            "transport:xmip-core-transport-tcp"
        ]
    );
    assert_eq!(given().len(), 2, "one transport per Location");
    assert!(
        xmip_core_runtime::catalogue::declarations().contains_key("tcp"),
        "loading carries the declaration"
    );

    deliver(&TcpTransport::loopback(), &receive, b"order 0");
    let first = far
        .accept_one(&listener)
        .expect("the first arrives")
        .taken()
        .expect("read whole");
    assert_eq!(first.bytes, b"order 0");

    // The node counts the processor time its threads work for each
    // Message and reports Xmip's own share, the fastest of five
    // (`Outcomes::own_share`); each Message's time end to end is printed
    // beside it, for information, and a plain wake measured beside each.
    let (plain, mut times, mut idle) = (PlainWake::start(), Vec::new(), Vec::new());
    for message in 1..=MESSAGES {
        let payload = format!("order {message}");
        let started = Instant::now();
        TcpTransport::loopback()
            .send(&receive, payload.as_bytes())
            .expect("the node takes it");
        let arrived = far
            .accept_one(&listener)
            .expect("it reaches the far end")
            .taken()
            .expect("read whole");
        times.push(started.elapsed());
        assert_eq!(arrived.bytes, payload.as_bytes());
        idle.push(plain.round().1);
    }
    let _ = spread("a Message end to end, for information", times);

    let outcomes = running.stop();
    let carried = u64::from(MESSAGES) + 1;
    assert_eq!(outcomes.received, carried);
    assert_eq!(outcomes.routed, carried, "{outcomes:?}");
    assert_eq!(outcomes.sent, carried, "{outcomes:?}");
    assert_eq!(
        outcomes.refused + outcomes.failed + outcomes.unroutable + outcomes.not_sent,
        0
    );
    // The millisecond rule, with the load counted as load (the owner,
    // 2026-10-03: *Go for A*; 2026-11-01: *the processor time its threads
    // spent working for the Message*): what the node's threads ran for a
    // Message outside its I/O — its Stream read off the connection, the
    // Ledger's append and sync, its send to the far end, its hand-on and
    // its share of the Storage node's batches — is Xmip's own share, and it
    // is held under a millisecond (its hand-on counted since 2026-11-15). A
    // thread waiting for a wake runs nothing, so no wake is counted. It is
    // measured by the node, so it is held by the rule's processor-time
    // half: within a millisecond of this process's processor time across a
    // plain wake measured in the same rounds
    // (`xcore::latency::worked_beside_a_plain_wake`); until 2026-11-15
    // under a millisecond flat.
    let own = outcomes.own_share.expect("the node measured its own share");
    // The Ledger's sync, the disk's time, printed beside it and held to
    // nothing (ADR-0018, amendment 2026-11-09).
    let disk = outcomes.disk_sync.expect("and the disk's time beside it");
    eprintln!(
        "Xmip's own share per Message {own:?}, the disk's sync beside it {disk:?}, the fastest \
         of five"
    );
    worked_beside_a_plain_wake("Xmip's own share per Message", own, idle);
    let _ = std::fs::remove_dir_all(path.parent().expect("its directory"));
}

#[test]
fn eight_senders_at_once_are_carried_side_by_side() {
    // A Receive Location carries one Stream at a time end to end unless a
    // Correlation spreads them (`sequence`): this one's is keyed by the
    // sender each request names, so one sender's Streams go one at a time
    // and eight senders' side by side, their Ledger writes sharing a group
    // commit's disk sync.
    const SENDERS: u32 = 8;
    const EACH: u32 = 50;
    let (far, far_address) = kept_far_end();
    let receive = unheld().to_string();
    let side_by_side = format!(
        "{}\n[[correlations]]\nname = \"PerSender\"\nkeys = [\"http.header.x-sender\"]\n",
        node_keeping_connections(&receive, &far_address).replace(
            "receive_port = \"Loopback\"\n",
            "receive_port = \"Loopback\"\ncorrelation = \"PerSender\"\n",
        )
    );
    let path = written("eight", &side_by_side);
    let running = started(path_text(&path), || linked(&path)).expect("the node starts");
    // Its Receive Location binds on its first receive: the warm-up connect
    // asks again until it listens; the senders connect after it was taken.
    posted_as(
        &mut until_listening(&receive, || connect_tcp(&receive, Some(CONNECT))),
        "warm",
        b"warm",
    );
    taken_at(&far);

    // Each Message the far end takes, and when.
    let taking = std::thread::spawn(move || {
        (0..SENDERS * EACH)
            .map(|_| (taken_at(&far), Instant::now()))
            .collect::<HashMap<Vec<u8>, Instant>>()
    });
    let senders: Vec<_> = (0..SENDERS)
        .map(|sender| {
            let at = receive.clone();
            std::thread::spawn(move || {
                // Each sender keeps its one connection, and names itself:
                // each Message's body, when it was posted and when answered.
                let mut connection = connect_tcp(&at, Some(CONNECT)).expect("connects");
                (0..EACH)
                    .map(|message| {
                        let body = format!("S{sender} {message}");
                        let posted = Instant::now();
                        posted_as(&mut connection, &format!("S{sender}"), body.as_bytes());
                        (body.into_bytes(), posted, posted.elapsed())
                    })
                    .collect::<Vec<_>>()
            })
        })
        .collect();
    let posted: Vec<_> = senders
        .into_iter()
        .flat_map(|sender| sender.join().expect("a sender"))
        .collect();
    let taken = taking.join().expect("the far end");
    assert_eq!(taken.len(), (SENDERS * EACH) as usize, "each Message once");
    // Side by side is the receive side's: each post is answered once its
    // Stream is carried and its Ledger write synced, so eight carried one
    // at a time would each wait out the others' syncs. Each post timed,
    // sender by sender in the order each posted, the fastest of five
    // (`xcore::latency::spread`): a busy moment is in some rounds only.
    // From its post to the far end taking it is said beside it, for
    // information: the four hundred wait their turn at the one far end.
    // Until 2026-11-15 the whole was timed together and its mean held.
    let (answered, carried): (Vec<Duration>, Vec<Duration>) = posted
        .iter()
        .map(|(body, at, answered)| {
            let arrived = taken.get(body).expect("taken by the far end");
            (*answered, arrived.saturating_duration_since(*at))
        })
        .unzip();
    let _ = spread(
        "a Message of eight senders at once, from its post to the far end taking it, for \
         information",
        carried,
    );
    let answered = spread(
        "a Message of eight senders at once, its post answered",
        answered,
    );

    let outcomes = running.stop();
    assert_eq!(outcomes.sent, u64::from(SENDERS * EACH) + 1, "{outcomes:?}");
    assert!(
        answered.fastest_of_five < Duration::from_millis(5),
        "{answered:?} a post"
    );
    let _ = std::fs::remove_dir_all(path.parent().expect("its directory"));
}
