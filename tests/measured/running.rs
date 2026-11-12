//! A running node (`xmip_core_runtime::running`), measured: Messages
//! carried from its Receive Location to the far end, Xmip's own share of
//! each held under a millisecond, and eight senders carried side by side.

use std::time::{Duration, Instant};

use http::HttpTransport;
use net::fixture::unheld;
use tcp::TcpTransport;
use transport::Transport;
use transport::socket::connect_tcp;
use xcore::latency::spread;
use xmip_core_runtime::fixture::started;

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

/// The most Xmip's own share of a carried Message may take, the fastest of
/// five: the millisecond rule.
const OWN: Duration = Duration::from_millis(1);

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
    // beside it, for information.
    let mut times = Vec::new();
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
    // Ledger's append and sync, its send to the far end — is Xmip's own
    // share, and it is held under a millisecond. A thread waiting for a
    // wake runs nothing, so no wake is counted.
    let own = outcomes.own_share.expect("the node measured its own share");
    // The Ledger's sync, the disk's time, printed beside it and held to
    // nothing (ADR-0018, amendment 2026-11-09).
    let disk = outcomes.disk_sync.expect("and the disk's time beside it");
    eprintln!(
        "Xmip's own share per Message {own:?}, the disk's sync beside it {disk:?}, the fastest \
         of five"
    );
    assert!(own < OWN, "Xmip's own share {own:?}, over {OWN:?}");
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
    let spread = format!(
        "{}\n[[correlations]]\nname = \"PerSender\"\nkeys = [\"http.header.x-sender\"]\n",
        node_keeping_connections(&receive, &far_address).replace(
            "receive_port = \"Loopback\"\n",
            "receive_port = \"Loopback\"\ncorrelation = \"PerSender\"\n",
        )
    );
    let path = written("eight", &spread);
    let running = started(path_text(&path), || linked(&path)).expect("the node starts");
    posted_as(
        &mut connect_tcp(&receive, Some(CONNECT)).expect("connects"),
        "warm",
        b"warm",
    );
    taken_at(&far);

    let started = Instant::now();
    let taking = std::thread::spawn(move || {
        let mut taken: Vec<Vec<u8>> = (0..SENDERS * EACH).map(|_| taken_at(&far)).collect();
        taken.sort();
        taken.dedup();
        taken.len()
    });
    let senders: Vec<_> = (0..SENDERS)
        .map(|sender| {
            let at = receive.clone();
            std::thread::spawn(move || {
                // Each sender keeps its one connection, and names itself.
                let mut connection = connect_tcp(&at, Some(CONNECT)).expect("connects");
                for message in 0..EACH {
                    let body = format!("S{sender} {message}");
                    posted_as(&mut connection, &format!("S{sender}"), body.as_bytes());
                }
            })
        })
        .collect();
    for sender in senders {
        sender.join().expect("a sender");
    }
    assert_eq!(
        taking.join().expect("the far end"),
        (SENDERS * EACH) as usize
    );
    let each = started.elapsed() / (SENDERS * EACH);
    eprintln!("eight senders, loopback end to end: {each:?} per Message");

    let outcomes = running.stop();
    assert_eq!(outcomes.sent, u64::from(SENDERS * EACH) + 1, "{outcomes:?}");
    assert!(each < Duration::from_millis(5), "{each:?} per Message");
    let _ = std::fs::remove_dir_all(path.parent().expect("its directory"));
}
