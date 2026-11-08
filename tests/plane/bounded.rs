//! A node's operate listener held to its limits against a caller that holds
//! it up rather than asks it anything (`plane::limits`): a connection past
//! the connections or the handshakes in progress it takes is closed as it
//! is accepted, a place freed is taken again, and a handshake dribbled a
//! byte at a time is cut at its deadline in all, not read by read.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

use xmip_core_runtime::fixture::Authority;
use xmip_core_runtime::plane::{Board, Grants, Limits, Listener};

use super::certified::{node, remote};

/// A node whose surface `CN=surface` observes, bounded by `limits`.
fn bounded(authority: &Authority, board: &Arc<Board>, limits: Limits) -> Listener {
    let (listener, _) = node(
        authority,
        board,
        Grants::listed([&["CN=surface".to_string()], &[], &[]]),
    );
    listener.limit(limits);
    listener
}

/// A connection to `listener` that says nothing, waiting `patience` at most
/// on each read.
fn silent(listener: &Listener, patience: Duration) -> TcpStream {
    let address: std::net::SocketAddr = listener.address().parse().expect("host:port");
    let tcp = net::connect(address, Some(patience)).expect("connected");
    tcp.set_read_timeout(Some(patience)).expect("bounded");
    tcp
}

/// Whether the node closed `tcp`: a read that ends, rather than one that
/// waits its timeout out.
fn closed(tcp: &mut TcpStream) -> bool {
    let mut byte = [0u8; 1];
    match tcp.read(&mut byte) {
        Ok(0) => true,
        Ok(_) => false,
        Err(error) => !matches!(
            error.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ),
    }
}

#[test]
fn a_connection_past_the_connections_or_handshakes_it_takes_is_closed() {
    let authority = Authority::new();
    let board = Arc::new(Board::default());
    let short = Duration::from_millis(300);
    let limits = Limits {
        connections: 2,
        ..Limits::default()
    };
    let listener = bounded(&authority, &board, limits);
    let mut held = [silent(&listener, short), silent(&listener, short)];
    let mut third = silent(&listener, Duration::from_secs(5));
    assert!(closed(&mut third), "the third connection is closed");
    for tcp in &mut held {
        assert!(!closed(tcp), "the two taken are held");
    }
    // A place freed is taken again: a surface of its own each try, since
    // one refused says its node is unreachable until its follow finds it.
    drop(held);
    let until = Instant::now() + Duration::from_secs(5);
    let answered = loop {
        let answered = remote(&authority, &listener).publication();
        if answered.is_ok() || Instant::now() >= until {
            break answered;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(
        answered.is_ok(),
        "answered once a place is free: {answered:?}"
    );

    let limits = Limits {
        handshakes: 1,
        ..Limits::default()
    };
    let listener = bounded(&authority, &board, limits);
    let mut handshaking = silent(&listener, short);
    let mut second = silent(&listener, Duration::from_secs(5));
    assert!(closed(&mut second), "the second handshake is refused");
    assert!(!closed(&mut handshaking), "the first is held");
}

#[test]
fn a_handshake_dribbled_a_byte_at_a_time_is_cut_at_its_deadline() {
    let authority = Authority::new();
    let board = Arc::new(Board::default());
    let within = Duration::from_millis(400);
    let limits = Limits {
        handshake_within: within,
        ..Limits::default()
    };
    let listener = bounded(&authority, &board, limits);
    let mut tcp = silent(&listener, Duration::from_secs(10));
    let mut writing = tcp.try_clone().expect("a writer");
    // A TLS record of a ClientHello 512 bytes long, sent one byte each 20
    // ms: every read the node makes gets a byte long before any read's own
    // wait could end.
    let began = Instant::now();
    let dribbling = std::thread::spawn(move || {
        let record = [0x16_u8, 0x03, 0x01, 0x02, 0x00, 0x01];
        for byte in record.into_iter().chain(std::iter::repeat(0)).take(517) {
            if writing.write_all(&[byte]).is_err() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    });
    assert!(closed(&mut tcp), "cut");
    let cut = began.elapsed();
    assert!(
        cut >= within && cut < within * 4,
        "cut after {cut:?}, the deadline {within:?}"
    );
    drop(tcp);
    dribbling.join().expect("the dribbler");
}
