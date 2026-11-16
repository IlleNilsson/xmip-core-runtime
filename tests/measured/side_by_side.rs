//! A running node (`xmip_core_runtime::running`), measured: eight senders
//! carried side by side, each post answered within five milliseconds and
//! the send side keeping up — a sender's next Message at the far end within
//! a millisecond of its predecessor's hand-on, the far end idle while a
//! Message waits within a millisecond, and Xmip's own share per send under
//! one (ADR-0018, amendment 2026-11-15).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use http::HttpTransport;
use net::fixture::unheld;
use transport::Transport;
use transport::socket::connect_tcp;
use xcore::latency::{PlainWake, spread, woke_beside_a_plain_wake, worked_beside_a_plain_wake};
use xmip_core_runtime::fixture::{Failing, started, until_listening};

use super::node::{linked, node, path_text, written};

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
    // Its Storage node counted: when each hand-on was answered, durable.
    let counting: Arc<Mutex<Option<Arc<Failing>>>> = Arc::default();
    let running = started(path_text(&path), || {
        let mut linked = linked(&path);
        let beneath = linked.storage.take().expect("its Storage node");
        let counted = Failing::over(beneath);
        *counting.lock().expect("held") = Some(Arc::clone(&counted));
        linked.storage = Some(counted);
        linked
    })
    .expect("the node starts");
    let counted = counting.lock().expect("held").clone().expect("opened");
    // Its Receive Location binds on its first receive: the warm-up connect
    // asks again until it listens; the senders connect after it was taken.
    posted_as(
        &mut until_listening(&receive, || connect_tcp(&receive, Some(CONNECT))),
        "warm",
        b"warm",
    );
    taken_at(&far);

    // Each Message the far end takes, when, by the Journey its send names,
    // and when it answered; a plain wake measured beside each.
    let taking = std::thread::spawn(move || {
        let plain = PlainWake::start();
        (0..SENDERS * EACH)
            .map(|_| (far_took(&far), plain.round()))
            .unzip::<_, _, Vec<FarTook>, Vec<(Duration, Duration)>>()
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
    let (took, beside) = taking.join().expect("the far end");
    let taken: HashMap<&[u8], &FarTook> =
        took.iter().map(|one| (one.bytes.as_slice(), one)).collect();
    assert_eq!(taken.len(), (SENDERS * EACH) as usize, "each Message once");
    let (woke, idle): (Vec<Duration>, Vec<Duration>) = beside.into_iter().unzip();
    let usual = spread("a plain wake beside the far end's each take", woke).fastest_of_five;
    // Side by side is the receive side's: each post is answered once its
    // Stream is carried and its Ledger write synced, so eight carried one
    // at a time would each wait out the others' syncs. Each post timed,
    // sender by sender in the order each posted, the fastest of five
    // (`xcore::latency::spread`): a busy moment is in some rounds only.
    // From its post to the far end taking it, and each sender's Messages
    // one after the other at the far end, are said beside it, for
    // information. Until 2026-11-15 the whole was timed together and its
    // mean held.
    let (answered, carried): (Vec<Duration>, Vec<Duration>) = posted
        .iter()
        .map(|(body, at, answered)| {
            let arrived = taken.get(body.as_slice()).expect("taken by the far end");
            (*answered, arrived.at.saturating_duration_since(*at))
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
    let _ = spread(
        "a sender's Message after its last at the far end, for information",
        per_sender(&posted, &taken),
    );
    // The send side keeps up (decided 2026-11-15; ADR-0018, amendment
    // 2026-11-15): a sender's Messages go one at a time end to end, so the
    // next of them may reach the far end only once the one before it is
    // handed on, durable; from then on the far end waits on Xmip alone. For
    // each Message posted and answered before its predecessor's hand-on was
    // durable, from that hand-on's answer to the far end taking it, in the
    // order the hand-ons were answered: within the millisecond beyond a
    // plain wake, the far end's wake for the request (the Rounds rule,
    // `xcore::latency`). Until 2026-11-15 the next gave its claim back
    // behind its predecessor, and was claimed and read again from its queue
    // after the hand-on, a claim's sync more: 1.9 ms more at the median.
    let handed_on: HashMap<String, Instant> = counted
        .handed_on()
        .into_iter()
        .map(|(journey, at)| (journey.to_string(), at))
        .collect();
    let next_after = spread(
        "a sender's next Message, from its predecessor's hand-on durable to the far end \
         taking it",
        after_hand_on(&posted, &taken, &handed_on),
    );
    woke_beside_a_plain_wake(
        "a sender's next Message after its predecessor's hand-on",
        next_after.fastest_of_five,
        usual,
        1,
    );
    // The far end idle while Messages wait for it: before each it takes,
    // from its answer to the one before, where one was accepted and not
    // yet taken; the fastest of five, within the millisecond beyond a
    // plain wake.
    let idle_gap = spread(
        "the far end idle while a Message waits for it",
        far_idle(&posted, &took),
    );
    woke_beside_a_plain_wake(
        "the far end idle while a Message waits for it",
        idle_gap.fastest_of_five,
        usual,
        1,
    );

    let outcomes = running.stop();
    assert_eq!(outcomes.sent, u64::from(SENDERS * EACH) + 1, "{outcomes:?}");
    assert!(
        answered.fastest_of_five < Duration::from_millis(5),
        "{answered:?} a post"
    );
    // Xmip's own share per send, as the node's stop record says it, held by
    // the rule's processor-time half beside the plain wakes measured at the
    // far end (`xcore::latency::worked_beside_a_plain_wake`).
    let own = outcomes.own_share.expect("the node measured its own share");
    eprintln!(
        "Xmip's own share per send of eight senders at once {own:?}, the disk's sync beside it \
         {:?}, the fastest of five",
        outcomes.disk_sync
    );
    worked_beside_a_plain_wake("Xmip's own share per send of eight senders", own, idle);
    let _ = std::fs::remove_dir_all(path.parent().expect("its directory"));
}

/// What the far end took: the body, when it took it, the Journey its send
/// named (`Idempotency-Key`), and when it answered it.
struct FarTook {
    bytes: Vec<u8>,
    at: Instant,
    journey: String,
    answered: Instant,
}

/// The next Message `far` takes, accepted: its sender is answered.
fn far_took(far: &HttpTransport) -> FarTook {
    let arrived = far.receive().expect("it reaches the far end").remove(0);
    let at = Instant::now();
    let journey = arrived
        .headers()
        .fields()
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(http::IDEMPOTENCY_KEY))
        .and_then(|(_, value)| match value {
            xcore::ScalarValue::Text(text) => Some(text.trim_matches('"').to_string()),
            _ => None,
        })
        .expect("each send names its Journey");
    let bytes = arrived.taken().expect("accepted").bytes;
    FarTook {
        bytes,
        at,
        journey,
        answered: Instant::now(),
    }
}

/// Each post: its body, when it was posted, and how long its answer took.
type Posted = (Vec<u8>, Instant, Duration);

/// Each sender's Messages in the order it posted them: the posts of one
/// sender are consecutive in `posted`, its name before the space.
fn senders_of(posted: &[Posted]) -> Vec<&[Posted]> {
    posted
        .chunk_by(|one, next| sender_of(&one.0) == sender_of(&next.0))
        .collect()
}

fn sender_of(body: &[u8]) -> &[u8] {
    body.split(|byte| *byte == b' ').next().unwrap_or_default()
}

/// From each sender's Message reaching the far end to its next one doing so.
fn per_sender(posted: &[Posted], taken: &HashMap<&[u8], &FarTook>) -> Vec<Duration> {
    senders_of(posted)
        .into_iter()
        .flat_map(|one| {
            one.windows(2).map(|pair| {
                let at = |post: &Posted| taken[post.0.as_slice()].at;
                at(&pair[1]).saturating_duration_since(at(&pair[0]))
            })
        })
        .collect()
}

/// For each Message answered before its predecessor's hand-on was durable,
/// from that hand-on's answer to the far end taking it, in the order the
/// hand-ons were answered.
fn after_hand_on(
    posted: &[Posted],
    taken: &HashMap<&[u8], &FarTook>,
    handed_on: &HashMap<String, Instant>,
) -> Vec<Duration> {
    let mut rounds: Vec<(Instant, Duration)> = senders_of(posted)
        .into_iter()
        .flat_map(|one| {
            one.windows(2).filter_map(|pair| {
                let before = taken[pair[0].0.as_slice()];
                let durable = *handed_on.get(&before.journey)?;
                let (body, at, answer) = &pair[1];
                (*at + *answer <= durable).then(|| {
                    let next = taken[body.as_slice()];
                    (durable, next.at.saturating_duration_since(durable))
                })
            })
        })
        .collect();
    rounds.sort_by_key(|(durable, _)| *durable);
    rounds.into_iter().map(|(_, took)| took).collect()
}

/// Before each Message the far end took, from its answer to the one before,
/// where a Message was answered and not yet taken then.
fn far_idle(posted: &[Posted], took: &[FarTook]) -> Vec<Duration> {
    let answered: Vec<Instant> = posted.iter().map(|(_, at, answer)| *at + *answer).collect();
    took.windows(2)
        .filter_map(|pair| {
            let free = pair[0].answered;
            let waiting = answered.iter().filter(|at| **at <= free).count();
            let taken = took.iter().filter(|one| one.at <= free).count();
            (waiting > taken).then(|| pair[1].at.saturating_duration_since(free))
        })
        .collect()
}
