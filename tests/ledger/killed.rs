//! The two kills: a receive killed before its Publication leaves no
//! Message, and every Message acknowledged before a kill is there after it.

use std::sync::Arc;

use journey::Journey;
use message::Message;
use stream::Content;
use xcore::{JourneyId, MessageId, StreamId};

use xmip_core_runtime::ledger::Chunks;

use super::{STARTED, directory, heard, killed, spawn, test_node};

/// One completed receive as the child said it: the number its content
/// carries, its Message and its Journeys.
struct Acknowledged {
    number: u64,
    message: MessageId,
    journeys: Vec<JourneyId>,
}

fn acknowledged(said: &str) -> Acknowledged {
    let mut words = said.split_whitespace();
    let mut next = || words.next().expect("a word");
    let number = next().parse().expect("a number");
    let message = MessageId::new(next().parse().expect("a Message"));
    let journeys = next()
        .split(',')
        .map(|id| JourneyId::new(id.parse().expect("a Journey")))
        .collect();
    Acknowledged {
        number,
        message,
        journeys,
    }
}

#[test]
fn a_message_acknowledged_before_the_kill_is_in_the_ledger_after_it() {
    let place = directory("acknowledged");
    let (child, lines) = spawn("receive", &place);
    let mut received = Vec::new();
    while received.len() < 100 {
        received.push(acknowledged(&heard(&lines, "received ", STARTED)));
    }
    received.extend(
        killed(child, &lines)
            .iter()
            .filter_map(|line| line.find("received ").map(|at| &line[at + 9..]))
            .map(acknowledged),
    );

    let node = test_node(&place);
    for one in &received {
        let record = node
            .read_message(one.message)
            .expect("read")
            .unwrap_or_else(|| panic!("acknowledged Message {} lost", one.number));
        let message = Message::from_record(&record.body, |stream, length| {
            Ok(Arc::new(Chunks::of(Arc::clone(&node), stream, length)) as Arc<dyn Content>)
        })
        .expect("the Message reads back");
        let expected = format!("order {}", one.number);
        assert_eq!(message.sections()[0].stream.bytes(), expected.as_bytes());
        assert_eq!(one.journeys.len(), 1, "one per matched Subscription");
        for journey in &one.journeys {
            let record = node
                .read_journey(*journey)
                .expect("read")
                .unwrap_or_else(|| panic!("the Journey of Message {} lost", one.number));
            let journey = Journey::from_record(&record.body).expect("the Journey reads back");
            assert_eq!(journey.messages()[0].message_id, one.message);
            assert_eq!(
                journey.cause().map(|cause| cause.subscription_id.as_str()),
                Some("onward")
            );
        }
    }
    drop(node);
    let _ = std::fs::remove_dir_all(&place);
}

#[test]
fn a_receive_killed_after_its_chunks_and_before_publication_leaves_no_message() {
    let place = directory("halted");
    let (child, lines) = spawn("halt", &place);
    let stream: u128 = heard(&lines, "chunk ", STARTED)
        .split_whitespace()
        .next()
        .expect("a Stream")
        .parse()
        .expect("a number");
    let message: u128 = heard(&lines, "halting ", STARTED)
        .parse()
        .expect("a Message");
    killed(child, &lines);

    let node = test_node(&place);
    let chunk = node
        .read_chunk(StreamId::new(stream), 0)
        .expect("read")
        .expect("the chunk written before the kill is there");
    assert_eq!(chunk.bytes, b"order 0");
    assert!(
        node.read_message(MessageId::new(message))
            .expect("read")
            .is_none(),
        "no Message was published, so none is kept"
    );
    drop(node);
    let _ = std::fs::remove_dir_all(&place);
}
