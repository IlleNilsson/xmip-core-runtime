use context::MessageContext;
use message::{Message, MessageCreationSource, MessageSection, MessageTreatment};
use stream::Stream;
use xcore::{IdGenerator, MessageId, ScalarValue, SectionId, StreamId, UuidV7Generator};

use super::{BATCH, COUNT, POSITION, Splitting, whole};
use crate::fixture::Lines;

fn received(ids: &UuidV7Generator, bytes: &[u8]) -> Message {
    let section = MessageSection {
        section_id: SectionId::new(ids.next_u128()),
        name: None,
        stream: Stream::new(StreamId::new(ids.next_u128()), bytes.to_vec(), None),
        contract: None,
    };
    Message::received(
        MessageId::new(ids.next_u128()),
        vec![section],
        MessageContext::new().with_value("Client", ScalarValue::Text("C-1".into())),
        MessageTreatment::default(),
    )
}

fn text(section: &MessageSection) -> String {
    let bytes = section.stream.load().expect("the Ledger reads it");
    String::from_utf8(bytes.to_vec()).expect("text")
}

#[test]
fn a_message_split_whole_makes_a_part_per_record_in_order_each_kept_together() {
    let ids = UuidV7Generator;
    let storage = crate::ledger::in_memory();
    let from = received(&ids, b"one\ntwo\nthree");
    // A chunk of two bytes, so records end across chunks.
    let parts = whole((storage, &ids, 2), &from, (&mut Lines::default(), None))
        .expect("split")
        .expect("every record");

    let texts: Vec<String> = parts.iter().map(|p| text(&p.sections()[0])).collect();
    assert_eq!(texts, ["one", "two", "three"]);
    for (part, position) in parts.iter().zip(1..) {
        assert_eq!(part.created_by(), MessageCreationSource::Debatch);
        assert_eq!(part.previous_message_id(), Some(from.message_id()));
        let context = part.context();
        assert_eq!(
            context.get("Client").and_then(|v| v.text()).as_deref(),
            Some("C-1"),
            "a part carries its context"
        );
        assert_eq!(
            context.get(BATCH),
            Some(&ScalarValue::Text(from.message_id().to_string()))
        );
        assert_eq!(context.get(POSITION), Some(&ScalarValue::Integer(position)));
        assert_eq!(context.get(COUNT), Some(&ScalarValue::Integer(3)));
        let stream = part.sections()[0].stream.id();
        assert!(
            storage.read_stream(stream).expect("read").is_some(),
            "a part's Stream is kept in the Ledger"
        );
    }
}

#[test]
fn every_refused_record_is_gathered_and_the_split_fails_once_with_a_summary() {
    let ids = UuidV7Generator;
    let from = received(&ids, b"one\nbad!\nthree\nworse!\nfive\n");
    let failures = whole(
        (crate::ledger::in_memory(), &ids, 64),
        &from,
        (
            &mut Lines::default(),
            Some("unit 'Lines' of 'Units'".into()),
        ),
    )
    .expect("split")
    .expect_err("all or nothing");

    assert_eq!(failures.total, 5, "every record is still split");
    let positions: Vec<Option<u64>> = failures.failed.iter().map(|f| f.at.position).collect();
    assert_eq!(positions, [Some(2), Some(4)]);
    for failed in &failures.failed {
        assert_eq!(failed.code, super::REFUSED);
        assert_eq!(failed.stage, "debatch");
        assert_eq!(failed.artifact.as_deref(), Some("unit 'Lines' of 'Units'"));
    }
    let said = failures.to_string();
    assert!(
        said.starts_with(
            "error: debatch: 5 records, 3 succeeded, 2 failed\n\
             error[record-refused]: the line 'bad!' is no record\n  \
             --> debatch, unit 'Lines' of 'Units', record 2"
        ),
        "{said}"
    );
    assert!(said.contains("worse!"), "{said}");
}

#[test]
fn fed_a_chunk_at_a_time_each_record_is_written_as_soon_as_it_is_complete() {
    let ids = UuidV7Generator;
    let mut lines = Lines::default();
    let mut splitting = Splitting::new((crate::ledger::in_memory(), &ids, 64), (&mut lines, None));

    splitting.feed(b"one\ntw").expect("fed");
    assert_eq!(
        splitting.written(),
        1,
        "a record complete is written at once"
    );
    splitting.feed(b"o").expect("fed");
    assert_eq!(splitting.written(), 1, "an incomplete record waits");
    splitting.feed(b"\nlast").expect("fed");
    assert_eq!(splitting.written(), 2);
    let sections = splitting.end().expect("ended").expect("every record");
    let texts: Vec<String> = sections.iter().map(text).collect();
    assert_eq!(texts, ["one", "two", "last"]);
}
