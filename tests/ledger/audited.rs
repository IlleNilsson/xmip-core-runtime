//! A receive's Publication audited with what it audits (ADR-0070): once the
//! audit keeper kept it, the audit record carries the Message as it was
//! published, in its one binary form, and the Stream's bytes beside it a
//! chunk at a time, their SHA-256 digest and length taken from the Stream's
//! own record; a read of them is verified against both.

use std::io::{Cursor, Read};
use std::sync::Arc;

use message::Message;
use persist::storage::{Ask, AuditEntry, ChunkReader, Query, Span, StreamDigest, XmipStorage};
use receive::ReceivedStream;
use xcore::AuditId;
use xmip_core_runtime::ledger::{CHUNK, Chunks};
use xmip_core_runtime::message_path::carry;
use xmip_core_runtime::outcome::Arrived;

use super::receive_cycle::on_runtime;
use super::sending::memory;

/// `content` received and published over `storage` in chunks of `chunk`
/// bytes, and the Publication's audit record once the keeper kept it.
fn published(storage: &Arc<dyn XmipStorage>, content: &[u8], chunk: usize) -> AuditEntry {
    let carried = on_runtime(storage, chunk, |runtime, pickup, gate| {
        let body = Cursor::new(content.to_vec());
        carry(
            runtime,
            pickup,
            gate,
            ReceivedStream::new(body, "tcp://127.0.0.1:1"),
        )
    });
    assert!(
        matches!(carried.arrived, Arrived::Routed { .. }),
        "routed: {:?}",
        carried.arrived
    );
    assert_eq!(storage.keep_audit(10).expect("kept"), 1, "its audit record");
    let occurred = Query {
        ask: Ask::AuditOccurred {
            occurred: Span::ALL,
        },
        most: 10,
        newest_first: false,
    };
    let found = storage.query(&occurred).expect("asked");
    storage
        .read_kept_audit(AuditId::new(found[0]))
        .expect("read")
        .expect("kept")
}

fn digest(content: &[u8]) -> [u8; 32] {
    let mut digest = StreamDigest::default();
    digest.update(content);
    digest.finish()
}

#[test]
fn an_audited_publish_carries_its_message_and_its_stream_s_bytes() {
    let storage = memory();
    let content = b"order 1, spelled out in its audit".to_vec();
    let kept = published(&storage, &content, 8);

    let audited = kept.audited.as_ref().expect("an act on a Message");
    let message = Message::from_record(&audited.message, |stream| {
        Chunks::referred(&storage, stream)
    })
    .expect("the Message in its one form");
    assert_eq!(message.generation(), 0, "as it was published");
    let ledger = storage
        .read_message(message.message_id())
        .expect("read")
        .expect("in the Ledger");
    assert_eq!(audited.message, ledger.body, "the Message as published");
    let stream = message.sections()[0].stream.id();
    assert_eq!(audited.streams, [stream], "its one Section's");
    let kept_stream = audited.kept(stream).expect("kept beside it");
    assert_eq!(kept_stream.digest, digest(&content));
    assert_eq!(kept_stream.length, content.len() as u64);
    let record = storage.read_stream(stream).expect("read");
    assert_eq!(
        Some(kept_stream),
        record.as_ref(),
        "taken from the Stream's own record"
    );

    let mut read = Vec::new();
    ChunkReader::audited(storage.as_ref(), &kept, stream)
        .expect("it carries the Stream")
        .read_to_end(&mut read)
        .expect("verified");
    assert_eq!(read, content);
}

#[test]
fn a_stream_larger_than_a_chunk_is_audited_in_chunks_of_its_own() {
    let storage = memory();
    let content: Vec<u8> = (0..CHUNK * 3 + 5)
        .map(|at| u8::try_from(at % 251).expect("below 251"))
        .collect();
    let kept = published(&storage, &content, CHUNK);
    let id = kept.id;
    let audited = kept.audited.as_ref().expect("an act on a Message");
    let stream = audited.streams[0];

    let last = storage.read_kept_audit_chunk(id, stream, 3).expect("read");
    assert_eq!(last.expect("a fourth chunk").bytes.len(), 5);
    let past = storage.read_kept_audit_chunk(id, stream, 4).expect("read");
    assert_eq!(past, None);
    let kept_stream = audited.kept(stream).expect("kept beside it");
    assert_eq!(kept_stream.digest, digest(&content));
    let mut read = Vec::new();
    ChunkReader::audited(storage.as_ref(), &kept, stream)
        .expect("it carries the Stream")
        .read_to_end(&mut read)
        .expect("verified");
    assert_eq!(read.len(), content.len());
    assert!(read == content, "the bytes as received");
}
