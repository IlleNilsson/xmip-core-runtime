//! The receive path's writes to the Ledger, through Xmip Storage
//! (`runtime-model.md` section 5, *How a receive runs*):
//!
//! ```text
//! transport identification, authentication, authorization
//!                          refused: nothing is kept
//! -> the Stream into the Ledger, in chunks     [`write_stream`]
//! -> Message creation ... Validation
//! -> Publication           the Message record, its Journeys, the ones a
//!                          paused Subscription holds, the rest in their
//!                          Send Ports' queues with this node's claims —
//!                          or, where nothing matched, its Dead Message
//!                          Queue entry — audited, as one write [`publish`]
//! -> acknowledgement       and the send step takes it from there
//!                          (`crate::send_step`)
//! ```
//!
//! **One sync per receive cycle, and nothing acknowledged before it** (the
//! owner, 2026-10-01: *Safe way*): the Stream's chunks are written unsynced
//! (`XmipStorage::write_chunk`), and the Publication's one durable write
//! makes them durable with it, so a receive cycle reported finished has its
//! Stream, its Message and its Journeys in the Ledger. A crash before the
//! Publication leaves at most chunks no Message refers to, and the sender,
//! never acknowledged, sends again (`runtime-model.md` section 3).
//!
//! **A Stream is written in chunks, never whole in memory** (the owner,
//! 2026-10-01), each a whole number of TCP segments ([`CHUNK`]; the owner,
//! 2026-10-03). [`write_stream`] reads from a [`Read`], so a transport that
//! streams hands its reader and the Stream is never whole here; one that
//! gives bytes hands them as a reader over a slice. What is written is
//! read back the same way: [`Kept::stream`] is the Stream kept in the
//! Ledger, its content [`Chunks`] read a chunk at a time, so Message
//! creation and every gate after it hold no more of it than they read.

use std::io::{self, Read};
use std::sync::Arc;

use codec::CodecError;
use persist::storage::{
    ChunkReader, Chunked, StreamChunk, StreamDigest, StreamRecord, XmipStorage,
};
use stream::{Content, Stream};
use xcore::StreamId;

mod publication;
mod record;

pub(crate) use publication::opened;
pub use publication::{Opened, Published, Publisher, publish};
pub(crate) use record::{audit_entry, audited, journey_record, message_record};

/// The TCP segments one chunk holds: 44 of them, 64,240 bytes, just under
/// TCP's classic 64 KiB window, so a Stream in flight holds about 128 KiB —
/// the chunk it writes and the one it reads ahead — whatever the machine
/// (the owner, 2026-10-03: *Do it fixed*).
pub const SEGMENTS: usize = 44;
/// The size a Stream is written to the Ledger in: [`SEGMENTS`] TCP
/// segments (`transport::TCP_SEGMENT`).
pub const CHUNK: usize = SEGMENTS * transport::TCP_SEGMENT;

/// What the Ledger holds of a Stream once [`write_stream`] has written it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Kept {
    pub stream: StreamId,
    /// Its length, in bytes.
    pub length: u64,
    /// How many chunks it was written in; one at least, an empty Stream one
    /// empty chunk.
    pub chunks: u32,
}

impl Kept {
    /// The Stream it is: kept in the Ledger behind `storage`, read back a
    /// chunk at a time, never whole until a gate asks for it whole.
    #[must_use]
    pub fn stream(&self, storage: &Arc<dyn XmipStorage>, media_type: Option<String>) -> Stream {
        Stream::kept(
            self.stream,
            self.length,
            media_type,
            Arc::new(Chunks::of(Arc::clone(storage), self.stream, self.length)),
        )
    }
}

/// A Stream's content as the Ledger keeps it: its chunks, read back one at
/// a time through Xmip Storage, up to the first it has not — where the
/// Stream ends (the owner, 2026-10-09) — and held to the length its own
/// record keeps (`XmipStorage::read_stream`): a chunk lost after
/// Publication, damaged or deleted, is refused in words, never read as a
/// shorter Stream. The reading is Xmip Storage's one chunk reader
/// (`persist::storage::ChunkReader`).
pub struct Chunks {
    storage: Arc<dyn XmipStorage>,
    stream: StreamId,
    length: u64,
}

impl Chunks {
    /// The chunks of `stream` behind `storage`, `length` bytes together.
    #[must_use]
    pub fn of(storage: Arc<dyn XmipStorage>, stream: StreamId, length: u64) -> Self {
        Self {
            storage,
            stream,
            length,
        }
    }

    /// The Stream `stream` as a Message record read back refers to it
    /// (`message::Message::from_record`): its length, from its own record
    /// — the one home of it — and its chunks behind `storage`.
    ///
    /// # Errors
    ///
    /// In words, where its record cannot be read or the Ledger holds none.
    pub fn referred(
        storage: &Arc<dyn XmipStorage>,
        stream: StreamId,
    ) -> Result<(u64, Arc<dyn Content>), CodecError> {
        let record = storage
            .read_stream(stream)
            .map_err(|failed| CodecError::new(format!("the Stream {stream}: {failed}")))?
            .ok_or_else(|| CodecError::new(format!("the Ledger holds no Stream {stream}")))?;
        let chunks = Self::of(Arc::clone(storage), stream, record.length);
        Ok((record.length, Arc::new(chunks)))
    }
}

impl Content for Chunks {
    fn reader(&self) -> io::Result<Box<dyn Read + Send + '_>> {
        let from = Chunked::Ledger(self.stream);
        Ok(Box::new(ChunkReader::new(
            self.storage.as_ref(),
            from,
            self.length,
        )))
    }
}

/// Write the Stream `content` gives into the Ledger as `stream`, in chunks
/// of `chunk` bytes, each written before the next is read and durable with
/// the Publication that follows ([`publish`]): never more of it in memory
/// than the chunk being written and the one read ahead to know whether
/// there is more. The Stream ends where it has no further chunk; its last
/// chunk goes with its own record, the one home of its length, its chunks
/// and the SHA-256 of its bytes — taken here as they pass, once (ADR-0070)
/// — which every Message referring to it refers to
/// (`XmipStorage::write_stream`). An empty Stream is one empty chunk.
///
/// # Errors
///
/// In words, where `content` cannot be read or Xmip Storage did not take a
/// chunk: the receive cycle has failed, and the sender is not
/// acknowledged.
pub fn write_stream(
    storage: &dyn XmipStorage,
    stream: StreamId,
    content: &mut dyn Read,
    chunk: usize,
) -> Result<Kept, String> {
    let chunk = chunk.max(1);
    let mut kept = Kept {
        stream,
        length: 0,
        chunks: 0,
    };
    let mut digest = StreamDigest::default();
    let mut pending = fill(content, chunk)?;
    loop {
        let next = if pending.len() < chunk {
            None
        } else {
            Some(fill(content, chunk)?).filter(|next| !next.is_empty())
        };
        kept.length += pending.len() as u64;
        digest.update(&pending);
        let written = StreamChunk {
            stream,
            index: kept.chunks,
            bytes: pending,
        };
        let refused = |failed| format!("Xmip Storage did not take the Stream {stream}: {failed}");
        kept.chunks += 1;
        let Some(next) = next else {
            // The last chunk, and the Stream's own record with it: the one
            // home of its length and its digest
            // (`persist::storage::StreamRecord`).
            let ended = StreamRecord {
                stream,
                length: kept.length,
                chunks: kept.chunks,
                digest: digest.finish(),
                written_unix_nanos: 0,
            };
            storage.write_stream(&written, &ended).map_err(refused)?;
            return Ok(kept);
        };
        storage.write_chunk(&written).map_err(refused)?;
        pending = next;
    }
}

/// Up to `chunk` bytes of `content`: fewer only at its end. Held as they
/// come, never set aside ahead of what arrived — a small Stream costs its
/// size, not a chunk.
fn fill(content: &mut dyn Read, chunk: usize) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    content
        .take(chunk as u64)
        .read_to_end(&mut bytes)
        .map_err(|failed| format!("the Stream could not be read: {failed}"))?;
    Ok(bytes)
}

/// Xmip Storage in this process's memory, sealed under a key held in
/// memory, for a test's Runtime to borrow for the test's length.
#[cfg(test)]
pub(crate) fn in_memory() -> &'static Arc<dyn XmipStorage> {
    use persist::fixture::Memory;
    let keys = secret::Held::new(secret::fixture::Memory::default());
    let kek = secret::KekName::new(crate::storage::KEK).expect("a name");
    let storage =
        persist::storage::Embedded::open(Memory::default(), Memory::default(), &keys, &kek)
            .expect("opened");
    let storage: Arc<dyn XmipStorage> = Arc::new(storage);
    Box::leak(Box::new(storage))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn storage() -> &'static dyn XmipStorage {
        in_memory().as_ref()
    }

    #[test]
    fn the_chunk_is_a_whole_number_of_tcp_segments() {
        assert_eq!(CHUNK, 64_240);
        assert_eq!(CHUNK % transport::TCP_SEGMENT, 0);
    }

    #[test]
    fn a_stream_is_written_in_chunks_and_ends_where_none_follows() {
        let storage = storage();
        let content: Vec<u8> = (0..10_000u32).map(|n| (n % 251) as u8).collect();
        for (chunk, chunks) in [(4096, 3), (5000, 2), (10_000, 1), (20_000, 1)] {
            let stream = StreamId::new(chunk as u128);
            let kept =
                write_stream(storage, stream, &mut content.as_slice(), chunk).expect("written");
            assert_eq!(
                kept,
                Kept {
                    stream,
                    length: 10_000,
                    chunks
                }
            );
            let mut read = Vec::new();
            for index in 0..chunks {
                let written = storage
                    .read_chunk(stream, index)
                    .expect("read")
                    .expect("there");
                read.extend(written.bytes);
            }
            assert_eq!(read, content, "{chunk}");
            assert!(storage.read_chunk(stream, chunks).expect("read").is_none());
        }
    }

    #[test]
    fn a_kept_stream_reads_back_a_chunk_at_a_time() {
        let storage = in_memory();
        let content: Vec<u8> = (0..10_000u32).map(|n| (n % 251) as u8).collect();
        let kept = write_stream(
            storage.as_ref(),
            StreamId::new(7),
            &mut content.as_slice(),
            4096,
        )
        .expect("written");
        let stream = kept.stream(storage, None);
        assert_eq!(stream.len(), 10_000);
        let mut piece = vec![0u8; 5000];
        stream
            .reader()
            .expect("a reader")
            .read_exact(&mut piece)
            .expect("across chunks");
        assert_eq!(piece, content[..5000]);
        assert_eq!(stream.load().expect("whole"), content.as_slice());
        let missing = Kept {
            stream: StreamId::new(8),
            length: 3,
            chunks: 1,
        }
        .stream(storage, None);
        assert!(missing.load().is_err(), "a Stream the Ledger does not hold");
    }

    #[test]
    fn a_stream_s_record_keeps_the_sha_256_of_its_bytes_taken_as_they_passed() {
        let storage = storage();
        let stream = StreamId::new(40);
        write_stream(storage, stream, &mut b"abc".as_slice(), 1).expect("written");
        let kept = storage.read_stream(stream).expect("read").expect("there");
        assert_eq!(kept.chunks, 3, "a chunk a byte");
        assert_eq!(
            codec::hex::encode(&kept.digest),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn an_empty_stream_is_one_empty_chunk() {
        let kept_in = in_memory();
        let storage = kept_in.as_ref();
        let stream = StreamId::new(1);
        let kept = write_stream(storage, stream, &mut [].as_slice(), 4096).expect("written");
        assert_eq!((kept.length, kept.chunks), (0, 1));
        let only = storage.read_chunk(stream, 0).expect("read").expect("there");
        assert!(only.bytes.is_empty());
        assert!(storage.read_chunk(stream, 1).expect("read").is_none());
        let kept = kept.stream(kept_in, None);
        assert_eq!(kept.load().expect("read back"), b"");
    }

    #[test]
    fn a_chunk_lost_after_publication_is_refused_in_words() {
        let storage = in_memory();
        let content: Vec<u8> = (0..10_000u32).map(|n| (n % 251) as u8).collect();
        let whole = StreamId::new(20);
        let kept =
            write_stream(storage.as_ref(), whole, &mut content.as_slice(), 4096).expect("written");
        assert_eq!(kept.chunks, 3);
        // The same Stream kept again without one of its chunks: the middle
        // one, and the last.
        for (lost, at) in [(1u32, 21u128), (2, 22)] {
            let stream = StreamId::new(at);
            for index in (0..kept.chunks).filter(|index| *index != lost) {
                let mut chunk = storage
                    .read_chunk(whole, index)
                    .expect("read")
                    .expect("there");
                chunk.stream = stream;
                storage.write_chunk(&chunk).expect("copied");
            }
            let short = Kept { stream, ..kept }.stream(storage, None);
            let refused = short.load().expect_err("a chunk is gone");
            let mut read = Vec::new();
            let streamed = short
                .reader()
                .expect("a reader")
                .read_to_end(&mut read)
                .expect_err("a chunk is gone, read in pieces");
            for why in [refused.to_string(), streamed.to_string()] {
                assert!(why.contains("a chunk was lost or damaged"), "{why}");
            }
        }
        assert_eq!(kept.stream(storage, None).load().expect("whole"), content);
    }

    #[test]
    fn two_messages_refer_to_one_stream_written_once_and_both_read_it_whole() {
        use message::{Message, MessageSection, MessageTreatment};
        use xcore::{MessageId, SectionId};
        let storage = in_memory();
        let content: Vec<u8> = (0..10_000u32).map(|n| (n % 251) as u8).collect();
        let stream = StreamId::new(30);
        let kept =
            write_stream(storage.as_ref(), stream, &mut content.as_slice(), 4096).expect("written");
        let written = storage
            .read_stream(stream)
            .expect("read")
            .expect("its record");
        assert_eq!((written.length, written.chunks), (10_000, 3));
        let section = MessageSection {
            section_id: SectionId::new(1),
            name: None,
            stream: kept.stream(storage, None),
            contract: None,
        };
        let received = Message::received(
            MessageId::new(31),
            vec![section],
            context::MessageContext::new(),
            MessageTreatment::default(),
        );
        // A Message assigned from it refers to the same Stream.
        let assigned = received.assigned(MessageId::new(32), context::MessageContext::new());
        for message in [&received, &assigned] {
            storage
                .write_message(&record::message_record(message))
                .expect("written");
        }
        let again = storage.read_stream(stream).expect("read");
        assert_eq!(again, Some(written), "one record, written once");
        for id in [31, 32] {
            let kept = storage
                .read_message(MessageId::new(id))
                .expect("read")
                .expect("there");
            let read = Message::from_record(&kept.body, |stream| Chunks::referred(storage, stream))
                .expect("read back");
            let section = &read.sections()[0].stream;
            assert_eq!(section.id(), stream);
            assert_eq!(section.load().expect("whole"), content.as_slice());
        }
    }
    #[test]
    fn a_stream_that_cannot_be_read_is_said_in_words() {
        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("the connection broke"))
            }
        }
        let refused =
            write_stream(storage(), StreamId::new(1), &mut Broken, 4096).expect_err("unreadable");
        assert!(refused.contains("the connection broke"), "{refused}");
    }
}
