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

use persist::storage::{StreamChunk, XmipStorage};
use stream::{Content, Stream};
use xcore::StreamId;

mod publication;

pub(crate) use publication::opened;
pub use publication::{Published, Publisher, publish};

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
    /// How many chunks it was written in; one at least, the last saying so.
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
            Arc::new(Chunks::of(Arc::clone(storage), self.stream)),
        )
    }
}

/// A Stream's content as the Ledger keeps it: its chunks, read back one at
/// a time through Xmip Storage.
pub struct Chunks {
    storage: Arc<dyn XmipStorage>,
    stream: StreamId,
}

impl Chunks {
    /// The chunks of `stream` behind `storage`.
    #[must_use]
    pub fn of(storage: Arc<dyn XmipStorage>, stream: StreamId) -> Self {
        Self { storage, stream }
    }
}

impl Content for Chunks {
    fn reader(&self) -> io::Result<Box<dyn Read + Send + '_>> {
        Ok(Box::new(ChunkReader {
            chunks: self,
            next: 0,
            held: Vec::new(),
            at: 0,
            ended: false,
        }))
    }
}

/// Reading a Stream's chunks in order: one held at a time.
struct ChunkReader<'a> {
    chunks: &'a Chunks,
    next: u32,
    held: Vec<u8>,
    at: usize,
    ended: bool,
}

impl Read for ChunkReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        while self.at == self.held.len() {
            if self.ended {
                return Ok(0);
            }
            let (stream, index) = (self.chunks.stream, self.next);
            let chunk = self
                .chunks
                .storage
                .read_chunk(stream, index)
                .map_err(io::Error::other)?
                .ok_or_else(|| {
                    io::Error::other(format!("the Stream {stream} has no chunk {index}"))
                })?;
            (self.held, self.at, self.ended) = (chunk.bytes, 0, chunk.last);
            self.next += 1;
        }
        let taken = out.len().min(self.held.len() - self.at);
        out[..taken].copy_from_slice(&self.held[self.at..self.at + taken]);
        self.at += taken;
        Ok(taken)
    }
}

/// Write the Stream `content` gives into the Ledger as `stream`, in chunks
/// of `chunk` bytes, each written before the next is read and durable with
/// the Publication that follows ([`publish`]): never more of it in memory
/// than the chunk being written and the one read ahead to
/// know whether it is the last. An empty Stream is one empty last chunk.
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
    let mut pending = fill(content, chunk)?;
    loop {
        let next = if pending.len() < chunk {
            None
        } else {
            Some(fill(content, chunk)?).filter(|next| !next.is_empty())
        };
        kept.length += pending.len() as u64;
        let written = StreamChunk {
            stream,
            index: kept.chunks,
            last: next.is_none(),
            bytes: pending,
        };
        storage
            .write_chunk(&written)
            .map_err(|failed| format!("Xmip Storage did not take the Stream {stream}: {failed}"))?;
        kept.chunks += 1;
        match next {
            Some(next) => pending = next,
            None => return Ok(kept),
        }
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
    fn a_stream_is_written_in_chunks_the_last_saying_so() {
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
                assert_eq!(written.last, index + 1 == chunks, "{chunk}: {index}");
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
    fn an_empty_stream_is_one_empty_last_chunk() {
        let storage = storage();
        let stream = StreamId::new(1);
        let kept = write_stream(storage, stream, &mut [].as_slice(), 4096).expect("written");
        assert_eq!((kept.length, kept.chunks), (0, 1));
        let only = storage.read_chunk(stream, 0).expect("read").expect("there");
        assert!(only.last && only.bytes.is_empty());
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
