//! One read of a Stream lent to every departure reading it at once (open
//! problem 38): a fan-out's departures — one Journey for each Send Port a
//! Message is routed to, sent side by side — each read the same Stream.
//!
//! **Each chunk is read from Xmip Storage once, while the departures keep
//! up.** The first departure of a Stream on this node opens one read of it,
//! a chunk at a time and held to its length as every read of the Ledger is
//! (`persist::storage::ChunkReader`); every departure of the same Stream in
//! flight here takes each chunk from that read, the chunk itself lent, never
//! copied. Until 2026-10-19 each departure read the Message whole.
//!
//! **No departure waits for another.** The read keeps the last [`WINDOW`]
//! chunks it took, and no more than there are departures reading it — one
//! alone keeps only the chunk it holds; a departure further behind — its far end slower, its
//! send begun later, a kept session's exchange gone again from the start —
//! reads on from Xmip Storage itself, from the chunk where it stands, so a
//! slow Send Port never holds back the others (ADR-0018 clause 11, the
//! bulkhead) and what is held is bounded for each Stream, however many
//! departures read it.

use std::collections::{HashMap, VecDeque};
use std::io::{self, Read};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

use persist::storage::{ChunkReader, Chunked, XmipStorage};
use xcore::StreamId;

/// The chunks of one Stream kept for the departures reading behind the
/// first, where there are several: the last one read and the one before it.
pub const WINDOW: usize = 2;

/// The Streams this node's departures read now, each read once.
pub struct StreamShare {
    storage: Arc<dyn XmipStorage>,
    streams: Mutex<HashMap<StreamId, Weak<Shared>>>,
}

/// One Stream's read and the last chunks it took.
struct Shared {
    source: Mutex<Source>,
}

struct Source {
    reader: ChunkReader<'static>,
    window: VecDeque<Arc<Vec<u8>>>,
    /// The place in the Stream of the window's first chunk.
    first: u64,
    ended: bool,
    /// Why the read failed, said to every departure of it.
    failed: Option<(io::ErrorKind, String)>,
}

impl StreamShare {
    /// Reads of Streams kept in the Ledger behind `storage`.
    #[must_use]
    pub fn new(storage: Arc<dyn XmipStorage>) -> Self {
        Self {
            storage,
            streams: Mutex::default(),
        }
    }

    /// The Stream `stream`, `length` bytes as its record keeps, from its
    /// start: its chunks lent from the one read of it on this node while
    /// this reader keeps up, read from Xmip Storage itself once it falls
    /// behind.
    #[must_use]
    pub fn reader(&self, stream: StreamId, length: u64) -> Lent {
        let mut streams = lock(&self.streams);
        streams.retain(|_, shared| shared.strong_count() > 0);
        let shared = streams
            .get(&stream)
            .and_then(Weak::upgrade)
            .unwrap_or_else(|| {
                let reader = self.ledger(stream, length);
                let fresh = Arc::new(Shared {
                    source: Mutex::new(Source {
                        reader,
                        window: VecDeque::with_capacity(WINDOW + 1),
                        first: 0,
                        ended: false,
                        failed: None,
                    }),
                });
                streams.insert(stream, Arc::downgrade(&fresh));
                fresh
            });
        Lent {
            shared,
            storage: Arc::clone(&self.storage),
            stream,
            length,
            place: 0,
            held: None,
            at: 0,
            own: None,
        }
    }

    /// How many Streams are being read now.
    #[must_use]
    pub fn reading(&self) -> usize {
        lock(&self.streams)
            .values()
            .filter(|shared| shared.strong_count() > 0)
            .count()
    }

    fn ledger(&self, stream: StreamId, length: u64) -> ChunkReader<'static> {
        ChunkReader::shared(Arc::clone(&self.storage), Chunked::Ledger(stream), length)
    }
}

/// One departure's read of a Stream: the chunk it holds, lent, and its place.
pub struct Lent {
    shared: Arc<Shared>,
    storage: Arc<dyn XmipStorage>,
    stream: StreamId,
    length: u64,
    /// The place of the next chunk it takes.
    place: u64,
    held: Option<Arc<Vec<u8>>>,
    at: usize,
    /// Its own read, once it fell behind the window.
    own: Option<ChunkReader<'static>>,
}

/// What the shared read gives a reader for the chunk at its place.
enum Next {
    Chunk(Arc<Vec<u8>>),
    End,
    Behind,
}

impl Lent {
    fn next(&self) -> io::Result<Next> {
        let mut source = lock(&self.shared.source);
        if let Some((kind, why)) = &source.failed {
            return Err(io::Error::new(*kind, why.clone()));
        }
        let Some(offset) = self.place.checked_sub(source.first) else {
            return Ok(Next::Behind);
        };
        let offset = usize::try_from(offset).unwrap_or(usize::MAX);
        if let Some(chunk) = source.window.get(offset) {
            return Ok(Next::Chunk(Arc::clone(chunk)));
        }
        if source.ended {
            return Ok(Next::End);
        }
        match source.reader.next_chunk() {
            Ok(Some(chunk)) => {
                let chunk = Arc::new(chunk);
                source.window.push_back(Arc::clone(&chunk));
                // No more kept than there are readers to take it: one
                // reader alone keeps only the chunk it holds.
                let kept = WINDOW.min(Arc::strong_count(&self.shared)).max(1);
                while source.window.len() > kept {
                    source.window.pop_front();
                    source.first += 1;
                }
                Ok(Next::Chunk(chunk))
            }
            Ok(None) => {
                source.ended = true;
                Ok(Next::End)
            }
            Err(failed) => {
                source.failed = Some((failed.kind(), failed.to_string()));
                Err(failed)
            }
        }
    }

    /// A read of its own from Xmip Storage, past the chunks it has taken:
    /// what a reader fallen behind the window reads on from.
    fn caught_up(&self) -> io::Result<ChunkReader<'static>> {
        let mut own = ChunkReader::shared(
            Arc::clone(&self.storage),
            Chunked::Ledger(self.stream),
            self.length,
        );
        for _ in 0..self.place {
            if own.next_chunk()?.is_none() {
                break;
            }
        }
        Ok(own)
    }
}

impl Read for Lent {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            if let Some(own) = self.own.as_mut() {
                return own.read(out);
            }
            if let Some(held) = self.held.as_ref().filter(|held| self.at < held.len()) {
                let taken = out.len().min(held.len() - self.at);
                out[..taken].copy_from_slice(&held[self.at..self.at + taken]);
                self.at += taken;
                return Ok(taken);
            }
            self.held = None;
            match self.next()? {
                Next::Chunk(chunk) => {
                    (self.held, self.at) = (Some(chunk), 0);
                    self.place += 1;
                }
                Next::End => return Ok(0),
                Next::Behind => self.own = Some(self.caught_up()?),
            }
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use persist::storage::StreamChunk;

    /// A Stream of `chunks` chunks of `size` patterned bytes kept in
    /// `storage` as `stream`: its length.
    fn kept(storage: &dyn XmipStorage, stream: StreamId, chunks: u32, size: usize) -> u64 {
        for index in 0..chunks {
            let bytes = (0..size)
                .map(|at| u8::try_from((index as usize * size + at) % 251).unwrap_or_default())
                .collect();
            storage
                .write_chunk(&StreamChunk {
                    stream,
                    index,
                    bytes,
                })
                .expect("chunk");
        }
        u64::from(chunks) * size as u64
    }

    fn patterned(read: &[u8]) -> bool {
        read.iter()
            .enumerate()
            .all(|(at, byte)| usize::from(*byte) == at % 251)
    }

    #[test]
    fn readers_keeping_up_take_each_chunk_from_one_read() {
        let storage = Arc::clone(crate::ledger::in_memory());
        let stream = StreamId::new(0x5_0001);
        let length = kept(storage.as_ref(), stream, 6, 1000);
        let share = StreamShare::new(Arc::clone(&storage));
        let mut readers: Vec<Lent> = (0..4).map(|_| share.reader(stream, length)).collect();
        assert_eq!(share.reading(), 1, "one read of the Stream for all four");
        let mut read = vec![Vec::new(); 4];
        let mut piece = [0u8; 1000];
        // Side by side, a chunk each in turn, as a fan-out's sends go.
        for _ in 0..7 {
            for (reader, bytes) in readers.iter_mut().zip(&mut read) {
                let taken = reader.read(&mut piece).expect("read");
                bytes.extend_from_slice(&piece[..taken]);
            }
        }
        for bytes in &read {
            assert_eq!(bytes.len() as u64, length);
            assert!(patterned(bytes), "every byte, as kept");
        }
        assert!(
            readers.iter().all(|reader| reader.own.is_none()),
            "none read again"
        );
        let source = lock(&readers[0].shared.source);
        assert!(
            source.window.len() <= WINDOW,
            "{} chunks kept",
            source.window.len()
        );
        drop(source);
        drop(readers);
        assert_eq!(share.reading(), 0, "let go with its last reader");
    }

    #[test]
    fn a_reader_fallen_behind_reads_on_from_storage_and_misses_nothing() {
        let storage = Arc::clone(crate::ledger::in_memory());
        let stream = StreamId::new(0x5_0002);
        let length = kept(storage.as_ref(), stream, 8, 500);
        let share = StreamShare::new(Arc::clone(&storage));
        let mut ahead = share.reader(stream, length);
        let mut first = vec![0u8; 3 * 500];
        ahead.read_exact(&mut first).expect("three chunks ahead");
        let mut behind = share.reader(stream, length);
        let mut late = Vec::new();
        behind.read_to_end(&mut late).expect("read on");
        assert!(behind.own.is_some(), "it read on from Xmip Storage");
        assert_eq!(late.len() as u64, length);
        assert!(patterned(&late));
        let mut rest = Vec::new();
        ahead.read_to_end(&mut rest).expect("the rest");
        first.extend_from_slice(&rest);
        assert!(patterned(&first) && first.len() as u64 == length);
    }

    #[test]
    fn a_stream_not_as_kept_is_refused_to_every_reader_of_it() {
        let storage = Arc::clone(crate::ledger::in_memory());
        let stream = StreamId::new(0x5_0003);
        let length = kept(storage.as_ref(), stream, 2, 100);
        let share = StreamShare::new(Arc::clone(&storage));
        let (mut one, mut two) = (
            share.reader(stream, length + 1),
            share.reader(stream, length + 1),
        );
        let refused = one.read_to_end(&mut Vec::new()).expect_err("short");
        assert_eq!(refused.kind(), io::ErrorKind::InvalidData);
        let again = two.read_to_end(&mut Vec::new()).expect_err("the same");
        assert_eq!(again.kind(), io::ErrorKind::InvalidData);
    }
}
