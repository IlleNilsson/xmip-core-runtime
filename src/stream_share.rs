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
//! **What is held is bounded for each Stream.** A read keeps the last
//! chunks it took — one where a departure reads it alone, and
//! [`KEPT_PER_READER`] for each other departure reading it, the room each
//! one's own read of Xmip Storage would have held (`budget::STREAM_CHUNKS`).
//!
//! **One kept from its processor holds the one ahead back a while.**
//! Departures paced alike by their far ends never close a gap a stall
//! opened, so a departure about to let go of the chunk another of its read
//! is to take next waits for that one to take it — at most what the kept
//! chunks take the read to pass at its pace, over the whole Stream for each
//! departure waited for, so a slow Send Port holds the others back no
//! longer than that, once, and is then left behind (ADR-0018 clause 11, the
//! bulkhead; ADR-0018, amendment 2026-10-20).
//!
//! **A departure behind the kept chunks reads on from where it is, and
//! comes back.** One begun late, or whose far end is slower, asks Xmip
//! Storage for the chunks it missed, from the chunk it reached and never
//! from the Stream's start (`ChunkReader::shared_from`; the owner,
//! 2026-10-20: *a departure that falls behind starts reading at the chunk
//! it reached, catches up from Storage over only the chunks it missed, and
//! rejoins the shared read*) — from a read of its Stream that reaches its
//! place where there is one, a read of its own only where none does, which
//! the next behind takes from. Before each chunk a departure moves to a
//! read that reaches it and that more departures read, or as many and
//! opened before, so the reads of a Stream come together as their places
//! meet; one no departure takes from is let go.

mod one_read;

use std::collections::HashMap;
use std::io::{self, Read};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

use persist::storage::{ChunkReader, XmipStorage};
use xcore::StreamId;

use one_read::{Next, OneRead, leave};

/// The chunks kept for each departure beside the first reading one Stream:
/// the room its own read of Xmip Storage would have held, which a
/// departure taking lent chunks does not hold — `budget::STREAM_CHUNKS`,
/// but for the chunk it is lent.
pub const KEPT_PER_READER: usize = crate::budget::STREAM_CHUNKS as usize - 1;

/// The Streams this node's departures read now, each read once.
pub struct StreamShare {
    storage: Arc<dyn XmipStorage>,
    streams: Mutex<HashMap<StreamId, Weak<Shared>>>,
}

/// One Stream's reads on this node, in the order they were opened.
struct Shared {
    storage: Arc<dyn XmipStorage>,
    stream: StreamId,
    length: u64,
    reads: Mutex<Vec<Arc<OneRead>>>,
    /// The next departure's own number among them.
    numbered: AtomicU64,
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
    /// start: its chunks lent from a read of it on this node that reaches
    /// this reader's place, read from Xmip Storage from where it stands
    /// where none does.
    #[must_use]
    pub fn reader(&self, stream: StreamId, length: u64) -> Lent {
        let shared = {
            let mut streams = lock(&self.streams);
            streams.retain(|_, shared| shared.strong_count() > 0);
            streams
                .get(&stream)
                .and_then(Weak::upgrade)
                .unwrap_or_else(|| {
                    let fresh = Arc::new(Shared {
                        storage: Arc::clone(&self.storage),
                        stream,
                        length,
                        reads: Mutex::default(),
                        numbered: AtomicU64::new(0),
                    });
                    streams.insert(stream, Arc::downgrade(&fresh));
                    fresh
                })
        };
        let number = shared.numbered.fetch_add(1, Ordering::Relaxed);
        let read = shared.joined(None, number, (0, 0));
        Lent {
            shared,
            read,
            number,
            place: 0,
            taken: 0,
            held: None,
            at: 0,
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
}

impl Shared {
    /// The read departure `number` at `place`, `taken` bytes into the
    /// Stream, takes from, having left `left` where it fell behind: the one
    /// that reaches it and that the most departures read, the first opened
    /// of those, or one of its own opened from its place.
    fn joined(
        &self,
        left: Option<&Arc<OneRead>>,
        number: u64,
        (place, taken): (u64, u64),
    ) -> Arc<OneRead> {
        let mut reads = lock(&self.reads);
        if let Some(left) = left {
            leave(&mut reads, left, number);
        }
        let mut best: Option<(usize, Arc<OneRead>)> = None;
        for read in reads.iter() {
            let source = lock(&read.source);
            let readers = source.readers.len();
            if source.reaches(place) && best.as_ref().is_none_or(|(most, _)| readers > *most) {
                best = Some((readers, Arc::clone(read)));
            }
        }
        let read = best.map_or_else(
            || {
                let chunk = u32::try_from(place).unwrap_or(u32::MAX);
                let storage = Arc::clone(&self.storage);
                let from =
                    ChunkReader::shared_from(storage, self.stream, self.length, (chunk, taken));
                let opened = Arc::new(OneRead::opened(from, place));
                reads.push(Arc::clone(&opened));
                opened
            },
            |(_, read)| read,
        );
        lock(&read.source).join(number, place);
        read
    }

    /// The read departure `number` on `on` at `place` moves to before its
    /// next chunk: one that reaches it and that more departures read than
    /// `on` would without it, or as many and opened before it.
    fn moved(&self, on: &Arc<OneRead>, number: u64, place: u64) -> Option<Arc<OneRead>> {
        let mut reads = lock(&self.reads);
        if reads.len() < 2 {
            return None;
        }
        let mine = reads.iter().position(|read| Arc::ptr_eq(read, on))?;
        let others = lock(&on.source).readers.len().saturating_sub(1);
        let to = reads.iter().enumerate().find_map(|(at, read)| {
            if at == mine {
                return None;
            }
            // Asked, never waited on: a read taking a chunk from Xmip
            // Storage is passed over for now.
            let mut source = read.source.try_lock().ok()?;
            let readers = source.readers.len();
            let more = readers > others || (readers == others && at < mine);
            (more && source.reaches(place)).then(|| {
                source.join(number, place);
                Arc::clone(read)
            })
        })?;
        leave(&mut reads, on, number);
        Some(to)
    }
}

/// One departure's read of a Stream: the chunk it holds, lent, and its place.
pub struct Lent {
    shared: Arc<Shared>,
    read: Arc<OneRead>,
    /// Its own number among its Stream's departures.
    number: u64,
    /// The place of the next chunk it takes.
    place: u64,
    /// The bytes of the chunks it took.
    taken: u64,
    held: Option<Arc<Vec<u8>>>,
    at: usize,
}

impl Lent {
    /// The next chunk at its place, from the read that reaches it.
    fn take(&mut self) -> io::Result<Option<Arc<Vec<u8>>>> {
        if let Some(to) = self.shared.moved(&self.read, self.number, self.place) {
            self.read = to;
        }
        loop {
            match self.read.chunk(self.number, self.place)? {
                Next::Chunk(chunk) => return Ok(Some(chunk)),
                Next::End => return Ok(None),
                Next::Behind => {
                    if u32::try_from(self.place).is_err() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "a Stream past its chunks",
                        ));
                    }
                    let at = (self.place, self.taken);
                    self.read = self.shared.joined(Some(&self.read), self.number, at);
                }
            }
        }
    }
}

impl Read for Lent {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            if let Some(held) = self.held.as_ref().filter(|held| self.at < held.len()) {
                let taken = out.len().min(held.len() - self.at);
                out[..taken].copy_from_slice(&held[self.at..self.at + taken]);
                self.at += taken;
                return Ok(taken);
            }
            self.held = None;
            let Some(chunk) = self.take()? else {
                return Ok(0);
            };
            self.taken += chunk.len() as u64;
            self.place += 1;
            (self.held, self.at) = (Some(chunk), 0);
        }
    }
}

impl Drop for Lent {
    fn drop(&mut self) {
        leave(&mut lock(&self.shared.reads), &self.read, self.number);
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::{Failing, Operation};
    use persist::storage::StreamChunk;
    use std::time::{Duration, Instant};

    /// A Stream of `chunks` chunks of `size` patterned bytes kept in
    /// `storage` as `stream`: its length.
    fn kept_stream(storage: &dyn XmipStorage, stream: StreamId, chunks: u32, size: usize) -> u64 {
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

    /// Storage that counts the chunks asked of it, over a Stream of
    /// `chunks` chunks of `size` bytes: the share, the counter, the length.
    fn counted(stream: StreamId, chunks: u32, size: usize) -> (StreamShare, Arc<Failing>, u64) {
        let failing = Failing::over(Arc::clone(crate::ledger::in_memory()));
        let length = kept_stream(failing.as_ref(), stream, chunks, size);
        let storage: Arc<dyn XmipStorage> = failing.clone();
        (StreamShare::new(storage), failing, length)
    }

    /// How many reads of its Stream there are now.
    fn reads(lent: &Lent) -> usize {
        lock(&lent.shared.reads).len()
    }

    /// Whether it takes from the first opened of its Stream's reads now.
    fn on_first(lent: &Lent) -> bool {
        Arc::ptr_eq(&lock(&lent.shared.reads)[0], &lent.read)
    }

    #[test]
    fn readers_keeping_up_take_each_chunk_from_one_read() {
        let stream = StreamId::new(0x5_0001);
        let (share, failing, length) = counted(stream, 6, 1000);
        let mut readers: Vec<Lent> = (0..4).map(|_| share.reader(stream, length)).collect();
        assert_eq!(share.reading(), 1, "one Stream read for all four");
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
        assert!(readers.iter().all(|reader| reads(reader) == 1), "one read");
        // Each chunk once, and the one ask that finds the Stream's end.
        assert!(failing.asked_times(Operation::ReadChunk) <= 6 + 1);
        drop(readers);
        assert_eq!(share.reading(), 0, "let go with its last reader");
    }

    #[test]
    fn a_reader_alone_keeps_only_the_chunk_it_holds() {
        let stream = StreamId::new(0x5_0004);
        let (share, _, length) = counted(stream, 6, 1000);
        let mut alone = share.reader(stream, length);
        alone.read_exact(&mut [0u8; 3000]).expect("three chunks");
        assert_eq!(lock(&alone.read.source).window.len(), 1);
    }

    #[test]
    fn a_reader_fallen_behind_reads_only_what_it_missed_and_comes_back() {
        let stream = StreamId::new(0x5_0002);
        let chunks = 40;
        let (share, failing, length) = counted(stream, chunks, 500);
        let mut ahead = share.reader(stream, length);
        let mut behind = share.reader(stream, length);
        let mut piece = [0u8; 500];
        // Side by side for two chunks.
        let mut late = Vec::new();
        for _ in 0..2 {
            ahead.read_exact(&mut piece).expect("ahead");
            behind.read_exact(&mut piece).expect("behind");
            late.extend_from_slice(&piece);
        }
        // Then the one ahead goes on past what is kept for the other.
        for _ in 0..KEPT_PER_READER + 3 {
            ahead.read_exact(&mut piece).expect("ahead");
        }
        // The one behind reads what it missed from Xmip Storage, from where
        // it stands, until its place meets the first read again.
        let before = failing.asked_times(Operation::ReadChunk);
        let mut caught = 0;
        loop {
            behind.read_exact(&mut piece).expect("catching up");
            late.extend_from_slice(&piece);
            if on_first(&behind) && reads(&behind) == 1 {
                break;
            }
            caught += 1;
        }
        let by_itself = failing.asked_times(Operation::ReadChunk) - before;
        assert!(caught > 0, "it fell behind");
        assert_eq!(
            by_itself, caught,
            "{by_itself} chunks asked of Xmip Storage for the {caught} it missed"
        );
        // Back on the one read: side by side to the end, the one ahead a
        // few chunks ahead still.
        loop {
            let went = ahead.read(&mut piece).expect("ahead");
            let taken = behind.read(&mut piece).expect("behind");
            late.extend_from_slice(&piece[..taken]);
            assert_eq!(reads(&behind), 1, "it stays on the one read");
            if went + taken == 0 {
                break;
            }
        }
        assert_eq!(late.len() as u64, length);
        assert!(patterned(&late), "every byte, in its place");
        let asked = failing.asked_times(Operation::ReadChunk);
        assert!(
            asked <= u64::from(chunks) + 1 + by_itself,
            "the Stream once and what was missed once: {asked} asked"
        );
    }

    #[test]
    fn readers_fallen_behind_together_share_one_read_of_what_they_missed() {
        let stream = StreamId::new(0x5_0005);
        let chunks = 40;
        let (share, failing, length) = counted(stream, chunks, 500);
        let mut ahead = share.reader(stream, length);
        let mut behind: Vec<Lent> = (0..2).map(|_| share.reader(stream, length)).collect();
        let mut piece = [0u8; 500];
        let mut late = vec![Vec::new(); 2];
        for _ in 0..2 {
            ahead.read_exact(&mut piece).expect("ahead");
            for (reader, bytes) in behind.iter_mut().zip(&mut late) {
                reader.read_exact(&mut piece).expect("behind");
                bytes.extend_from_slice(&piece);
            }
        }
        // The one ahead goes on past all that is kept, to the end.
        ahead
            .read_to_end(&mut Vec::new())
            .expect("ahead to the end");
        // Both behind, side by side, from where they stand: one more read.
        loop {
            let mut went = 0;
            for (reader, bytes) in behind.iter_mut().zip(&mut late) {
                let taken = reader.read(&mut piece).expect("behind");
                bytes.extend_from_slice(&piece[..taken]);
                went += taken;
            }
            assert!(reads(&behind[0]) <= 2, "the two behind share one read");
            if went == 0 {
                break;
            }
        }
        for bytes in &late {
            assert_eq!(bytes.len() as u64, length);
            assert!(patterned(bytes), "every byte, in its place");
        }
        // The Stream once for the one ahead and once from chunk 2 for the
        // two behind, each read finding its end once: never three times.
        let asked = failing.asked_times(Operation::ReadChunk);
        let most = 2 * u64::from(chunks);
        assert!(asked <= most, "{asked} chunks asked, {most} at most");
    }

    #[test]
    fn a_reader_begun_late_and_the_one_ahead_of_it_come_together() {
        let stream = StreamId::new(0x5_0006);
        let chunks = 40;
        let (share, failing, length) = counted(stream, chunks, 500);
        let mut first = share.reader(stream, length);
        let mut piece = [0u8; 500];
        // Alone for three chunks, so it keeps only the one it holds.
        for _ in 0..3 {
            first.read_exact(&mut piece).expect("first");
        }
        let mut late = share.reader(stream, length);
        assert_eq!(
            reads(&late),
            2,
            "begun behind what is kept: a read of its own"
        );
        let mut taken = Vec::new();
        loop {
            let went = first.read(&mut piece).expect("first");
            let got = late.read(&mut piece).expect("late");
            taken.extend_from_slice(&piece[..got]);
            if went + got == 0 {
                break;
            }
        }
        assert_eq!(taken.len() as u64, length);
        assert!(patterned(&taken), "every byte, in its place");
        assert_eq!(reads(&late), 1, "the two on one read");
        // The three chunks the first took alone, read once more.
        let asked = failing.asked_times(Operation::ReadChunk);
        assert!(asked <= u64::from(chunks) + 3 + 1, "{asked} chunks asked");
    }

    #[test]
    fn one_kept_from_its_processor_a_while_holds_the_one_ahead_back_and_nothing_is_read_twice() {
        use xcore::latency::spin;
        let stream = StreamId::new(0x5_0007);
        let chunks = 24;
        let (share, failing, length) = counted(stream, chunks, 500);
        // The read's first chunk slow to come, as from a Storage node across
        // a network, so its pace makes the kept chunks worth some hundreds
        // of milliseconds: the one behind may be kept from its processor
        // that long by the machine and still not be left behind.
        failing.before(
            Operation::ReadChunk,
            Box::new(|| std::thread::sleep(Duration::from_millis(500))),
        );
        let pace = Duration::from_millis(2);
        let (mut ahead, mut behind) = (share.reader(stream, length), share.reader(stream, length));
        let went = AtomicU64::new(0);
        let mut piece = [0u8; 500];
        behind.read_exact(&mut piece).expect("its first chunk");
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let mut piece = [0u8; 500];
                while ahead.read(&mut piece).expect("ahead") > 0 {
                    went.fetch_add(1, Ordering::Release);
                    spin(pace);
                }
            });
            // Kept from its processor until the one ahead has gone as far as
            // the kept chunks let it, and longer than a chunk takes it.
            let most = 1 + KEPT_PER_READER as u64;
            while went.load(Ordering::Acquire) < most {
                spin(pace / 10);
            }
            spin(2 * pace);
            assert_eq!(
                went.load(Ordering::Acquire),
                most,
                "held back for the one behind"
            );
            while behind.read(&mut piece).expect("behind") > 0 {
                spin(pace);
            }
        });
        let asked = failing.asked_times(Operation::ReadChunk);
        assert!(
            asked <= u64::from(chunks) + 1,
            "each chunk once: {asked} asked"
        );
    }

    #[test]
    fn one_that_stops_taking_holds_the_one_ahead_back_only_for_the_time_kept() {
        use xcore::latency::spin;
        let stream = StreamId::new(0x5_0008);
        let chunks = 24;
        let (share, _, length) = counted(stream, chunks, 500);
        let pace = Duration::from_millis(1);
        let (mut ahead, mut stopped) = (share.reader(stream, length), share.reader(stream, length));
        let mut piece = [0u8; 500];
        stopped.read_exact(&mut piece).expect("its first chunk");
        // The one whose far end stopped takes nothing more; the one ahead
        // goes to the end, held back for it no longer than the kept chunks
        // take the read to pass.
        let (began, mut went) = (Instant::now(), 0);
        while ahead.read(&mut piece).expect("ahead") > 0 {
            went += 1;
            spin(pace);
        }
        assert_eq!(went, chunks, "the one ahead took every chunk");
        assert!(
            began.elapsed() < Duration::from_secs(5),
            "never held for good"
        );
        assert_eq!(
            lock(&stopped.read.source).readers.len(),
            2,
            "the one stopped still on the read, left behind"
        );
    }

    #[test]
    fn a_stream_not_as_kept_is_refused_to_every_reader_of_it() {
        let storage = Arc::clone(crate::ledger::in_memory());
        let stream = StreamId::new(0x5_0003);
        let length = kept_stream(storage.as_ref(), stream, 2, 100);
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
