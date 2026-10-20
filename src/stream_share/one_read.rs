//! One read of a Stream from Xmip Storage, the last chunks it took, and
//! the departures taking from it (`super`): what it keeps for them, which
//! departure one more may join it at, and how long one ahead is held back
//! for one about to be left behind.

use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use persist::storage::ChunkReader;
use xcore::wake::Wake;

use super::{KEPT_PER_READER, lock};

/// One read of Xmip Storage and the last chunks it took, and the word a
/// departure held back waits on.
pub(super) struct OneRead {
    pub(super) source: Mutex<Source>,
    took: Wake,
}

pub(super) struct Source {
    reader: ChunkReader<'static>,
    pub(super) window: VecDeque<Arc<Vec<u8>>>,
    /// The place in the Stream of the window's first chunk; the read's
    /// next is the window's end, `first + window.len()`.
    first: u64,
    ended: bool,
    /// Why the read failed, said to every departure of it.
    failed: Option<(io::ErrorKind, String)>,
    /// The departures taking from it.
    pub(super) readers: Vec<Reader>,
    /// When it began its first chunk from Xmip Storage, and how many it
    /// took since: its pace.
    paced: Option<(Instant, u32)>,
}

/// A departure taking from a read: its number, the place of the next chunk
/// it takes, and how long departures ahead of it were held back for it.
pub(super) struct Reader {
    number: u64,
    next: u64,
    waited: Duration,
}

/// What a read gives a departure for the chunk at its place.
pub(super) enum Next {
    Chunk(Arc<Vec<u8>>),
    End,
    Behind,
}

/// The chunks a read keeps while `readers` departures take from it: the
/// one lent where one does, and [`KEPT_PER_READER`] for each other.
fn kept(readers: usize) -> usize {
    (KEPT_PER_READER * readers.saturating_sub(1)).max(1)
}

impl Source {
    /// Whether one more departure, at `place`, may take from this read: a
    /// chunk it keeps, the next it takes, or one ahead it reads on to
    /// while what it keeps for the rest stays within what it may keep.
    pub(super) fn reaches(&self, place: u64) -> bool {
        let Some(ahead) = place.checked_sub(self.first) else {
            return false;
        };
        self.failed.is_none()
            && (ahead <= self.window.len() as u64 || ahead < kept(self.readers.len() + 1) as u64)
    }

    /// Departure `number` taking from it from `place` on.
    pub(super) fn join(&mut self, number: u64, place: u64) {
        let waited = Duration::ZERO;
        self.readers.push(Reader {
            number,
            next: place,
            waited,
        });
    }

    /// The departure the next chunk would leave behind — whose next is the
    /// first kept, with the read keeping all it may — and how much longer
    /// a departure ahead may be held back for it: what the chunks kept
    /// take the read to pass at its pace, over the whole Stream.
    fn behind(&self) -> Option<(u64, Duration)> {
        let (began, read) = self.paced?;
        if self.window.len() < kept(self.readers.len()) || read == 0 {
            return None;
        }
        let worth = began.elapsed() / read * u32::try_from(self.window.len()).ok()?;
        let reader = self
            .readers
            .iter()
            .find(|reader| reader.next == self.first)?;
        let left = worth.checked_sub(reader.waited)?;
        (!left.is_zero()).then_some((reader.number, left))
    }

    fn reader(&mut self, number: u64) -> Option<&mut Reader> {
        self.readers
            .iter_mut()
            .find(|reader| reader.number == number)
    }
}

impl OneRead {
    /// `reader`, read on from `place`, its chunk next.
    pub(super) fn opened(reader: ChunkReader<'static>, place: u64) -> Self {
        Self {
            source: Mutex::new(Source {
                reader,
                window: VecDeque::new(),
                first: place,
                ended: false,
                failed: None,
                readers: Vec::new(),
                paced: None,
            }),
            took: Wake::new(),
        }
    }

    /// The chunk at `place` for departure `number`: kept, or read on to —
    /// the chunks between kept for those behind it, and the next held back
    /// while one of them is about to take the first kept and may still be
    /// waited for ([`Source::behind`]).
    pub(super) fn chunk(&self, number: u64, place: u64) -> io::Result<Next> {
        let mut source = lock(&self.source);
        loop {
            if let Some((kind, why)) = &source.failed {
                return Err(io::Error::new(*kind, why.clone()));
            }
            let Some(ahead) = place.checked_sub(source.first) else {
                return Ok(Next::Behind);
            };
            let ahead = usize::try_from(ahead).unwrap_or(usize::MAX);
            if let Some(chunk) = source.window.get(ahead).map(Arc::clone) {
                if let Some(me) = source.reader(number) {
                    me.next = place + 1;
                }
                drop(source);
                self.took.notify_all();
                return Ok(Next::Chunk(chunk));
            }
            if source.ended {
                return Ok(Next::End);
            }
            if let Some((behind, left)) = source.behind() {
                let began = Instant::now();
                source = self.took.wait_timeout(&self.source, source, left).0;
                if let Some(behind) = source.reader(behind) {
                    behind.waited += began.elapsed();
                }
                continue;
            }
            let (began, read) = source.paced.unwrap_or((Instant::now(), 0));
            match source.reader.next_chunk() {
                Ok(Some(chunk)) => {
                    source.paced = Some((began, read + 1));
                    source.window.push_back(Arc::new(chunk));
                    while source.window.len() > kept(source.readers.len()) {
                        source.window.pop_front();
                        source.first += 1;
                    }
                }
                Ok(None) => source.ended = true,
                Err(failed) => {
                    source.failed = Some((failed.kind(), failed.to_string()));
                    return Err(failed);
                }
            }
        }
    }
}

/// Departure `number` gone from `read`, which is let go from `reads` once
/// none takes from it; one held back for it goes on.
pub(super) fn leave(reads: &mut Vec<Arc<OneRead>>, read: &Arc<OneRead>, number: u64) {
    let mut source = lock(&read.source);
    source.readers.retain(|reader| reader.number != number);
    let none = source.readers.is_empty();
    drop(source);
    read.took.notify_all();
    if none {
        reads.retain(|kept| !Arc::ptr_eq(kept, read));
    }
}
