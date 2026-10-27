//! Debatching, placed once: a Message split into a Message per record by a
//! splitting unit, fed its bytes a chunk at a time and answering each record
//! as soon as it is complete.
//!
//! ADR-0031, amendments 2026-10-22 and 2026-10-27: debatching runs in the
//! receive and in an Xmip Work Process, *one splitting implementation,
//! placed once, called from both*; and a debatch is all or nothing (the
//! owner, 2026-10-27: *If one fails, they all fail*), its records in the
//! order they had in the inbound Stream or Message. So each record is
//! written into the Ledger as a Stream of its own as soon as it is complete
//! — memory stays bounded by a record — and made a Message only once every
//! record is split ([`parts`]): the next generation of the Message split
//! (`message::Message::debatched`), carrying its context and the values that
//! keep the records together ([`BATCH`], [`POSITION`], [`COUNT`]; the owner,
//! 2026-10-27, on Spring Integration's `correlationId`, `sequenceNumber` and
//! `sequenceSize`, with no flag for the last), so a Work Process can take
//! them up together. A record the unit refuses does not end the splitting:
//! every record is still split and every failure gathered with its position
//! (`xcore::Failures`; the owner, 2026-10-27: *Failures … shall be
//! accumulated. The caller shall get a summary and detailed information of
//! what failed*), nothing more is written once one failed, and nothing is
//! made: the split fails once, its summary — how many records, how many
//! failed — followed by each.

use std::io::Read;
use std::sync::Arc;

use message::{Message, MessageSection};
use persist::storage::XmipStorage;
use xcore::{Failures, IdGenerator, MessageId, ScalarValue, SectionId, StreamId};

/// The stage a debatch reports its failures as.
pub const STAGE: &str = "debatch";

/// What one of a debatch's items is called.
pub const ITEM: &str = "record";

use crate::ledger::write_stream;

/// The context value naming the Message a record was split from — a draft
/// name, the owner's to decide.
pub const BATCH: &str = "debatch.message";

/// The context value giving a record's position in the Message it was split
/// from, from one — a draft name, the owner's to decide.
pub const POSITION: &str = "debatch.position";

/// The context value giving how many records the Message was split into — a
/// draft name, the owner's to decide.
pub const COUNT: &str = "debatch.count";

/// One record a [`Split`] found complete.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Record {
    /// A record's bytes: the content of a Message of its own.
    Part(Vec<u8>),
    /// A record the unit could not read, and why, in words.
    Refused(String),
}

/// What a splitting unit is to the node: handed a Message's bytes a chunk
/// at a time, in order, it answers every record as soon as it is complete,
/// and what is left once the bytes end.
pub trait Split: Send {
    /// `chunk`, the next of the bytes: each record it completes added to
    /// `records`, in order.
    fn feed(&mut self, chunk: &[u8], records: &mut Vec<Record>);

    /// The bytes ended: what remains added to `records` — a last record,
    /// or a refusal of an incomplete one.
    fn end(&mut self, records: &mut Vec<Record>);
}

/// The splitting of one Message's bytes: each record written into the
/// Ledger as a Stream of its own as `split` completes it while none has
/// failed, every failure gathered.
pub struct Splitting<'a> {
    storage: &'a Arc<dyn XmipStorage>,
    ids: &'a dyn IdGenerator,
    chunk: usize,
    split: &'a mut dyn Split,
    records: Vec<Record>,
    written: Vec<MessageSection>,
    failures: Failures,
}

impl<'a> Splitting<'a> {
    /// A splitting by `split`, each record's Stream written to `storage` in
    /// chunks of `chunk` bytes, its identifiers taken from `ids`.
    pub fn new(
        (storage, ids, chunk): (&'a Arc<dyn XmipStorage>, &'a dyn IdGenerator, usize),
        split: &'a mut dyn Split,
    ) -> Self {
        Self {
            storage,
            ids,
            chunk: chunk.max(1),
            split,
            records: Vec::new(),
            written: Vec::new(),
            failures: Failures::new(STAGE, ITEM),
        }
    }

    /// `chunk`, the next of the bytes: every record it completes written,
    /// in order, while none has failed; each failure gathered.
    ///
    /// # Errors
    /// A record's Stream Xmip Storage did not take.
    pub fn feed(&mut self, chunk: &[u8]) -> Result<(), String> {
        self.split.feed(chunk, &mut self.records);
        self.write()
    }

    /// The bytes ended: every record written as its Section, in the order
    /// found — or, where any failed, every failure.
    ///
    /// # Errors
    /// As [`Splitting::feed`].
    pub fn end(mut self) -> Result<Result<Vec<MessageSection>, Failures>, String> {
        self.split.end(&mut self.records);
        self.write()?;
        if self.failures.is_empty() {
            Ok(Ok(self.written))
        } else {
            Ok(Err(self.failures))
        }
    }

    /// How many records are written so far.
    #[must_use]
    pub fn written(&self) -> usize {
        self.written.len()
    }

    fn write(&mut self) -> Result<(), String> {
        let records = std::mem::take(&mut self.records);
        for record in records {
            let position = self.failures.took();
            match record {
                // Once one failed nothing is made, so nothing more is kept.
                Record::Part(bytes) if self.failures.is_empty() => {
                    let section = self.section(&bytes)?;
                    self.written.push(section);
                }
                Record::Part(_) => {}
                Record::Refused(reason) => self.failures.fail(position, reason),
            }
        }
        Ok(())
    }

    /// `bytes` as a Stream in the Ledger, and the Section over it.
    fn section(&self, mut bytes: &[u8]) -> Result<MessageSection, String> {
        let stream = StreamId::new(self.ids.next_u128());
        let kept = write_stream(self.storage.as_ref(), stream, &mut bytes, self.chunk)?;
        Ok(MessageSection {
            section_id: SectionId::new(self.ids.next_u128()),
            name: None,
            stream: kept.stream(self.storage, None),
            contract: None,
        })
    }
}

/// What a splitting of `from` ended with, made its parts: where every
/// record was split, each a Message in their order — the next generation
/// of `from`, its context and the values keeping the records together;
/// where any failed, nothing, and every failure.
///
/// # Errors
/// The failures: how many records, how many failed, and each.
pub fn parts(
    from: &Message,
    split: Result<Vec<MessageSection>, Failures>,
    ids: &dyn IdGenerator,
) -> Result<Vec<Message>, Failures> {
    let sections = split?;
    let count = i64::try_from(sections.len()).unwrap_or(i64::MAX);
    let batch = ScalarValue::Text(from.message_id().to_string());
    Ok(sections
        .into_iter()
        .zip(1_i64..)
        .map(|(section, position)| {
            let context = from
                .context()
                .clone()
                .with_value(BATCH, batch.clone())
                .with_value(POSITION, ScalarValue::Integer(position))
                .with_value(COUNT, ScalarValue::Integer(count));
            from.debatched(MessageId::new(ids.next_u128()), vec![section], context)
        })
        .collect())
}

/// `from` split by `split` whole, its Sections' bytes fed in their order a
/// chunk of `chunk` bytes at a time: its parts, or every record's failure —
/// a Work Process's Debatch, and the receive's.
///
/// # Errors
/// A Section that could not be read, or a record's Stream Xmip Storage did
/// not take.
pub fn whole(
    (storage, ids, chunk): (&Arc<dyn XmipStorage>, &dyn IdGenerator, usize),
    from: &Message,
    split: &mut dyn Split,
) -> Result<Result<Vec<Message>, Failures>, String> {
    let mut splitting = Splitting::new((storage, ids, chunk), split);
    let mut buffer = vec![0; chunk.max(1)];
    for section in from.sections() {
        let unread = |failed: std::io::Error| {
            format!(
                "the Message {} could not be read: {failed}",
                from.message_id()
            )
        };
        let mut reader = section.stream.reader().map_err(unread)?;
        loop {
            let read = reader.read(&mut buffer).map_err(unread)?;
            if read == 0 {
                break;
            }
            splitting.feed(&buffer[..read])?;
        }
    }
    Ok(parts(from, splitting.end()?, ids))
}

#[cfg(test)]
#[path = "split/tests.rs"]
mod tests;
