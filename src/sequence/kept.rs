//! What a queue keeps beside each Message it holds (`persist::storage::Hold`
//! body): the places its Stream holds end to end, each with who holds it,
//! and the identity it arrived with in its one form (`context::facts_record`)
//! — so a step reading its queue knows which sequences each entry waits in
//! from the page alone, reading no Journey (ADR-0066, amendment 2026-11-22;
//! open problem 93). One writer, [`Kept::write`], and one reader,
//! [`Kept::read`]; a Message moved on from a paused Subscription's queue,
//! a Retry's and what a Work Process publishes from it keep it as it was.
//!
//! The places are the Stream's alone, the same for every Journey born of
//! it: a Send Port Group delivery's and the point's own are taken late or
//! per Journey, and the step that takes it up asks them under its claim as
//! before (`super::may_go`).

use codec::cursor::Cursor;
use codec::writer::ByteWriter;
use journey::Received;

/// What a queue keeps beside a Message, as read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Kept<'a> {
    /// Each sequence its Stream holds a place in end to end, and who holds
    /// the place: its origin.
    pub places: Vec<(u128, u128)>,
    /// The identity it arrived with, in its one form.
    pub identity: &'a [u8],
}

impl<'a> Kept<'a> {
    /// What a queue keeps beside a Message of the Stream `received` says —
    /// none for one received by no Receive Location's sequences — arrived
    /// with `identity`.
    #[must_use]
    pub fn write(received: Option<&Received>, identity: &[u8]) -> Vec<u8> {
        let places: Vec<(u128, u128)> = streamed(received).collect();
        let mut out = Vec::with_capacity(2 + places.len() * 32 + identity.len());
        out.u16_be(u16::try_from(places.len()).unwrap_or(u16::MAX));
        for (queue, holder) in places.iter().take(usize::from(u16::MAX)) {
            out.u128_be(*queue).u128_be(*holder);
        }
        out.bytes(identity);
        out
    }

    /// `body`, as [`Kept::write`] wrote it.
    ///
    /// # Errors
    /// A body no [`Kept::write`] wrote, in words.
    pub fn read(body: &'a [u8]) -> Result<Self, String> {
        let malformed = |why: codec::CodecError| format!("what its queue keeps beside it: {why}");
        let mut cursor = Cursor::new(body);
        let count = cursor.u16_be().map_err(malformed)?;
        let mut places = Vec::with_capacity(usize::from(count));
        for _ in 0..count {
            let queue = cursor.u128_be().map_err(malformed)?;
            places.push((queue, cursor.u128_be().map_err(malformed)?));
        }
        Ok(Self {
            places,
            identity: cursor.take_rest(),
        })
    }
}

/// Each sequence the Stream `received` says holds a place in end to end,
/// and who holds it: its origin. The one list of them, which a step reads
/// beside each Message ([`Kept`]) and asks under its claim
/// (`super::held_by`).
pub fn streamed(received: Option<&Received>) -> impl Iterator<Item = (u128, u128)> + '_ {
    received.into_iter().flat_map(|received| {
        let origin = received.origin;
        received.sequences.iter().map(move |queue| (*queue, origin))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_a_queue_keeps_reads_back_as_written() {
        let received = Received {
            location: "Orders".to_string(),
            port: "In".to_string(),
            origin: 7,
            sequences: vec![11, 12],
            skips: false,
        };
        let body = Kept::write(Some(&received), b"facts");
        let kept = Kept::read(&body).expect("read");
        assert_eq!(kept.places, [(11, 7), (12, 7)]);
        assert_eq!(kept.identity, b"facts");
        let none = Kept::write(None, b"");
        assert_eq!(Kept::read(&none).expect("read").places, []);
        assert!(Kept::read(&[0, 1, 2]).is_err(), "a place cut short");
    }
}
