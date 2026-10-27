//! A splitting unit's stand-in: a record a line, split as its bytes arrive,
//! and the Work Process units that carry it (`crate::split`).

use message::Message;
use process::program::Call;
use xcore::IdGenerator;

use crate::split::{Record, Split};
use crate::work_step::{NO_UNIT, Thrown, WorkUnits};

/// A record a line; a line holding `!` is refused, naming it.
#[derive(Default)]
pub struct Lines {
    pending: Vec<u8>,
}

impl Lines {
    fn record(line: Vec<u8>) -> Record {
        if line.contains(&b'!') {
            Record::Refused(format!(
                "the line '{}' is no record",
                String::from_utf8_lossy(&line)
            ))
        } else {
            Record::Part(line)
        }
    }
}

impl Split for Lines {
    fn feed(&mut self, chunk: &[u8], records: &mut Vec<Record>) {
        for byte in chunk {
            if *byte == b'\n' {
                records.push(Self::record(std::mem::take(&mut self.pending)));
            } else {
                self.pending.push(*byte);
            }
        }
    }

    fn end(&mut self, records: &mut Vec<Record>) {
        if !self.pending.is_empty() {
            records.push(Self::record(std::mem::take(&mut self.pending)));
        }
    }
}

/// The units a node carries in a test: [`Lines`] as the unit `Lines`, and
/// no other.
pub struct LinesUnits;

impl LinesUnits {
    fn none(call: &Call) -> Thrown {
        Thrown {
            code: NO_UNIT.to_string(),
            reason: format!("no unit '{}' in this test", call.unit),
        }
    }
}

impl WorkUnits for LinesUnits {
    fn call(&self, call: &Call, _: &Message, _: &dyn IdGenerator) -> Result<Vec<Message>, Thrown> {
        Err(Self::none(call))
    }

    fn splitter(&self, call: &Call) -> Result<Box<dyn Split>, Thrown> {
        if call.unit == "Lines" {
            Ok(Box::new(Lines::default()))
        } else {
            Err(Self::none(call))
        }
    }
}
