//! A Send Location's far end that takes each body as it is sent, a piece at
//! a time, and keeps only how long it was: what a test of what a send holds
//! sends large Messages to, as a transport that streams sends them — at the
//! machine's pace, or at a far end's.

use std::io::{self, Write};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

/// A far end that reads every body it is sent as it comes and keeps its
/// length, in the order taken, and the deduplication key it came under.
#[derive(Clone, Default)]
pub struct Drain {
    taken: Arc<Mutex<Vec<(u64, String)>>>,
    /// How long it takes over each piece, where it is slower than the
    /// machine: a network's far end.
    pace: Option<Duration>,
}

impl Drain {
    /// A far end that takes over each piece written to it at least `pace`,
    /// as a far end across a network sets a send's pace.
    #[must_use]
    pub fn paced(pace: Duration) -> Self {
        Self {
            pace: Some(pace),
            ..Self::default()
        }
    }

    /// Each body's length it took, with its key, in the order taken.
    #[must_use]
    pub fn taken(&self) -> Vec<(u64, String)> {
        self.taken
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The Send Location `name` sending to it.
    #[must_use]
    pub fn at(self, name: &str) -> crate::sending::Sending {
        let mut sending = super::FarEnd::answering(Box::new(|_| Ok(()))).0.at(name);
        sending.transport = Box::new(self);
        sending
    }
}

/// Bytes counted as they are written, and let go of — each piece taken
/// over at least `pace`, where there is one.
struct Counted {
    bytes: u64,
    pace: Option<Duration>,
}

impl Write for Counted {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if let Some(pace) = self.pace {
            // A far end's pace, held to the microsecond: a sleep ends on the
            // system's tick.
            let until = Instant::now() + pace;
            while Instant::now() < until {
                std::hint::spin_loop();
            }
        }
        self.bytes += bytes.len() as u64;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl transport::Transport for Drain {
    fn name(&self) -> &'static str {
        "drain"
    }

    fn directions(&self) -> transport::Directions {
        transport::Directions::SEND
    }

    fn receive_up_to(&self, _most: usize) -> transport::Result<Vec<transport::Arrived>> {
        Ok(Vec::new())
    }

    fn arrivals(&self) -> transport::Arrivals {
        transport::Arrivals::Unordered("it receives nothing")
    }

    fn waiting(&self) -> transport::Waiting {
        transport::Waiting::Polled("it looks and finds nothing")
    }

    fn sending(&self) -> transport::Sending {
        transport::Sending::Streamed("it counts each piece of the body as it is read")
    }

    fn send_from(&self, _target: &str, outgoing: transport::Outgoing<'_>) -> transport::Result<()> {
        let mut counted = Counted {
            bytes: 0,
            pace: self.pace,
        };
        let length = outgoing.write_to(&mut counted)?;
        let key = outgoing.key().unwrap_or_default().to_string();
        self.taken
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((length.min(counted.bytes), key));
        Ok(())
    }
}
