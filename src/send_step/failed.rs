//! Every Journey that failed waiting in a Send Port's queue, read from its
//! queue's index of failed Journeys in Xmip Storage a page at a time
//! (`xmip_operate.h` section 16): what a surface lists at the Port's scope,
//! beyond the oldest its node keeps and publishes, with Retry and Dismiss on
//! each.

use route::Subscriber;

use super::{FailedJourney, SendStep};

/// One page of the Journeys that failed in a Send Port's queue.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FailedPage {
    /// How many failed Journeys wait in the queue, as Xmip Storage counts
    /// them.
    pub count: u64,
    /// Those of this page, oldest first.
    pub journeys: Vec<FailedJourney>,
    /// The place in the queue's index of failed Journeys the next page reads
    /// from; `None` where the index was read to its end.
    pub next: Option<u64>,
}

impl SendStep {
    /// The Journeys that failed in the queue of the Send Port `port`, read
    /// from its index of them in Xmip Storage from the place `from` there
    /// on, oldest first: at most `most`, one at least. The page is one read,
    /// however long the queue and however many failed.
    ///
    /// # Errors
    /// FAILED, in words, where Xmip Storage did not answer.
    pub fn failed_journeys(&self, port: &str, from: u64, most: u32) -> Result<FailedPage, String> {
        let queue = self.queue(&Subscriber::SendPort(port.to_string()));
        let most = most.max(1);
        let read = self
            .storage
            .read_failed(queue, from, most)
            .map_err(|error| {
                format!("FAILED: Xmip Storage did not answer for {port}'s queue: {error}")
            })?;
        let full = read.failed.len() >= usize::try_from(most).unwrap_or(usize::MAX);
        let next = read
            .failed
            .last()
            .map(|last| last.sequence + 1)
            .filter(|next| full && *next < read.next);
        Ok(FailedPage {
            count: read.count,
            journeys: read.failed.iter().map(FailedJourney::of).collect(),
            next,
        })
    }
}
