//! Every Journey that failed waiting in a Send Port's queue, read from Xmip
//! Storage a page at a time (`xmip_operate.h` section 16): what a surface
//! lists at the Port's scope, beyond the oldest its node publishes, with
//! Retry and Dismiss on each.

use journey::{Journey, JourneyState};
use route::Subscriber;

use super::{FailedJourney, SendStep};

/// The most entries of a queue read at once.
const PAGE: u32 = 64;

/// The most entries of a queue one page of failed Journeys reads, failed
/// or not, so a page is bounded however long the queue is; what is left
/// is the next page's.
const READ_MOST: usize = 1024;

/// One page of the Journeys that failed in a Send Port's queue.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FailedPage {
    /// How many failed Journeys the node knows wait in the queue.
    pub count: u64,
    /// Those of this page, oldest first.
    pub journeys: Vec<FailedJourney>,
    /// The place the next page reads from; `None` where the queue was read
    /// to its end.
    pub next: Option<u64>,
}

impl SendStep {
    /// The Journeys that failed in the queue of the Send Port `port`, read
    /// from Xmip Storage from the place `from` on, oldest first: at most
    /// `most` — one at least — and no more than [`READ_MOST`] entries read
    /// for them.
    ///
    /// # Errors
    /// FAILED, in words, where Xmip Storage did not answer.
    pub fn failed_journeys(&self, port: &str, from: u64, most: u32) -> Result<FailedPage, String> {
        let queue = self.queue(&Subscriber::SendPort(port.to_string()));
        let most = usize::try_from(most.max(1)).unwrap_or(usize::MAX);
        let unanswered = |error: persist::PersistError| {
            format!("FAILED: Xmip Storage did not answer for {port}'s queue: {error}")
        };
        let mut page = FailedPage::default();
        let (mut at, mut read) = (from, 0);
        'pages: loop {
            let held = self
                .storage
                .read_held(queue, at, PAGE)
                .map_err(unanswered)?;
            let last = held.held.len() < PAGE as usize;
            for entry in held.held {
                at = entry.sequence + 1;
                read += 1;
                let id = entry.hold.journey;
                let kept = self.storage.read_journey(id).map_err(unanswered)?;
                let journey = kept.and_then(|kept| Journey::from_record(&kept.body).ok());
                if let Some(journey) = journey.filter(|j| j.state == JourneyState::Failed) {
                    let reason = journey
                        .entries()
                        .last()
                        .map(|entry| entry.outcome.clone())
                        .unwrap_or_default();
                    self.found_failing(port, entry.sequence, id, reason.clone());
                    page.journeys.push(FailedJourney {
                        journey: id,
                        place: entry.sequence,
                        reason,
                    });
                }
                if page.journeys.len() >= most || read >= READ_MOST {
                    page.next = Some(at);
                    break 'pages;
                }
            }
            if last {
                break;
            }
        }
        page.count = self
            .lock()
            .failing
            .get(port)
            .map_or(0, |failing| failing.len() as u64);
        Ok(page)
    }
}
