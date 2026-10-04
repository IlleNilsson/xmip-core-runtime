//! What a node's send step counts per Send Port, and the last Journey that
//! failed there with its reason: what its snapshot publishes at the Port's
//! scope (`crate::running::publication`), so every surface shows it.

/// One Send Port's figures since the node started.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PortFigures {
    /// Journeys sent: written Completed.
    pub sent: u64,
    /// Journeys whose every Send Location failed its tries: written Failed.
    pub failed: u64,
    /// Journeys waiting now for a retry's due time.
    pub waiting: u64,
    /// The last that failed: its Journey and why, in words.
    pub last_failure: Option<(String, String)>,
}

impl PortFigures {
    /// The Port's state in one line, as its snapshot says it.
    #[must_use]
    pub fn evidence(&self) -> String {
        let mut said = format!(
            "sent {}, failed {}, waiting {}",
            self.sent, self.failed, self.waiting
        );
        if let Some((journey, why)) = &self.last_failure {
            said.push_str(&format!("; the Journey {journey} failed: {why}"));
        }
        said
    }
}
