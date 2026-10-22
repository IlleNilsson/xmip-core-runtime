//! A Journey's key in a correlation set: the tuple of the values its set's
//! keys read, each read as a Subscription's filter reads a name (ADR-0024
//! and ADR-0066, amendments 2026-10-22).
//!
//! The owner, 2026-10-22: *Equal values in a correlation set (aka
//! hashtable) go in the same queue, different values go parallel depending
//! on the value in the correlation set.* So a key is the whole tuple,
//! written out in full, and two keys are the same only where every value
//! is: the identifier a key is kept by is named from that text, and the
//! text is kept with it ([`ResolvedSet::text`]).

use journey::Journey;
use message::Message;
use route::{Gathering, Promoted};

pub use configure::correlation::KeyWord;

/// A correlation set, its keys read once.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedSet {
    pub name: String,
    pub keys: Vec<KeyWord>,
}

impl ResolvedSet {
    /// The set `name` of `keys`.
    ///
    /// # Errors
    /// A key that is no key word, or no key at all.
    pub fn read(name: &str, keys: &[String]) -> Result<Self, String> {
        if keys.is_empty() {
            return Err(format!("the correlation set '{name}' has no key"));
        }
        let keys = keys
            .iter()
            .map(|key| KeyWord::read(key))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|why| format!("the correlation set '{name}': {why}"))?;
        Ok(Self {
            name: name.to_string(),
            keys,
        })
    }

    /// The Message Context names its keys read, for a gathering.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.keys.iter().filter_map(KeyWord::context)
    }

    /// The key of `journey` and its Message in this set, written out in
    /// full: each value, in order, its length before it, so no two tuples
    /// write the same text.
    ///
    /// # Errors
    /// The key part it lacks, in words naming it and the set.
    pub fn text(
        &self,
        journey: &Journey,
        promoted: &Promoted,
        work_process: &str,
    ) -> Result<String, String> {
        let mut text = String::new();
        for key in &self.keys {
            let value = match key {
                KeyWord::ReceiveLocation => journey.received().map(|r| r.location.as_str()),
                KeyWord::ReceivePort => journey.received().map(|r| r.port.as_str()),
                KeyWord::WorkProcess => Some(work_process),
                KeyWord::SendPort => journey.send_port.as_deref(),
                KeyWord::Context(name) => promoted.get(name),
            };
            let Some(value) = value else {
                return Err(format!(
                    "the Message carries no {}, which the correlation set '{}' keys by",
                    key.shown(),
                    self.name
                ));
            };
            text.push_str(&format!("{}:{value};", value.len()));
        }
        Ok(text)
    }
}

/// What `message` gives the names `gathering` reads, or why not.
///
/// # Errors
/// A route technology refused the Message, in words.
pub fn promoted(gathering: &Gathering, message: &Message) -> Result<Promoted, String> {
    gathering.promote(message).map_err(|why| why.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_word_reads_as_the_artifact_or_a_context_name() {
        assert_eq!(KeyWord::read("receive-port"), Ok(KeyWord::ReceivePort));
        assert_eq!(
            KeyWord::read("context:Client"),
            Ok(KeyWord::Context("Client".into()))
        );
        assert_eq!(
            KeyWord::read("OrderId"),
            Ok(KeyWord::Context("OrderId".into()))
        );
        assert!(KeyWord::read("journey:Step").is_err());
        assert!(ResolvedSet::read("Empty", &[]).is_err());
    }
}
