//! The cluster's publication a monitoring node gathered, read and followed
//! through the same surface as the node's own (ADR-0027 decision 8,
//! amendment 2026-11-13; `xmip_operate.h` section 17,
//! `xmip_remote_cluster_v1`). A node that gathers none says so in its own
//! words, told apart from one that does not answer, so a surface follows
//! the node's own publication there instead — decided by that answer, never
//! by a name, and where a surface leaves it to the follow
//! ([`Follows::Answered`]), decided there, once, as each connection is
//! made: never by asking again and again.
//!
//! A surface follows one publication, or the one the node's answer
//! decides: what its first [`Remote::follow`] names. Its follow asks the
//! node for whichever that is (`plane::follow`), so one connection of its
//! own still carries it, and every state it tells says which it follows.

use std::time::Duration;

use serde_json::json;

use super::{Remote, State};
use crate::plane::call::{self, CLUSTER, CLUSTER_WAIT, WAIT};
use xcore::lock::Locked;

/// What a follow does with what its node answered a wait
/// ([`Follows::waited`]).
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Waited {
    /// The publication's revision now, where the answer says one.
    Revision(Option<u64>),
    /// Follow this instead, on the same connection.
    Instead(Follows),
    /// Not followed on this connection, and why.
    Lost(String),
}

/// Which publication a surface follows. The numbers are what crosses the C
/// boundary (`XMIP_REMOTE_FOLLOWS_NODE`, `XMIP_REMOTE_FOLLOWS_CLUSTER`,
/// `XMIP_REMOTE_FOLLOWS_ANSWERED`).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Follows {
    /// The node's own publication.
    #[default]
    Node = 0,
    /// The cluster's, as the node gathered it.
    Cluster = 1,
    /// The cluster's where the node answers one, else the node's own: the
    /// node's answer decides, as each connection to it is made. A state
    /// says it while nothing has decided yet.
    Answered = 2,
}

impl Follows {
    /// What a number crossing the C boundary names, if it names one.
    #[must_use]
    pub const fn from_wire(number: u32) -> Option<Self> {
        match number {
            0 => Some(Self::Node),
            1 => Some(Self::Cluster),
            2 => Some(Self::Answered),
            _ => None,
        }
    }

    /// The call the node's operate listener answers a wait on it with: the
    /// cluster's first, where the node's answer decides.
    pub(crate) const fn method(self) -> &'static str {
        match self {
            Self::Node => WAIT,
            Self::Cluster | Self::Answered => CLUSTER_WAIT,
        }
    }

    /// What a follow of this does with `answered`, what the node answered a
    /// wait, decided by the answer's kind and never by its words: a node
    /// gathering no cluster turns a follow left to its answer to its own
    /// publication on the same connection, and is a node not reached, its
    /// words the reason, for one following the cluster's; any refusal is a
    /// node lost.
    pub(crate) fn waited(self, answered: Result<serde_json::Value, String>) -> Waited {
        match answered {
            Err(why) => Waited::Lost(format!("lost: {why}")),
            Ok(answer) => match call::gathered_none(&answer) {
                None => Waited::Revision(answer["revision"].as_u64()),
                Some(_) if self == Self::Answered => Waited::Instead(Self::Node),
                Some(said) => Waited::Lost(said.to_string()),
            },
        }
    }

    /// What it is, in the words a refusal says.
    const fn said(self) -> &'static str {
        match self {
            Self::Node => "the node's own publication",
            Self::Cluster => "the cluster's publication",
            Self::Answered => "the publication the node's answer decides",
        }
    }
}

/// What a node answered when asked for the cluster's publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Clustered {
    /// The revision and the text a publication file holds, which every
    /// surface reads with the one reader: revision 0 and no text until the
    /// node has gathered its first view.
    Gathered(u64, String),
    /// The node gathers no cluster: its refusal, naming the role.
    GathersNone(String),
}

impl Remote {
    /// The cluster's publication the node gathered, and its revision; or,
    /// where the node gathers none, its refusal saying so.
    ///
    /// # Errors
    ///
    /// Why the node did not answer, or refused the call — by the caller's
    /// role among them: said at once while the follow is recovering it, as
    /// [`Remote::publication`] says.
    pub fn cluster(&self) -> Result<Clustered, String> {
        let answer = self.asked(CLUSTER, &json!({}))?;
        if let Some(said) = call::gathered_none(&answer) {
            return Ok(Clustered::GathersNone(said.to_string()));
        }
        let revision = answer["revision"].as_u64().unwrap_or(0);
        let text = answer["publication"].as_str().unwrap_or_default();
        Ok(Clustered::Gathered(revision, text.to_string()))
    }

    /// [`Remote::wait`] on `follows`: the state once a follower has been
    /// told more than `seen` times, or after `within`, saying which
    /// publication it follows. The first names what this surface follows
    /// from then on; at a node that gathers no cluster, following the
    /// cluster's is told unreached with the node's refusal, and tried again
    /// as a lost node is, and [`Follows::Answered`] follows the node's own.
    ///
    /// # Errors
    ///
    /// `follows` names another than this surface follows.
    pub fn follow(&self, follows: Follows, seen: u64, within: Duration) -> Result<State, String> {
        let fixed = *self.shared.follows.get_or_init(|| {
            let mut state = self.shared.state.locked();
            if state.told == 0 {
                state.follows = follows;
            }
            follows
        });
        if fixed != follows {
            return Err(format!(
                "REFUSED: this surface follows {}; {} is followed over a surface of its own",
                fixed.said(),
                follows.said()
            ));
        }
        Ok(self.wait(seen, within))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_number_names_which_publication_and_no_other() {
        assert_eq!(Follows::from_wire(0), Some(Follows::Node));
        assert_eq!(Follows::from_wire(1), Some(Follows::Cluster));
        assert_eq!(Follows::from_wire(2), Some(Follows::Answered));
        assert_eq!(Follows::from_wire(3), None);
        assert_eq!(Follows::Node.method(), WAIT);
        assert_eq!(Follows::Cluster.method(), CLUSTER_WAIT);
        assert_eq!(Follows::Answered.method(), CLUSTER_WAIT);
    }

    /// What the node answered, through the one reading of an answer.
    fn answered(response: &net::http::Response) -> Result<serde_json::Value, String> {
        call::answered(response)
    }

    #[test]
    fn a_follow_left_to_the_answer_turns_by_the_answers_kind_whatever_its_words() {
        // The kind, with words that say nothing of a role: it turns.
        let kind = answered(&call::gathers_none("other words entirely"));
        assert_eq!(
            Follows::Answered.waited(kind.clone()),
            Waited::Instead(Follows::Node)
        );
        // Following the cluster's, it is no node followed, its words why.
        assert_eq!(
            Follows::Cluster.waited(kind),
            Waited::Lost("other words entirely".to_string())
        );
        // The words, as another kind of refusal: a node lost, never turned.
        let words = "REFUSED. This node declares no monitoring role";
        for status in ["UNIMPLEMENTED", "PERMISSION_DENIED", "FAILED_PRECONDITION"] {
            let refused = answered(&call::refusal(status, words));
            assert!(
                matches!(Follows::Answered.waited(refused), Waited::Lost(why) if why.starts_with("lost: ")),
                "{status}"
            );
        }
        // The words in an answer of no such kind: an answer, read as one.
        let said = answered(&call::answer(&json!({ "said": words, "revision": 3 })));
        assert_eq!(Follows::Answered.waited(said), Waited::Revision(Some(3)));
    }
}
