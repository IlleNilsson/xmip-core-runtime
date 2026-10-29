//! A secret set through a node's operate listener, and the secrets it
//! keeps listed, from the surface's side (`crate::secret` is the node's).

use serde_json::json;

use crate::plane::call::{SECRET, SECRETS};
use crate::plane::remote::{Outcome, Remote};

impl Remote {
    /// Set the secret `name` of `kind` to `value` through the node at
    /// `node`, as the identity this side's connection proves: what came of
    /// it, and the node's sentence. The value crosses inside the operate
    /// listener's TLS, or the local endpoint the operating system guards,
    /// and never comes back.
    ///
    /// # Errors
    ///
    /// Why the node did not answer.
    pub fn set_secret(
        &self,
        node: &str,
        (name, kind, value): (&str, &str, &str),
    ) -> Result<(Outcome, String), String> {
        let message = json!({ "node": node, "name": name, "kind": kind, "value": value });
        let answer = self.asked(SECRET, &message)?;
        Ok((
            Outcome::of(answer["outcome"].as_str().unwrap_or_default()),
            answer["said"].as_str().unwrap_or_default().to_string(),
        ))
    }

    /// The secrets the node at `node` keeps, as `crate::secret::listed`
    /// says them, never a value.
    ///
    /// # Errors
    ///
    /// Why the node did not answer, or its refusal.
    pub fn secrets(&self, node: &str) -> Result<serde_json::Value, String> {
        let answer = self.asked(SECRETS, &json!({ "node": node }))?;
        match answer["refused"].as_str() {
            Some(refused) => Err(refused.to_string()),
            None => Ok(answer),
        }
    }
}
