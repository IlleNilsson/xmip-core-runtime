//! The nonces a node issues its relays (ADR-0009, amendment 2026-11-02):
//! fresh, single-use and short-lived, each issued to the relay's account
//! for the one listener certificate it named — what a web host binds into
//! the random its server sends a browser (`tls::possession`), so the node,
//! finding its own nonce bound in the transcript it is handed, knows the
//! browser held its key in a handshake made after the nonce was issued, to
//! that listener. A nonce is spent once (`spend`); one not spent within
//! [`WITHIN`] is no proof, counted on the Clock the pool was handed
//! (ADR-0068, amendment 2026-11-15).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use xcore::clock::nanos;
use xcore::lock::Locked;
use xcore::{Clock, SystemClock};

use context::AuthenticatedIdentity;
use serde_json::{Value, json};

/// How long a nonce is fresh.
pub const WITHIN: Duration = Duration::from_secs(30);

/// How many a relay is answered at once, at most.
pub const AT_ONCE: usize = 32;

/// How many are outstanding at once, at most: past that, the stale go, and
/// where none is stale a relay is answered none.
pub const MOST: usize = 65_536;

/// How long a nonce is.
pub const LENGTH: usize = 16;

/// One nonce outstanding: to whom, for which listener, until when on the
/// pool's clock.
struct Issued {
    through: String,
    listener: Vec<u8>,
    until: i128,
}

/// The nonces one operate listener issued and has not seen spent: each
/// node's own, so a nonce of one is no nonce of another in the same
/// process.
pub struct Fresh {
    issued: Mutex<HashMap<[u8; LENGTH], Issued>>,
    clock: Arc<dyn Clock>,
}

/// None issued, fresh by the operating system's clock.
impl Default for Fresh {
    fn default() -> Self {
        Self::timed_by(Arc::new(SystemClock))
    }
}

impl Fresh {
    /// None issued, each fresh for [`WITHIN`] on `clock`.
    #[must_use]
    pub fn timed_by(clock: Arc<dyn Clock>) -> Self {
        Self {
            issued: Mutex::default(),
            clock,
        }
    }

    fn issued(&self) -> MutexGuard<'_, HashMap<[u8; LENGTH], Issued>> {
        self.issued.locked()
    }

    /// `count` fresh nonces — at most [`AT_ONCE`] — issued to `through` for the
    /// listener whose leaf certificate is `listener` (DER).
    #[must_use]
    pub fn issue(&self, through: &str, listener: &[u8], count: usize) -> Vec<[u8; LENGTH]> {
        let now = self.clock.monotonic_nanos();
        let mut held = self.issued();
        if held.len() + count >= MOST {
            held.retain(|_, one| one.until > now);
        }
        let room = MOST.saturating_sub(held.len());
        (0..count.min(AT_ONCE).min(room))
            .map(|_| {
                let nonce = loop {
                    let drawn: [u8; LENGTH] = codec::random::array();
                    if !held.contains_key(&drawn) {
                        break drawn;
                    }
                };
                held.insert(
                    nonce,
                    Issued {
                        through: through.to_string(),
                        listener: listener.to_vec(),
                        until: now.saturating_add(nanos(WITHIN)),
                    },
                );
                nonce
            })
            .collect()
    }

    /// Spend the one nonce among `nonces` this node issued to `through` and
    /// that is still fresh: the listener certificate it was issued for. Every
    /// nonce of this node's in the list is spent, used or not, so none is
    /// offered twice; `None` where none was fresh and `through`'s.
    #[must_use]
    pub fn spend(&self, nonces: &[Vec<u8>], through: &str) -> Option<Vec<u8>> {
        let now = self.clock.monotonic_nanos();
        let mut held = self.issued();
        let mut found = None;
        for nonce in nonces {
            let Ok(key) = <[u8; LENGTH]>::try_from(nonce.as_slice()) else {
                continue;
            };
            if let Some(one) = held.remove(&key)
                && one.through == through
                && one.until > now
            {
                found.get_or_insert(one.listener);
            }
        }
        found
    }

    /// The answer to a relay's `Nonces`: `{"nonces": [hex...], "within_ms"}`,
    /// `count` of them issued to the relay `connection` proved for the
    /// listener whose leaf certificate is `listener` (DER), which the node
    /// has verified under its anchors (`plane::vouched::nonces`), or
    /// `{"refused": <why>}`. A
    /// relay a certificate proved — on the network listener — names a listener
    /// whose certificate is that same subject's; one the operating system
    /// proved, on the local endpoint, is taken at that word.
    #[must_use]
    pub fn answered(
        &self,
        connection: &AuthenticatedIdentity,
        listener: &[u8],
        count: usize,
    ) -> Value {
        let through = connection.value.as_str();
        if connection.mechanism.name() == xcore::mechanism::mutual_tls().name()
            && crate::plane::caller::certificate(listener).map(|named| named.value)
                != Ok(connection.value.clone())
        {
            return json!({
                "refused": format!(
                    "REFUSED. {through} names a listener whose certificate is not its own subject's"
                )
            });
        }
        let nonces: Vec<String> = self
            .issue(through, listener, count)
            .iter()
            .map(|nonce| codec::hex::encode(nonce))
            .collect();
        json!({ "nonces": nonces, "within_ms": WITHIN.as_millis() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_nonce_is_spent_once_by_its_relay_alone_and_names_its_listener() {
        let fresh = Fresh::default();
        let other = Fresh::default();
        let issued = fresh.issue("HOST\\gui", b"leaf", 3);
        assert_eq!(issued.len(), 3);
        let list: Vec<Vec<u8>> = issued.iter().map(|nonce| nonce.to_vec()).collect();
        assert_eq!(
            fresh.spend(&list[..1], "HOST\\other"),
            None,
            "another relay's is no one's"
        );
        assert_eq!(
            fresh.spend(&list[..1], "HOST\\gui"),
            None,
            "and spent by the try"
        );
        assert_eq!(fresh.spend(&list[1..], "HOST\\gui"), Some(b"leaf".to_vec()));
        assert_eq!(fresh.spend(&list[1..], "HOST\\gui"), None, "used once");
        assert_eq!(fresh.issue("x", b"leaf", 1000).len(), AT_ONCE);
        let theirs = other.issue("HOST\\gui", b"leaf", 1);
        let spent = fresh.spend(&[theirs[0].to_vec()], "HOST\\gui");
        assert_eq!(spent, None, "another node's");
        let relay = AuthenticatedIdentity::new(
            xcore::mechanism::peer_credentials(),
            "x",
            xcore::Established::Detected,
            context::Verified::Proven,
        );
        let given = fresh.answered(&relay, b"leaf", 2);
        assert_eq!(given["nonces"].as_array().map(Vec::len), Some(2));
    }

    #[test]
    fn a_nonce_is_fresh_until_its_span_passed_on_the_pools_clock() {
        let clock = Arc::new(xcore::clock::Stepped::default());
        let fresh = Fresh::timed_by(Arc::clone(&clock) as Arc<dyn Clock>);
        let issued = fresh.issue("HOST\\gui", b"leaf", 2);
        let (first, second) = (vec![issued[0].to_vec()], vec![issued[1].to_vec()]);
        let short = WITHIN.checked_sub(Duration::from_nanos(1));
        clock.pass(short.expect("a span of seconds"));
        assert_eq!(fresh.spend(&first, "HOST\\gui"), Some(b"leaf".to_vec()));
        clock.pass(Duration::from_nanos(1));
        assert_eq!(fresh.spend(&second, "HOST\\gui"), None, "stale at its span");
    }
}
