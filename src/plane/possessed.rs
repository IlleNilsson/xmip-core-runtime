//! A relay's proof that its browser held its key, checked by the node
//! (ADR-0009, amendment 2026-11-02): the browser's handshake, handed over
//! whole, must sign — with the browser's own certificate's key — a
//! transcript whose `ServerHello` random is bound to the nonces handed with
//! it (`tls::possession`), one of them this node's, fresh and issued to the
//! relay the call comes through (`plane::fresh`), and made with the very
//! listener that nonce was issued for — which the node verified under its
//! own anchors when it issued the nonce (`plane::vouched::nonces`). Only
//! then is the browser's chain the node's to verify and hold
//! (`plane::vouched`). Each check refuses in words, and vouches nothing.

use tls::possession::{BINDING, binding, proved};

use crate::plane::fresh;
use crate::plane::vouched::Relaying;

/// The browser's chain, leaf first, once `transcript` proves it held its
/// key in a handshake bound to `nonces` — a fresh one of them this node's,
/// issued to `through`, which is spent — to the listener that nonce was
/// issued for.
///
/// # Errors
///
/// The refusal, in words: a transcript that proves nothing, a random not
/// bound to the nonces, no fresh nonce of this node's for `through`, or a
/// server that is not that listener.
pub fn possessed(
    relaying: &Relaying,
    through: &str,
    transcript: &[u8],
    nonces: &[Vec<u8>],
) -> Result<Vec<Vec<u8>>, String> {
    let proof = proved(transcript).map_err(|failed| {
        format!("REFUSED. The browser's handshake proves nothing: {failed} (ADR-0009)")
    })?;
    let listed: Vec<&[u8]> = nonces.iter().map(Vec::as_slice).collect();
    if proof.server_random[..BINDING] != binding(&listed) {
        return Err(
            "REFUSED. The browser's handshake is not bound to the nonces handed with it: its \
             server's random holds none of them (ADR-0009)"
                .to_string(),
        );
    }
    let listener = relaying.fresh.spend(nonces, through).ok_or_else(|| {
        format!(
            "REFUSED. The browser's handshake holds no fresh nonce this node issued {through}: \
             each is spent once, within {} s (ADR-0009)",
            fresh::WITHIN.as_secs()
        )
    })?;
    if proof.server_leaf != listener {
        return Err(
            "REFUSED. The browser's handshake was made with a server that is not the listener \
             the node's nonce was issued for (ADR-0009)"
                .to_string(),
        );
    }
    Ok(proof.client_chain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::Authority;

    #[test]
    fn a_handshake_that_proves_nothing_is_refused_in_words_and_spends_no_nonce() {
        let authority = Authority::new();
        let (_, _, anchors) = authority.pem("anchors");
        let relaying = Relaying::new(vec!["HOST\\gui".to_string()], &anchors).expect("anchors");
        let issued = relaying.fresh.issue("HOST\\gui", b"listener", 1);
        let nonces = vec![issued[0].to_vec()];
        let refused =
            possessed(&relaying, "HOST\\gui", b"not a handshake", &nonces).expect_err("refused");
        assert!(refused.starts_with("REFUSED. The browser's handshake proves nothing"));
        assert_eq!(
            relaying.fresh.spend(&nonces, "HOST\\gui"),
            Some(b"listener".to_vec())
        );
    }
}
