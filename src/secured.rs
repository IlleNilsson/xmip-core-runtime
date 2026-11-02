//! The caller a browser's secure session proves (ADR-0009, amendments
//! 2026-11-01 and 2026-11-02), made once on the session's handshake thread:
//! the handshake bound to a fresh nonce of every node this process follows
//! (`plane::remote::fresh`) and recorded (`tls::possession`); the caller its
//! certificate proves run through this process's own gate
//! (`plane::caller::certificate`) and held for the session
//! (`plane::held`), no longer than the certificate and revoked with the
//! listener; and the handshake handed to every node it was bound to, each
//! deciding for itself whether the browser held its key
//! (`plane::remote::relayed`). A browser that presents no certificate is
//! no one, and is handed to no node.

use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use xcore::spent::Spent;

use tls::GuardedServer;
use tls::peer::Unanswered;

use crate::plane::held;
use crate::plane::remote::fresh;
use crate::plane::remote::relayed::vouched_everywhere;
use crate::secure_listener::Waiting;

/// What a browser's handshake made: the session, where it was accepted and
/// where the client is, the leaf it presented (DER), the caller held for it
/// — 0, no one, where it presented none or the gate refused it — and Xmip's
/// own share of its start.
pub(crate) struct Proven {
    pub(crate) guarded: GuardedServer,
    pub(crate) ends: (SocketAddr, SocketAddr),
    pub(crate) presented: Option<Vec<u8>>,
    pub(crate) caller: u64,
    pub(crate) own: Duration,
}

/// The handshake on `tcp` over `config` — `tls::possession::proving`'s —
/// for the listener `waiting` stands for, bounded by `within`.
///
/// Its own share — what the millisecond rule holds — is the processor time
/// this thread and the threads handing it to the nodes spend on proving
/// its caller (`xcore::spent`): the binding, the transcript recovered, the
/// gate, and each `Vouch` made and sent; never TLS's handshake itself, nor
/// a wait on a node.
///
/// # Errors
///
/// Where the handshake did not finish, by kind.
pub(crate) fn proven(
    tcp: TcpStream,
    config: Arc<tls::ServerConfig>,
    waiting: &Waiting,
    within: Duration,
) -> Result<Proven, Unanswered> {
    let failed = |what: &str, failure: std::io::Error| {
        Unanswered::Failed(tls::TlsError::new(format!("{what}: {failure}")))
    };
    let local = tcp
        .local_addr()
        .map_err(|f| failed("the local address", f))?;
    let remote = tcp
        .peer_addr()
        .map_err(|f| failed("the client's address", f))?;
    tcp.set_read_timeout(Some(within))
        .and_then(|()| tcp.set_write_timeout(Some(within)))
        .and_then(|()| tcp.set_nodelay(true))
        .map_err(|f| failed("bounding the handshake", f))?;
    let (prover, listener) = (waiting.prover, waiting.listener.as_slice());
    let spent = Spent::begin();
    let bound = {
        let _own = spent.entered();
        fresh::bound(listener)
    };
    let (guarded, recorded) = tls::possession::handshaken(tcp, config, bound.binding)?;
    let (presented, caller) = {
        let _own = spent.entered();
        let presented = tls::peer::presented(&guarded.conn);
        let caller = presented.as_deref().map_or(0, |leaf| {
            let Ok(identity) = crate::plane::caller::certificate(leaf) else {
                return 0;
            };
            let until = authenticate::x509::not_after_of(leaf).ok();
            let handle = held::hold(identity, until, Some(prover), Some(leaf.to_vec()));
            // Recovered only where a node is to be handed it.
            if let Some(proof) = held::proof(handle).filter(|_| !bound.surfaces.is_empty())
                && let Ok(transcript) = recorded.transcript()
            {
                vouched_everywhere(&proof, &bound.surfaces, &transcript, &bound.nonces, &spent);
            }
            handle
        });
        (presented, caller)
    };
    Ok(Proven {
        guarded,
        ends: (local, remote),
        presented,
        caller,
        own: spent.own(Duration::ZERO),
    })
}
