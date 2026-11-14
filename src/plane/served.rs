//! One connection to a node's operate listener: the handshake, who the
//! certificate — or, on the local endpoint, the operating system — proves,
//! the role the node's configuration grants that very caller
//! (`plane::grant`), and each call answered in turn — the publication,
//! a wait for its next revision, the cluster's publication a monitoring
//! node gathered and a wait for its next ([`read`]), and an operator's act,
//! admitted by the caller's role and audited taken or refused (ADR-0009,
//! amendments 2026-10-06 and 2026-11-07; ADR-0062).

mod read;

pub use read::GATHERS_NO_CLUSTER;

use std::collections::BTreeMap;
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use context::AuthenticatedIdentity;
use net::http::{Request, Response};
use net::http2::{Boxed, BoxedServer};
use net::watched::Watched;
use observe::{Noun, Order};
use serde_json::{Value, json};
use xcore::{ExecutionPhase, Severity};

use crate::act_watch::Asker;
use crate::applied::Applied;
use crate::plane::call::{self, ACT, NONCES, PUBLICATION, SECRET, SECRETS, UNVOUCH, VOUCH, WAIT};
use crate::plane::call::{CLUSTER, CLUSTER_WAIT, WATCH};
use crate::plane::caller;
use crate::plane::grant::Presented;
use crate::plane::limits::{Handshaking, handshaken};
use crate::plane::listener::Serve;
use crate::plane::local::Stream;
use crate::plane::role::{Role, admitted};
use crate::plane::vouched::{self, Relaying};

/// The most a write to a surface that does not read waits.
const PATIENCE: Duration = Duration::from_secs(5);

/// The audit action every act through the gate records — the one
/// `GatedOperator.AuditAction` names.
pub const AUDIT_ACTION: &str = "act";

/// Serve one network connection until the surface or the listener ends
/// it: mutual TLS agreeing `h2`, its handshake finished within the first of
/// `bound` in all and counted in progress by the second until it has, the
/// caller what the authentication gate answers for its certificate
/// (`plane::caller::certificate`) and its role the one granted it.
pub(crate) fn answer(
    connection: TcpStream,
    peer: SocketAddr,
    serve: &Serve,
    bound: (Duration, Handshaking),
) {
    let (within, handshaking) = bound;
    let Some(config) = serve.config.as_ref() else {
        return;
    };
    let guarded = connection
        .set_nodelay(true)
        .map_err(|error| error.to_string())
        .and_then(|()| tls::server(connection, Arc::clone(config)).map_err(|e| e.message))
        .and_then(|mut guarded| {
            handshaken(&mut guarded, within)?;
            drop(handshaking);
            let agreed = tls::alpn::agreed(&mut guarded).map_err(|e| e.message)?;
            if agreed.as_deref() != Some(b"h2") {
                return Err("refused: the surface did not agree h2".to_string());
            }
            let who = proven(&guarded, serve)?;
            // A connection waits on its surface for as long as it is held,
            // looking each WATCH whether the listener stops.
            guarded
                .sock
                .set_read_timeout(Some(WATCH))
                .and_then(|()| guarded.sock.set_write_timeout(Some(PATIENCE)))
                .map_err(|error| error.to_string())?;
            Ok((guarded, who))
        });
    match guarded {
        Ok((guarded, (caller, role, presented))) => calls(
            Box::new(Watched::new(guarded, || serve.stopped())),
            (&caller, role, &presented),
            serve,
        ),
        Err(reason) => noted(serve, &peer.to_string(), &format!("refused: {reason}")),
    }
}

/// Serve one connection on the node's local endpoint: plain HTTP/2, the
/// caller what the authentication gate answers for the account the
/// operating system says its process runs as (`plane::caller::local`).
pub(crate) fn answer_local(mut stream: Stream, serve: &Serve) {
    let proven = stream.caller().and_then(|account| caller::local(&account));
    let caller = match proven {
        Ok(caller) => caller,
        Err(reason) => return noted(serve, "the local endpoint", &format!("refused: {reason}")),
    };
    if let Err(error) = stream.watch(WATCH) {
        return noted(serve, &caller.value, &format!("refused: {error}"));
    }
    let presented = Presented::Account(caller.value.clone());
    let role = serve.grants.of(&presented);
    calls(
        Box::new(Watched::new(stream, || serve.stopped())),
        (&caller, role, &presented),
        serve,
    );
}

/// Each call on a connection answered in turn, until the surface or the
/// listener ends it: HTTP/2 compiled in `net`, as it ships, over the
/// connection boxed (`net::http2::boxed`). Every call taken was answered
/// by then, and the surface that went away said so or closed, so the
/// connection is let go with nothing more said: until 2026-10-21 this side
/// answered a surface's `GOAWAY` with its own and read on until it closed,
/// a quarter of a millisecond of processor time a connection on the local
/// endpoint (open problem 35).
fn calls(connection: Boxed<'_>, caller: Caller<'_>, serve: &Serve) {
    let Ok(mut server) = BoxedServer::handshake(connection) else {
        return;
    };
    while !serve.stopped() {
        let Ok(Some((stream, request))) = server.next_request() else {
            break;
        };
        let response = called(serve, caller, &request);
        if server.respond(stream, &response).is_err() {
            break;
        }
    }
}

/// A connection's caller, the role granted it — `None` for none — and what
/// it presented, which that role is read from.
type Caller<'a> = (&'a AuthenticatedIdentity, Option<Role>, &'a Presented);

/// The caller the certificate the surface presented proves, which the
/// handshake checked against the anchors, through the authentication gate,
/// the role `serve` grants that certificate, and the certificate.
fn proven(
    guarded: &tls::GuardedServer,
    serve: &Serve,
) -> Result<(AuthenticatedIdentity, Option<Role>, Presented), String> {
    let leaf = guarded
        .conn
        .peer_certificates()
        .and_then(<[_]>::first)
        .ok_or_else(|| "the surface presented no certificate".to_string())?;
    let presented = Presented::Certificate(leaf.to_vec());
    let role = serve.grants.of(&presented);
    Ok((caller::certificate(leaf)?, role, presented))
}

/// The answer to one call: decided from its method, the identity the
/// connection proved — or, where a relay names the caller it calls for
/// ([`call::CALLER_HEADER`]), that caller as the node holds it
/// (`plane::vouched`) — and the role granted that very caller before a
/// byte of it is read (`role::admitted`), and only then read and answered.
fn called(serve: &Serve, (caller, role, presented): Caller<'_>, request: &Request) -> Response {
    let Some(method) = call::method(&request.path).filter(|method| METHODS.contains(method)) else {
        return call::refusal(
            "UNIMPLEMENTED",
            &format!("{} is no method of {}", request.path, call::SERVICE),
        );
    };
    let relaying = serve
        .relaying
        .get()
        .filter(|relaying| caller.verified.is_proven() && relaying.relays(&caller.value));
    if matches!(method, NONCES | VOUCH | UNVOUCH) {
        return relayed(serve, relaying.map(AsRef::as_ref), caller, method, request);
    }
    // The caller each call names is decided by the identity and role the
    // connection proved, or the one a relay vouched for, and no other.
    let (acting, through) = match (call::caller_of(request), relaying) {
        (None, _) => (Some((caller.clone(), role, presented.clone())), None),
        (Some(handle), Some(_)) => (
            relaying.and_then(|relaying| vouched::proven(relaying, handle, &caller.value)),
            Some(caller.value.as_str()),
        ),
        (Some(_), None) => {
            let refused = format!("REFUSED. {} {NOT_A_RELAY} (ADR-0009)", caller.value);
            return answered_refused(method, &refused);
        }
    };
    let Some((acting, role, presented)) = acting else {
        return answered_refused(method, call::UNKNOWN_CALLER);
    };
    let asker = Asker {
        who: acting.value.as_str(),
        proven: acting.mechanism.name(),
        presented: &presented,
        role,
        through,
    };
    let asking = (asked(method), "on this node");
    if let Err(refused) = admitted(Some(&acting), role, method, asking) {
        record(serve, asker, method, "", Some(&refused));
        return answered_refused(method, &refused);
    }
    let message = match call::message(request) {
        Ok(message) => message,
        Err(why) => return call::refusal("INVALID_ARGUMENT", &why),
    };
    match method {
        PUBLICATION | WAIT | CLUSTER | CLUSTER_WAIT => read::read(serve, method, &message),
        ACT => acted(serve, asker, &message),
        SECRET => secret_set(serve, asker, &message),
        _ => match crate::secret::listed(message["node"].as_str().unwrap_or_default()) {
            Ok(listed) => call::answer(&listed),
            Err(refused) => call::answer(&json!({ "refused": refused })),
        },
    }
}

/// What a connection that is no relay is told where it names a caller.
const NOT_A_RELAY: &str = "relays for no one: [operate] relay does not name it";

/// A refusal, as the call's method answers one.
fn answered_refused(method: &str, refused: &str) -> Response {
    match method {
        ACT | SECRET => outcome("denied", refused),
        SECRETS => call::answer(&json!({ "refused": refused })),
        _ => call::refusal("PERMISSION_DENIED", refused),
    }
}

/// A relay's `Nonces`, `Vouch` or `Unvouch`, answered only for a connection
/// `[operate] relay` names (`relaying`); every other is refused before its
/// call is read, and audited.
fn relayed(
    serve: &Serve,
    relaying: Option<&Relaying>,
    caller: &AuthenticatedIdentity,
    method: &str,
    request: &Request,
) -> Response {
    let who = caller.value.as_str();
    let Some(relaying) = relaying else {
        let refused = format!("REFUSED. {who} {NOT_A_RELAY} (ADR-0009)");
        noted(serve, who, &refused);
        return call::refusal("PERMISSION_DENIED", &refused);
    };
    let message = match call::message(request) {
        Ok(message) => message,
        Err(why) => return call::refusal("INVALID_ARGUMENT", &why),
    };
    let answer = match method {
        NONCES => vouched::nonces(relaying, caller, &message),
        VOUCH => vouched::vouched_for(relaying, who, &message, &serve.grants),
        _ => vouched::unvouched(relaying, who, &message),
    };
    if let Some(refused) = answer["refused"].as_str() {
        noted(serve, who, refused);
    }
    call::answer(&answer)
}

/// What a call of `method` asks, in the words its refusal says.
fn asked(method: &str) -> &'static str {
    match method {
        PUBLICATION => "read the publication",
        WAIT => "follow the publication",
        CLUSTER => "read the cluster's publication",
        CLUSTER_WAIT => "follow the cluster's publication",
        SECRET => "set a secret",
        SECRETS => "list the secrets",
        _ => "act",
    }
}

/// Every method the listener answers.
const METHODS: [&str; 10] = [
    PUBLICATION,
    WAIT,
    CLUSTER,
    CLUSTER_WAIT,
    ACT,
    SECRET,
    SECRETS,
    NONCES,
    VOUCH,
    UNVOUCH,
];

/// An act, its caller admitted by role already: read, recorded, asked
/// through the node's door of the node it names (`act_watch::Door`), and
/// what came of it — `taken`, `refused` by the node or the door, `failed`,
/// `asked` where its node did not take it within the door's bound, or
/// `invalid` for no act the noun takes.
fn acted(serve: &Serve, asker: Asker<'_>, message: &Value) -> Response {
    let who = asker.who;
    let text = |key: &str| message[key].as_str().unwrap_or_default().to_string();
    let (node, target) = (text("node"), text("target"));
    let Some(noun) = Noun::named(&text("noun")) else {
        return outcome(
            "invalid",
            &format!("REFUSED: '{}' is no noun", text("noun")),
        );
    };
    let act = match noun.act(&text("act")) {
        Ok(act) => act,
        Err(refused) => return outcome("invalid", &refused),
    };
    let thing = format!("{} '{target}' at {node}", noun.called());
    record(serve, asker, act.word(), &thing, None);
    let order = Order {
        node,
        noun,
        target,
        act,
        who: who.to_string(),
    };
    let (decided, said) = serve.door().ask(&order, asker);
    outcome(decided.word(), &said)
}

/// A secret set, its caller admitted by role already as for any act:
/// audited with its name and never its value, and written through the
/// node.
fn secret_set(serve: &Serve, asker: Asker<'_>, message: &Value) -> Response {
    let text = |key: &str| message[key].as_str().unwrap_or_default();
    let (node, name) = (text("node"), text("name"));
    let thing = format!("the secret '{name}' at {node}");
    record(serve, asker, "set", &thing, None);
    match crate::secret::set(node, (name, text("kind"), text("value")), asker.who) {
        Applied::Taken(said) => outcome("taken", &said),
        Applied::Refused(said) => outcome("refused", &said),
        Applied::Failed(said) => outcome("failed", &said),
    }
}

fn outcome(word: &str, said: &str) -> Response {
    call::answer(&json!({ "outcome": word, "said": said }))
}

/// The gate's record, as `GatedOperator` writes it: who, the act, its
/// target and the role granted the caller, `none` where none is, taken or
/// refused — and, for a caller a relay called for, the relay it came
/// through (`through`).
fn record(serve: &Serve, asker: Asker<'_>, act: &str, target: &str, refused: Option<&String>) {
    let who = asker.who;
    let asked = match asker.through {
        Some(through) => format!("{who} asked through {through} to {act} {target}"),
        None => format!("{who} asked to {act} {target}"),
    };
    let (phase, severity, message) = match refused {
        None => (
            ExecutionPhase::Execute,
            Severity::Information,
            asked.as_str(),
        ),
        Some(refused) => (ExecutionPhase::Failure, Severity::Warning, refused.as_str()),
    };
    let mut properties = BTreeMap::from([
        ("act".to_string(), act.to_string()),
        ("target".to_string(), target.to_string()),
        ("who".to_string(), who.to_string()),
        (
            "role".to_string(),
            asker.role.map_or("none", Role::word).to_string(),
        ),
    ]);
    if let Some(through) = asker.through {
        properties.insert("through".to_string(), through.to_string());
    }
    let _ = serve
        .audit
        .record(AUDIT_ACTION, phase, severity, Some(message), properties);
}

/// A connection refused, in the node's audit.
pub(crate) fn noted(serve: &Serve, peer: &str, message: &str) {
    let properties = BTreeMap::from([("peer".to_string(), peer.to_string())]);
    let _ = serve.audit.record(
        "operate.connection",
        ExecutionPhase::Failure,
        Severity::Warning,
        Some(message),
        properties,
    );
}
