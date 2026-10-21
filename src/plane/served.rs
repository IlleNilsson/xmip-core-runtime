//! One connection to a node's operate listener: the handshake, who the
//! certificate — or, on the local endpoint, the operating system — proves,
//! and each call answered in turn — the publication,
//! a wait for its next revision, and an operator's act, admitted by the
//! caller's role and audited taken or refused (ADR-0009, amendment
//! 2026-10-06; ADR-0062).

use std::collections::BTreeMap;
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use authenticate::x509::Name;
use net::http::{Request, Response};
use net::http2::{Boxed, BoxedServer};
use net::watched::Watched;
use observe::{Noun, Order};
use serde_json::{Value, json};
use xcore::{ExecutionPhase, Severity};

use crate::applied::{Applied, apply};
use crate::plane::call::{self, ACT, PUBLICATION, WAIT};
use crate::plane::call::{LONGEST_WAIT, WATCH};
use crate::plane::listener::Serve;
use crate::plane::local::Stream;
use crate::plane::role::{Role, admitted};

/// The most a handshake, or a write to a surface that does not read,
/// waits.
const PATIENCE: Duration = Duration::from_secs(5);

/// The audit action every act through the gate records — the one
/// `GatedOperator.AuditAction` names.
pub const AUDIT_ACTION: &str = "act";

/// Serve one network connection until the surface or the listener ends
/// it: mutual TLS agreeing `h2`, the caller its certificate's subject.
pub(crate) fn answer(connection: TcpStream, peer: SocketAddr, serve: &Serve) {
    let settled = connection
        .set_nodelay(true)
        .and_then(|()| connection.set_read_timeout(Some(PATIENCE)))
        .and_then(|()| connection.set_write_timeout(Some(PATIENCE)));
    let Some(config) = serve.config.as_ref() else {
        return;
    };
    let guarded = settled
        .map_err(|error| error.to_string())
        .and_then(|()| tls::server(connection, Arc::clone(config)).map_err(|e| e.message))
        .and_then(|mut guarded| {
            let agreed = tls::alpn::agreed(&mut guarded).map_err(|e| e.message)?;
            if agreed.as_deref() != Some(b"h2") {
                return Err("refused: the surface did not agree h2".to_string());
            }
            let who = proven(&guarded)?;
            // A connection waits on its surface for as long as it is held,
            // looking each WATCH whether the listener stops.
            guarded
                .sock
                .set_read_timeout(Some(WATCH))
                .map_err(|error| error.to_string())?;
            Ok((guarded, who))
        });
    match guarded {
        Ok((guarded, who)) => calls(
            Box::new(Watched::new(guarded, || serve.stopped())),
            &who,
            serve,
        ),
        Err(reason) => noted(serve, &peer.to_string(), &format!("refused: {reason}")),
    }
}

/// Serve one connection on the node's local endpoint: plain HTTP/2, the
/// caller the user the operating system says its process runs as.
pub(crate) fn answer_local(mut stream: Stream, serve: &Serve) {
    let who = match stream.caller() {
        Ok(who) => who,
        Err(reason) => return noted(serve, "the local endpoint", &format!("refused: {reason}")),
    };
    if let Err(error) = stream.watch(WATCH) {
        return noted(serve, &who, &format!("refused: {error}"));
    }
    calls(
        Box::new(Watched::new(stream, || serve.stopped())),
        &who,
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
fn calls(connection: Boxed<'_>, who: &str, serve: &Serve) {
    let Ok(mut server) = BoxedServer::handshake(connection) else {
        return;
    };
    while !serve.stopped() {
        let Ok(Some((stream, request))) = server.next_request() else {
            break;
        };
        let response = called(serve, who, &request);
        if server.respond(stream, &response).is_err() {
            break;
        }
    }
}
/// The subject of the certificate the surface presented, which the
/// handshake checked against the anchors.
fn proven(guarded: &tls::GuardedServer) -> Result<String, String> {
    let leaf = guarded
        .conn
        .peer_certificates()
        .and_then(<[_]>::first)
        .ok_or_else(|| "the surface presented no certificate".to_string())?;
    Name::subject_of(leaf)
        .map(|name| name.to_string())
        .map_err(|failed| failed.to_string())
}

/// The answer to one call.
fn called(serve: &Serve, who: &str, request: &Request) -> Response {
    let message = match call::message(request) {
        Ok(message) => message,
        Err(why) => return call::refusal("INVALID_ARGUMENT", &why),
    };
    match call::method(&request.path) {
        Some(PUBLICATION) => {
            let (revision, text) = serve.published.read();
            call::answer(&json!({ "revision": revision, "publication": text }))
        }
        Some(WAIT) => {
            let after = message["after"].as_u64().unwrap_or(0);
            let within = message["within_ms"]
                .as_u64()
                .map_or(LONGEST_WAIT, Duration::from_millis)
                .min(LONGEST_WAIT);
            let stopped = || serve.stopped();
            let revision = serve.published.wait(after, within, &stopped);
            call::answer(&json!({ "revision": revision }))
        }
        Some(ACT) => acted(serve, who, &message),
        _ => call::refusal(
            "UNIMPLEMENTED",
            &format!("{} is no method of {}", request.path, call::SERVICE),
        ),
    }
}

/// An act: read, admitted by the caller's role, applied, and what came of
/// it — `taken`, `denied` by role, `refused` by the node, `invalid` for no
/// act the noun takes, or `failed`.
fn acted(serve: &Serve, who: &str, message: &Value) -> Response {
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
    // Every caller here is proven, by its certificate or by the operating
    // system; the role is the one the node's configuration states,
    // Observer where it states none.
    let role = serve.stated.unwrap_or_default();
    let thing = format!("{} '{target}' at {node}", noun.called());
    let gate = admitted(Some(who), role, act.word(), &thing);
    record(serve, who, role, act.word(), &thing, gate.as_ref().err());
    if let Err(refused) = gate {
        return outcome("denied", &refused);
    }
    let order = Order {
        node,
        noun,
        target,
        act,
        who: who.to_string(),
    };
    match apply(&order) {
        Applied::Taken(said) => {
            serve.published.acted();
            outcome("taken", &said)
        }
        Applied::Refused(said) => outcome("refused", &said),
        Applied::Failed(said) => outcome("failed", &said),
    }
}

fn outcome(word: &str, said: &str) -> Response {
    call::answer(&json!({ "outcome": word, "said": said }))
}

/// The gate's record, as `GatedOperator` writes it: who, the act, its
/// target and the role, taken or refused.
fn record(serve: &Serve, who: &str, role: Role, act: &str, target: &str, refused: Option<&String>) {
    let asked = format!("{who} asked to {act} {target}");
    let (phase, severity, message) = match refused {
        None => (
            ExecutionPhase::Execute,
            Severity::Information,
            asked.as_str(),
        ),
        Some(refused) => (ExecutionPhase::Failure, Severity::Warning, refused.as_str()),
    };
    let properties = BTreeMap::from([
        ("act".to_string(), act.to_string()),
        ("target".to_string(), target.to_string()),
        ("who".to_string(), who.to_string()),
        ("role".to_string(), role.word().to_string()),
    ]);
    let _ = serve
        .audit
        .record(AUDIT_ACTION, phase, severity, Some(message), properties);
}

/// A connection refused, in the node's audit.
fn noted(serve: &Serve, peer: &str, message: &str) {
    let properties = BTreeMap::from([("peer".to_string(), peer.to_string())]);
    let _ = serve.audit.record(
        "operate.connection",
        ExecutionPhase::Failure,
        Severity::Warning,
        Some(message),
        properties,
    );
}
