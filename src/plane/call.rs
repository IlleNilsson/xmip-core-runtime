//! One call of the operate service as it crosses: a method of
//! [`SERVICE`] on a stream of its own, its message JSON in a gRPC frame
//! (`application/grpc+json`), and the answer's status in its trailers —
//! the request built and the answer read here, for both ends, once.

use std::time::Duration;

use net::grpc;
use net::http::{Request, Response};
use serde_json::Value;

/// How often a connection waiting on its peer looks whether its end stops
/// — a listener stopping, a surface ending. An arriving byte wakes it at
/// once; this bounds only how long a stop waits for an idle connection.
pub(crate) const WATCH: Duration = Duration::from_millis(50);

/// The longest one wait is held before it is answered with the revision
/// unchanged: what a surface's own patience allows for.
pub const LONGEST_WAIT: Duration = Duration::from_secs(25);

/// The service a node's operate listener answers.
pub const SERVICE: &str = "xmip.operate.v1.Operate";

/// The node's publication and its revision.
pub const PUBLICATION: &str = "Publication";

/// The revision once it is past the one a surface last saw.
pub const WAIT: &str = "Wait";

/// An operator's act on what the node publishes.
pub const ACT: &str = "Act";

/// A secret set through the node (`crate::secret`): an Operator's act.
pub const SECRET: &str = "SetSecret";

/// The secrets the node keeps, by name, never a value.
pub const SECRETS: &str = "Secrets";

/// A relay hands the node the certificate a caller presented to it, and is
/// answered the node's handle for that caller (`plane::vouched`).
pub const VOUCH: &str = "Vouch";

/// A relay lets a caller it was answered a handle for go.
pub const UNVOUCH: &str = "Unvouch";

/// The header a relay names the caller in, by the node's handle for it,
/// so the node decides whose call it is before it reads the call.
pub const CALLER_HEADER: &str = "xmip-caller";

/// What a node answers a relay whose handle it does not hold for the
/// account the call came through: no one, and a relay that holds the
/// caller vouches for it again.
pub const UNKNOWN_CALLER: &str =
    "REFUSED. Nothing proved who asks: the node holds no caller by that handle for this relay";

/// What every refusal of a call by the node opens with.
pub const REFUSED_CALL: &str = "the node refused the call";

/// The path a method is called at.
#[must_use]
pub fn path(method: &str) -> String {
    format!("/{SERVICE}/{method}")
}

/// The method a path calls, where it is one of [`SERVICE`]'s.
#[must_use]
pub fn method(path: &str) -> Option<&str> {
    path.strip_prefix('/')
        .and_then(|rest| rest.strip_prefix(SERVICE))
        .and_then(|rest| rest.strip_prefix('/'))
}

/// `method` called at `authority` with `message`, for the caller the
/// node's handle `caller` names where a relay calls for one
/// ([`CALLER_HEADER`]).
///
/// # Errors
///
/// A message no frame holds.
pub fn request(
    authority: &str,
    method: &str,
    message: &Value,
    caller: Option<u64>,
) -> Result<Request, String> {
    let body = grpc::frame(message.to_string().as_bytes()).map_err(|failed| failed.message)?;
    let request = Request::new("POST", path(method))
        .header("host", authority)
        .header("content-type", grpc::CONTENT_TYPE_JSON)
        .header("te", "trailers");
    let request = match caller {
        Some(caller) => request.header(CALLER_HEADER, &caller.to_string()),
        None => request,
    };
    Ok(request.body(&body))
}

/// The node's handle a call names its caller by, where it names one; 0 —
/// no one — for a header that is no handle.
#[must_use]
pub fn caller_of(request: &Request) -> Option<u64> {
    request
        .header_value(CALLER_HEADER)
        .map(|value| value.trim().parse().unwrap_or(0))
}

/// The message a request carries.
///
/// # Errors
///
/// A body that is no frame, or a frame that is not JSON.
pub fn message(request: &Request) -> Result<Value, String> {
    let (message, _) = grpc::unframe(&request.body).map_err(|failed| failed.message)?;
    serde_json::from_slice(message).map_err(|error| format!("the message is not JSON: {error}"))
}

/// An answer carrying `message`, status OK.
#[must_use]
pub fn answer(message: &Value) -> Response {
    match grpc::frame(message.to_string().as_bytes()) {
        Ok(body) => Response::new(200)
            .header("content-type", grpc::CONTENT_TYPE_JSON)
            .body(&body)
            .trailer(grpc::STATUS, "0"),
        Err(failed) => refusal("INTERNAL", &failed.message),
    }
}

/// An answer with no message: the status `name` and why, in words.
#[must_use]
pub fn refusal(name: &str, why: &str) -> Response {
    Response::new(200)
        .header("content-type", grpc::CONTENT_TYPE_JSON)
        .trailer(grpc::STATUS, &grpc::code(name).to_string())
        .trailer(grpc::MESSAGE, &codec::percent::encode(why, false))
}

/// The message an answer carries.
///
/// # Errors
///
/// An answer that is no gRPC answer, a status other than OK — said with
/// its words — or a message that is not JSON.
pub fn answered(response: &Response) -> Result<Value, String> {
    if response.status != 200 {
        return Err(format!("the node answered HTTP {}", response.status));
    }
    let field = |name: &str| {
        response
            .trailers
            .iter()
            .chain(&response.headers)
            .find(|(field, _)| field.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    };
    let status = field(grpc::STATUS).unwrap_or("2");
    if status != "0" {
        let said = field(grpc::MESSAGE).map_or_else(String::new, codec::percent::decode);
        return Err(format!("{REFUSED_CALL} ({status}): {said}"));
    }
    let (message, _) = grpc::unframe(&response.body).map_err(|failed| failed.message)?;
    serde_json::from_slice(message).map_err(|error| format!("the answer is not JSON: {error}"))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn a_call_round_trips_and_names_its_method() {
        let sent = request("node:1", WAIT, &json!({ "after": 3 }), None).expect("a request");
        assert_eq!(method(&sent.path), Some(WAIT));
        assert_eq!(caller_of(&sent), None, "no caller named");
        let relayed = request("node:1", ACT, &json!({}), Some(42)).expect("a request");
        assert_eq!(caller_of(&relayed), Some(42));
        assert_eq!(message(&sent).expect("read")["after"], 3);
        let back = answered(&answer(&json!({ "revision": 4 }))).expect("answered");
        assert_eq!(back["revision"], 4);
    }

    #[test]
    fn a_refusal_is_said_in_its_words() {
        let refused = answered(&refusal("UNIMPLEMENTED", "no method Nope")).unwrap_err();
        assert_eq!(refused, "the node refused the call (12): no method Nope");
        assert_eq!(method("/other.Service/Wait"), None);
    }
}
