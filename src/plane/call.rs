//! One call of the operate service as it crosses: a method of
//! [`SERVICE`] on a stream of its own, its message JSON in a gRPC frame
//! (`application/grpc+json`), and the answer's status in its trailers —
//! the request built and the answer read here, for both ends, once.

use net::grpc;
use net::http::{Request, Response};
use serde_json::Value;

/// The service a node's operate listener answers.
pub const SERVICE: &str = "xmip.operate.v1.Operate";

/// The node's publication and its revision.
pub const PUBLICATION: &str = "Publication";

/// The revision once it is past the one a surface last saw.
pub const WAIT: &str = "Wait";

/// An operator's act on what the node publishes.
pub const ACT: &str = "Act";

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

/// `method` called at `authority` with `message`.
///
/// # Errors
///
/// A message no frame holds.
pub fn request(authority: &str, method: &str, message: &Value) -> Result<Request, String> {
    let body = grpc::frame(message.to_string().as_bytes()).map_err(|failed| failed.message)?;
    Ok(Request::new("POST", path(method))
        .header("host", authority)
        .header("content-type", grpc::CONTENT_TYPE_JSON)
        .header("te", "trailers")
        .body(&body))
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
        .trailer(grpc::MESSAGE, &net::percent::encode(why, false))
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
        let said = field(grpc::MESSAGE).map_or_else(String::new, net::percent::decode);
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
        let sent = request("node:1", WAIT, &json!({ "after": 3 })).expect("a request");
        assert_eq!(method(&sent.path), Some(WAIT));
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
