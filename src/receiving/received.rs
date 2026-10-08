//! One arrival as the runtime takes it from its transport: everything the
//! transport handed over, and nothing dropped.
//!
//! The owner, 2026-10-06: *The first stream will come from somewhere, it will
//! carry its identity via transport or on its message* — *that goes for all
//! streams*. What the transport observed of the sender — the socket peer, a
//! TLS peer certificate, an SSH key, the request line — reaches the identity
//! gates under the name it was written by (ADR-0019 clause 5, amendment
//! 2026-09-24); the headers its protocol delivered reach the gates and the
//! Message Context as `<protocol>.header.<name>` (ADR-0046, amendment
//! 2026-09-25, later); and how it got here, pushed, detected or scheduled,
//! is what the technology said (ADR-0019 clause 8).

use receive::ReceivedStream;
use transport::{Acknowledgement, Arrived};
use xcore::Arriving;

/// `arrived` as the message path reads it, and the acknowledgement its far
/// end is told by once the receive cycle ends.
pub(super) fn received(mut arrived: Arrived) -> (ReceivedStream, Acknowledgement) {
    let headers = arrived.take_headers();
    let observed = arrived.take_observed();
    let arriving = arrived.arriving();
    let (origin_uri, body, acknowledgement) = arrived.into_parts();

    let mut received = match arriving {
        Arriving::Pushed => ReceivedStream::new(body, origin_uri),
        Arriving::Detected => ReceivedStream::new(body, origin_uri).detected(),
        Arriving::Scheduled => ReceivedStream::new(body, origin_uri).scheduled(),
    };
    for (name, value) in observed {
        received = received.with_property(name, value);
    }
    let (protocol, fields) = headers.into_parts();
    for (name, value) in fields {
        received = received.with_header(&protocol, &name, value);
    }
    (received, acknowledgement)
}

#[cfg(test)]
mod tests {
    use super::*;
    use context::property::{HTTP_AUTHORIZATION, PEER_ADDRESS};
    use transport::Headers;
    use xcore::ScalarValue;

    #[test]
    fn nothing_the_transport_handed_over_is_dropped() {
        let peer = "192.0.2.10:4711".parse().expect("an address");
        let arrived = Arrived::whole(
            "http://192.0.2.10:4711/in",
            b"{}".to_vec(),
            Acknowledgement::at_most_once("a test"),
        )
        .with_headers(Headers::of("http").text([("Authorization", "Bearer t-1")]))
        .from_peer(peer)
        .detected();

        let (received, _) = received(arrived);

        assert_eq!(received.arriving, Arriving::Detected);
        assert_eq!(received.source_uri, "http://192.0.2.10:4711/in");
        let observed = received.observed();
        assert!(observed.contains(&(PEER_ADDRESS.into(), "192.0.2.10:4711".into())));
        assert!(observed.contains(&(HTTP_AUTHORIZATION.into(), "Bearer t-1".into())));
        assert_eq!(
            received.headers,
            [(
                HTTP_AUTHORIZATION.to_string(),
                ScalarValue::Text("Bearer t-1".into())
            )]
        );
    }
}
