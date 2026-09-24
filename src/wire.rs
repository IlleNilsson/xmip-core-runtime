//! The header's integers for observe's enums, in both directions.
//!
//! `xmip_operate.h` carries health, the counted thing and a topology's kind,
//! origin and pattern as `int`, and `xmip-core-observe` keeps them as enums. The two conversions live here so
//! `operate.rs` holds the table and nothing else. A value the header does not
//! name is `None`, which the table answers with `XMIP_E_MALFORMED`.
//!
//! It stays in the runtime under ADR-0058: this is the only crate that has
//! both the header's constants and observe's enums, and neither of those two
//! may depend on the other — `xmip-core-abi` is Foundation and
//! `xmip-core-observe` is Operation.

use abi::operate::publication::{kind, origin, pattern};
use abi::operate::{counted, health};
use observe::{Counted, Health, NodeKind, Origin, Pattern};

/// The header's `int` for an observe `Health`.
pub(crate) const fn wire_health(value: Health) -> i32 {
    match value {
        Health::Fine => health::FINE,
        Health::Paused => health::PAUSED,
        Health::Working => health::WORKING,
        Health::Stressed => health::STRESSED,
        Health::Exhausted => health::EXHAUSTED,
        Health::Done => health::DONE,
        Health::Holding => health::HOLDING,
    }
}

/// An observe `Health` for the header's `int`, or `None` for a value section
/// 3 does not define.
pub(crate) const fn from_wire_health(value: i32) -> Option<Health> {
    match value {
        health::FINE => Some(Health::Fine),
        health::PAUSED => Some(Health::Paused),
        health::WORKING => Some(Health::Working),
        health::STRESSED => Some(Health::Stressed),
        health::EXHAUSTED => Some(Health::Exhausted),
        health::DONE => Some(Health::Done),
        health::HOLDING => Some(Health::Holding),
        _ => None,
    }
}

/// An observe `Counted` for the header's `int`, or `None`.
pub(crate) const fn from_wire_counted(value: i32) -> Option<Counted> {
    match value {
        counted::STREAMS => Some(Counted::Streams),
        counted::MESSAGES => Some(Counted::Messages),
        counted::JOURNEYS => Some(Counted::Journeys),
        counted::BYTES => Some(Counted::Bytes),
        counted::RETRYING => Some(Counted::Retrying),
        counted::FAILED => Some(Counted::Failed),
        _ => None,
    }
}

/// The header's `int` for an observe `Counted`.
pub(crate) const fn wire_counted(value: Counted) -> i32 {
    match value {
        Counted::Streams => counted::STREAMS,
        Counted::Messages => counted::MESSAGES,
        Counted::Journeys => counted::JOURNEYS,
        Counted::Bytes => counted::BYTES,
        Counted::Retrying => counted::RETRYING,
        Counted::Failed => counted::FAILED,
    }
}

/// The header's `XmipTopologyKind` for an observe `NodeKind`.
pub(crate) const fn wire_kind(value: NodeKind) -> i32 {
    match value {
        NodeKind::Computer => kind::COMPUTER,
        NodeKind::Server => kind::SERVER,
        NodeKind::VirtualMachine => kind::VIRTUAL_MACHINE,
        NodeKind::Gateway => kind::GATEWAY,
        NodeKind::Appliance => kind::APPLIANCE,
        NodeKind::Service => kind::SERVICE,
        NodeKind::Process => kind::PROCESS,
        NodeKind::Interface => kind::INTERFACE,
        NodeKind::Port => kind::PORT,
        NodeKind::Protocol => kind::PROTOCOL,
        NodeKind::Location => kind::LOCATION,
        NodeKind::Cluster => kind::CLUSTER,
        NodeKind::Node => kind::NODE,
        NodeKind::Stage => kind::STAGE,
        NodeKind::Endpoint => kind::ENDPOINT,
    }
}

/// The header's `XmipTopologyOrigin` for an observe `Origin`.
pub(crate) const fn wire_origin(value: Origin) -> i32 {
    match value {
        Origin::Configured => origin::CONFIGURED,
        Origin::Observed => origin::OBSERVED,
        Origin::Both => origin::BOTH,
    }
}

/// The header's `XmipCommunicationPattern` for an observe `Pattern`.
pub(crate) const fn wire_pattern(value: Pattern) -> i32 {
    match value {
        Pattern::RequestResponse => pattern::REQUEST_RESPONSE,
        Pattern::SendReceive => pattern::SEND_RECEIVE,
        Pattern::PublishConsume => pattern::PUBLISH_CONSUME,
        Pattern::Streaming => pattern::STREAMING,
        Pattern::FireAndForget => pattern::FIRE_AND_FORGET,
        Pattern::Session => pattern::SESSION,
        Pattern::Retry => pattern::RETRY,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_counted_thing_the_header_names_comes_back() {
        assert_eq!(from_wire_counted(counted::STREAMS), Some(Counted::Streams));
        assert_eq!(
            from_wire_counted(counted::RETRYING),
            Some(Counted::Retrying)
        );
        assert_eq!(from_wire_counted(counted::FAILED), Some(Counted::Failed));
        assert_eq!(from_wire_counted(0), None);
    }

    #[test]
    fn health_crosses_as_the_header_says() {
        assert_eq!(wire_health(Health::Fine), health::FINE);
        assert_eq!(wire_health(Health::Holding), health::HOLDING);
    }

    #[test]
    fn every_mood_comes_back_from_its_wire_value_and_nothing_else_does() {
        for mood in Health::ALL {
            assert_eq!(from_wire_health(wire_health(mood)), Some(mood));
        }
        assert_eq!(from_wire_health(7), None);
        assert_eq!(from_wire_health(-1), None);
    }

    #[test]
    fn every_counted_thing_crosses_and_comes_back() {
        for counted in Counted::ALL {
            assert_eq!(from_wire_counted(wire_counted(counted)), Some(counted));
        }
    }

    #[test]
    fn every_topology_word_has_its_own_header_value_in_the_headers_order() {
        let kinds: Vec<i32> = NodeKind::ALL.iter().map(|k| wire_kind(*k)).collect();
        let origins: Vec<i32> = Origin::ALL.iter().map(|o| wire_origin(*o)).collect();
        let patterns: Vec<i32> = Pattern::ALL.iter().map(|p| wire_pattern(*p)).collect();

        assert_eq!(kinds, (0..15).collect::<Vec<i32>>());
        assert_eq!(origins, [0, 1, 2]);
        assert_eq!(patterns, (0..7).collect::<Vec<i32>>());
    }
}
