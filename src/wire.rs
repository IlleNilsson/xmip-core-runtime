//! The header's integers for observe's enums, in both directions.
//!
//! `xmip_operate.h` carries health and the counted thing as `int`, and
//! `xmip-core-observe` keeps them as enums. The two conversions live here so
//! `operate.rs` holds the table and nothing else. A value the header does not
//! name is `None`, which the table answers with `XMIP_E_MALFORMED`.
//!
//! It stays in the runtime under ADR-0058: this is the only crate that has
//! both the header's constants and observe's enums, and neither of those two
//! may depend on the other — `xmip-core-abi` is Foundation and
//! `xmip-core-observe` is Operation.

use abi::operate::{counted, health};
use observe::{Counted, Health};

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
}
