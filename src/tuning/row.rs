//! How a `[tuning]` row is written in its declaration (`super::declared`):
//! a duration or a count either direction reads, its default the constant
//! beside the code it bounds.

use std::time::Duration;

use xcore::settings::{Applies, Fixed, Kind, Presence, Setting};

/// A duration either direction reads, its default the constant beside the
/// code it bounds: the Storage client's and node's, the operate plane's, the
/// sync plane's (`xcluster::timing`) and the connect's.
pub(super) const fn duration(
    name: &'static str,
    default: Duration,
    meaning: &'static str,
) -> Setting {
    Setting {
        name,
        kind: Kind::Duration,
        presence: Presence::Default(Fixed::Duration(default)),
        meaning,
        applies: Applies::Both,
    }
}

/// A count either direction reads, from `minimum` to `maximum`, its default
/// the constant beside the code it bounds.
pub(super) const fn count(
    name: &'static str,
    (minimum, maximum): (i64, i64),
    default: usize,
    meaning: &'static str,
) -> Setting {
    Setting {
        name,
        kind: Kind::Integer { minimum, maximum },
        presence: Presence::Default(Fixed::Integer(as_integer(default))),
        meaning,
        applies: Applies::Both,
    }
}

/// A count as the declaration writes its default.
#[allow(clippy::cast_possible_wrap)]
pub(super) const fn as_integer(count: usize) -> i64 {
    count as i64
}
