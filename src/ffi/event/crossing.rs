//! An Event and a filter as `xmip_operate.h` section 11 lays them out,
//! read from a program and written for one: the crossing `ffi/event.rs`'s
//! exports make, and nothing the event crate decides. The header's action
//! and outcome integers are read and written by `crate::wire`.
//!
//! In `ffi/`, the one folder of the runtime that may hold unsafe code
//! (ADR-0050, refined 2026-09-25): a program's pointers are read here.
#![allow(unsafe_code)]

use std::collections::BTreeMap;
use std::path::Path;

use abi::ffi::{Str, status};
use abi::operate::event::{Event as Wire, EventFilter};
use xaudit::program_audit::ProgramAudit;
use xevent::Event;
use xevent::filter::Filter;
use xevent::subscriber::Subscriber;

use crate::ffi::operate::{borrow, scope_text};
use crate::wire::{outcome_of, stage_of, wire_outcome, wire_stage};

/// The text an Event's identifiers are written as, and its diagnostics as
/// the header's strings, owned beside the Event they borrow from.
pub(super) struct Texts {
    id: String,
    journey: String,
    message: String,
    stream: String,
    party: String,
    diagnostics: Vec<Str>,
}

/// The subscriber and filter a subscribe asked with, or the status that
/// refuses them.
///
/// # Safety
/// As `xmip_event_subscribe_v1`.
pub(super) unsafe fn asked(
    program: Str,
    directory: Str,
    subscriber: Str,
    filter: *const EventFilter,
) -> Result<(Subscriber, Filter), i32> {
    // SAFETY: the caller upholds the contract on every string.
    let (program, directory, party) = unsafe {
        (
            scope_text(program).ok_or(status::MALFORMED)?,
            scope_text(directory).ok_or(status::MALFORMED)?,
            scope_text(subscriber).ok_or(status::MALFORMED)?,
        )
    };
    if party.is_empty() {
        return Err(status::INVALID);
    }
    let party = party.parse().map_err(|_| status::MALFORMED)?;
    let stated = (!directory.is_empty()).then(|| Path::new(directory));
    let subscriber = Subscriber::in_process(party, ProgramAudit::new(program, stated));
    // SAFETY: filter is null or readable with its lists, per the contract.
    let filter = match unsafe { filter.as_ref() } {
        None => Filter::everything(),
        Some(wire) => unsafe { filter_of(wire)? },
    };
    Ok((subscriber, filter))
}

/// A filter as the event crate reads one.
///
/// # Safety
/// The filter's lists hold their stated lengths and its strings theirs.
pub(super) unsafe fn filter_of(wire: &EventFilter) -> Result<Filter, i32> {
    // SAFETY: per the contract.
    let (types, outcomes, scope, party) = unsafe {
        (
            slice(wire.types, wire.types_len),
            slice(wire.outcomes, wire.outcomes_len),
            scope_text(wire.scope).ok_or(status::MALFORMED)?,
            scope_text(wire.party).ok_or(status::MALFORMED)?,
        )
    };
    let mut filter = Filter::everything();
    for kind in types {
        // SAFETY: each type points at its stated length.
        filter.types.push(
            unsafe { scope_text(*kind) }
                .ok_or(status::MALFORMED)?
                .to_string(),
        );
    }
    for number in outcomes {
        filter
            .outcomes
            .push(outcome_of(*number).ok_or(status::INVALID)?);
    }
    filter.scope = (!scope.is_empty()).then(|| scope.to_string());
    filter.party = match party {
        "" => None,
        party => Some(party.parse().map_err(|_| status::MALFORMED)?),
    };
    Ok(filter)
}

/// An Event the program raised, as the event crate holds one.
///
/// # Safety
/// The Event's strings and diagnostics hold their stated lengths.
pub(super) unsafe fn event_of(wire: &Wire) -> Result<Event, i32> {
    // SAFETY: each string per the contract.
    let text = |value: Str| unsafe { scope_text(value) }.ok_or(status::MALFORMED);
    let optional = |value: Str| text(value).map(|t| (!t.is_empty()).then(|| t.to_string()));
    let (kind, scope) = (text(wire.kind)?, text(wire.scope)?);
    let stage = stage_of(wire.action).ok_or(status::INVALID)?;
    let ended = outcome_of(wire.outcome).ok_or(status::INVALID)?;
    if kind.is_empty() || scope.is_empty() || !wire.diagnostics_len.is_multiple_of(2) {
        return Err(status::INVALID);
    }
    let mut event = Event::raised(kind, stage, ended, scope);
    let parsed = |value: Str| -> Result<Option<u128>, i32> {
        optional(value)?
            .map(|t| t.parse::<xcore::EventId>().map(xcore::EventId::value))
            .transpose()
            .map_err(|_| status::MALFORMED)
    };
    if let Some(id) = parsed(wire.id)? {
        event.id = xcore::EventId::new(id);
    }
    if wire.time_unix_nanos != 0 {
        event.time_unix_nanos = i128::from(wire.time_unix_nanos);
    }
    event.journey = parsed(wire.journey)?.map(xcore::JourneyId::new);
    event.message = parsed(wire.message)?.map(xcore::MessageId::new);
    event.stream = parsed(wire.stream)?.map(xcore::StreamId::new);
    event.party = parsed(wire.party)?.map(xcore::PartyId::new);
    event.endpoint = optional(wire.endpoint)?;
    event.module = optional(wire.module)?;
    event.artifact = optional(wire.artifact)?;
    // SAFETY: diagnostics holds diagnostics_len strings per the contract.
    let pairs = unsafe { slice(wire.diagnostics, wire.diagnostics_len) };
    let mut diagnostics = BTreeMap::new();
    for [name, value] in pairs.as_chunks::<2>().0 {
        diagnostics.insert(text(*name)?.to_string(), text(*value)?.to_string());
    }
    event.diagnostics = diagnostics;
    Ok(event)
}

/// An Event's identifiers as text, and its diagnostics as strings that
/// borrow from it.
pub(super) fn texts_of(event: &Event) -> Texts {
    let text = |id: Option<String>| id.unwrap_or_default();
    Texts {
        id: event.id.to_string(),
        journey: text(event.journey.map(|id| id.to_string())),
        message: text(event.message.map(|id| id.to_string())),
        stream: text(event.stream.map(|id| id.to_string())),
        party: text(event.party.map(|id| id.to_string())),
        diagnostics: event
            .diagnostics
            .iter()
            .flat_map(|(name, value)| [borrow(name), borrow(value)])
            .collect(),
    }
}

/// The header's Event, borrowing from `event` and `texts`.
pub(super) fn view_of(event: &Event, texts: &Texts) -> Wire {
    let optional = |value: &Option<String>| value.as_deref().map_or(Str::empty(), borrow);
    Wire {
        id: borrow(&texts.id),
        kind: borrow(&event.kind),
        time_unix_nanos: i64::try_from(event.time_unix_nanos).unwrap_or(i64::MAX),
        action: wire_stage(event.action),
        outcome: wire_outcome(event.outcome),
        scope: borrow(&event.scope),
        journey: borrow(&texts.journey),
        message: borrow(&texts.message),
        stream: borrow(&texts.stream),
        endpoint: optional(&event.endpoint),
        module: optional(&event.module),
        artifact: optional(&event.artifact),
        party: borrow(&texts.party),
        diagnostics: texts.diagnostics.as_ptr(),
        diagnostics_len: texts.diagnostics.len(),
    }
}

/// `len` items at `items`, or none.
///
/// # Safety
/// `items` holds `len` readable items, or `len` is 0.
pub(super) unsafe fn slice<'a, T>(items: *const T, len: usize) -> &'a [T] {
    if items.is_null() || len == 0 {
        return &[];
    }
    // SAFETY: per the contract above.
    unsafe { core::slice::from_raw_parts(items, len) }
}
