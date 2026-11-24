//! The promote trait of a loaded module, driven through its table
//! (`include/xmip_module.h` section 14; ADR-0066, amendment 2026-10-22;
//! ADR-0075).
//!
//! A Promote unit reads values out of a Message's content into its context,
//! at receive. It ships apart from Xmip as a library a node loads, written
//! in any language that exports the table — Rust, C, or .NET published
//! with NativeAOT over `Xmip.Module`. This is the host side of it: a step
//! entry opened once with its settings in their transfer form, the content
//! handed in through an `XmipReader`, and each value the unit hands the
//! host's sink copied out as the `ScalarValue` it is.
//!
//! A node does not run a step entry yet (`configure::step::unrun`): this is
//! the table's loader, and its tests are what call it.
#![allow(unsafe_code)]

use std::ffi::c_void;

use abi::Expectation;
use abi::ffi::{PromoteVtable, PromotionSink, Reader, Slice, Str, status, value_kind};
use codec::cursor::Cursor;
use node::Stage;
use xcore::ScalarValue;
use xcore::settings::Given;

use crate::ffi::lifecycle::Lifecycle;
use crate::ffi::loaded_contract::read_source;
use crate::ffi::loaded_module::{LoadedModule, read_str};

/// The trait this file drives, as `descriptor.module` spells it: the
/// promote capability's word, as a manifest writes it.
pub const PROMOTE: &str = abi::UnitCapability::Promote.word();

/// What this host requires of a module offering the promote trait.
#[must_use]
pub fn expectation() -> Expectation {
    Expectation::new(PROMOTE, 1, 0)
}

/// The promote table of one loaded module, borrowed for as long as the
/// module is held.
pub struct LoadedPromotion<'a> {
    module: &'a LoadedModule,
    table: &'a PromoteVtable,
}

impl<'a> LoadedPromotion<'a> {
    /// Select this module's promote table, by the name in its descriptor.
    ///
    /// # Errors
    /// A module that answers another trait, or names this one and carries
    /// no table.
    pub fn of(module: &'a LoadedModule) -> Result<Self, String> {
        let descriptor = module.descriptor();
        if descriptor.module != PROMOTE {
            return Err(format!(
                "{descriptor} answers the '{}' trait, not '{PROMOTE}'",
                descriptor.module
            ));
        }
        if module.vtable().is_null() {
            return Err(format!(
                "{descriptor} names the '{PROMOTE}' trait and carries no table"
            ));
        }
        // SAFETY: header section 7 — the table is the one `descriptor.module`
        // names, checked above, and lives in the library `module` holds,
        // which this borrow cannot outlive.
        let table = unsafe { &*module.vtable().cast::<PromoteVtable>() };
        Ok(Self { module, table })
    }

    /// Header section 8: `configure` once, before `start`, then `start`
    /// and `stop`.
    #[must_use]
    pub const fn lifecycle(&self) -> Lifecycle<'a> {
        Lifecycle::of(self.module, &self.table.header)
    }

    /// Open the unit for one step entry at `stage`, with its settings
    /// `given` as read through the unit's declaration, every default
    /// filled in (header section 14).
    ///
    /// # Errors
    /// A table with no `open`, or the unit's refusal, with why.
    pub fn open(&self, stage: Stage, given: &[(String, Given)]) -> Result<PromoteStep<'_>, String> {
        let open = self
            .table
            .open
            .ok_or_else(|| format!("{} carries no open", self.module.descriptor()))?;
        let (word, settings) = (stage.name(), transferred(given).to_string());
        let mut step: *mut c_void = std::ptr::null_mut();
        // SAFETY: `word` and `settings` outlive the call and the unit copies
        // what it keeps; `step` is a live local it writes at most once.
        let answer = unsafe {
            open(
                self.module.state(),
                Str::from_static(word),
                Str {
                    ptr: settings.as_ptr(),
                    len: settings.len(),
                },
                &raw mut step,
            )
        };
        if answer != status::OK || step.is_null() {
            return Err(format!(
                "{} refused the step: status {answer}: {}",
                self.module.descriptor(),
                self.module.last_error()
            ));
        }
        Ok(PromoteStep { of: self, step })
    }
}

/// A step entry's settings in their transfer form, one JSON object: text
/// as a string, an integer as a number, a boolean as itself, a table as an
/// object of its values (header section 14).
fn transferred(given: &[(String, Given)]) -> serde_json::Value {
    serde_json::Value::Object(
        given
            .iter()
            .map(|(name, value)| (name.clone(), transferred_value(value)))
            .collect(),
    )
}

fn transferred_value(value: &Given) -> serde_json::Value {
    match value {
        Given::Text(text) => serde_json::Value::from(text.as_str()),
        Given::Integer(integer) => serde_json::Value::from(*integer),
        Given::Boolean(boolean) => serde_json::Value::from(*boolean),
        Given::Table(table) => transferred(table),
        // Refused by the unit's declaration before any step opens.
        Given::Other(_) => serde_json::Value::Null,
    }
}

/// One opened step. Released through the unit that opened it — no
/// allocator is shared across the boundary (specification section 4).
pub struct PromoteStep<'a> {
    of: &'a LoadedPromotion<'a>,
    step: *mut c_void,
}

/// What the sink was handed during one `promote`, or the first thing it
/// refused.
#[derive(Default)]
struct Gathered {
    values: Vec<(String, ScalarValue)>,
    refused: Option<String>,
}

impl PromoteStep<'_> {
    /// The values the unit promotes from `content`, each under its
    /// property, in the order it handed them.
    ///
    /// # Errors
    /// A table with no `promote`, the unit's own status with why, or a value
    /// handed in a kind the header does not give a promoted value.
    pub fn promote(&self, content: &[u8]) -> Result<Vec<(String, ScalarValue)>, String> {
        let promote = self
            .of
            .table
            .promote
            .ok_or_else(|| format!("{} carries no promote", self.of.module.descriptor()))?;
        let mut source = Cursor::new(content);
        let reader = Reader {
            ctx: (&raw mut source).cast(),
            read: Some(read_source),
        };
        let mut gathered = Gathered::default();
        let sink = PromotionSink {
            ctx: (&raw mut gathered).cast(),
            promoted: Some(take_promoted),
        };
        // SAFETY: `source`, `reader`, `gathered` and `sink` live across the
        // call and the unit may keep none of them; `step` came from this
        // table's own `open` and is not yet released.
        let answer = unsafe {
            promote(
                self.of.module.state(),
                self.step,
                &raw const reader,
                &raw const sink,
            )
        };
        if let Some(refused) = gathered.refused {
            return Err(format!("{}: {refused}", self.of.module.descriptor()));
        }
        if answer != status::OK {
            return Err(format!(
                "{} answered status {answer} to promote: {}",
                self.of.module.descriptor(),
                self.of.module.last_error()
            ));
        }
        Ok(gathered.values)
    }
}

impl Drop for PromoteStep<'_> {
    fn drop(&mut self) {
        if let Some(release) = self.of.table.release {
            // SAFETY: `step` came from this table's own `open` and is
            // released exactly once, here, through the unit that opened it.
            unsafe { release(self.of.module.state(), self.step) };
        }
    }
}

/// The host's sink: each value copied out as the call hands it, borrowed
/// for that call alone (header section 14).
unsafe extern "C" fn take_promoted(
    ctx: *mut c_void,
    property: Str,
    kind: i32,
    value: Slice,
) -> i32 {
    abi::guarded(status::PANIC, || {
        if ctx.is_null() || (value.ptr.is_null() && value.len > 0) {
            return status::INVALID;
        }
        // SAFETY: `ctx` is the `Gathered` that `promote` above keeps on its
        // stack across the one call it hands this sink to.
        let gathered = unsafe { &mut *ctx.cast::<Gathered>() };
        let bytes = if value.len == 0 {
            &[][..]
        } else {
            // SAFETY: the header lends `value` for this call; copied below.
            unsafe { std::slice::from_raw_parts(value.ptr, value.len) }
        };
        match scalar(kind, bytes) {
            Ok(scalar) => {
                gathered.values.push((read_str(property), scalar));
                status::OK
            }
            Err(why) => {
                gathered.refused.get_or_insert(why);
                status::INVALID
            }
        }
    })
}

/// A promoted value as the context holds it, from its kind and its bytes
/// written as section 10 writes a leaf.
fn scalar(kind: i32, bytes: &[u8]) -> Result<ScalarValue, String> {
    let text =
        || std::str::from_utf8(bytes).map_err(|_| "a promoted value is not UTF-8".to_string());
    match kind {
        value_kind::BOOL => match text()? {
            "true" => Ok(ScalarValue::Bool(true)),
            "false" => Ok(ScalarValue::Bool(false)),
            other => Err(format!("a promoted boolean reads '{other}'")),
        },
        value_kind::NUMBER => {
            let written = text()?;
            written
                .parse::<i64>()
                .map(ScalarValue::Integer)
                .or_else(|_| written.parse::<f64>().map(ScalarValue::Decimal))
                .map_err(|_| format!("a promoted number reads '{written}'"))
        }
        value_kind::STRING => Ok(ScalarValue::Text(text()?.to_string())),
        value_kind::BINARY => Ok(ScalarValue::Binary(bytes.to_vec())),
        other => Err(format!(
            "a promoted value is of kind {other}; a Promote unit hands a boolean, a number, \
             text or bytes (header section 14)"
        )),
    }
}

#[cfg(test)]
mod tests;
