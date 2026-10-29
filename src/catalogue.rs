//! The technologies this runtime carries, and the settings each declares
//! (ADR-0064, amendment 2026-09-26).
//!
//! Every technology declares its own settings in its own crate
//! (`xcore::settings::Settings`: a transport's `transport::Configured`, a
//! contract's `ContractFactory::settings`). The runtime names no technology
//! (`architecture.toml`: a platform service depends on no technology
//! repository), so it holds the declarations of the technologies it has been
//! given — a node carries each technology here as it loads it (startup phase
//! 6, `startup.rs`) — and every reader asks here: `xmip_validate_v1`
//! and `xmip_start_v1` hold each Location to its technology's declaration
//! through `configure::location_problems`, and `xmip_technology_catalogue_v1`
//! (`xmip_operate.h` section 12) hands the same declarations to the language
//! server and the desktop editor, which build a Location's form from them.

use std::sync::{PoisonError, RwLock};

use configure::Declarations;
use serde::Serialize;
use xcore::settings::Settings;

/// Which capability a technology carried belongs to: a transport, which a
/// Location's address chooses by its scheme, or a contract, which its
/// `contract` names. Said by whoever carries it, never read from
/// its name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Capability {
    /// A transport technology: chosen by a Location's address.
    Transport,
    /// A contract technology: a Location's `contract`.
    Contract,
}

/// One technology carried, as the catalogue answers it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Carried {
    /// Its capability.
    pub capability: Capability,
    /// The schemes a Location's address is entered with to choose it, a
    /// transport's; none for a contract, which a Location names.
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    pub schemes: &'static [&'static str],
    /// Its declaration, `technology` and `settings` side by side with the
    /// capability in the answer.
    #[serde(flatten)]
    pub settings: &'static Settings,
}

static CARRIED: RwLock<Vec<Carried>> = RwLock::new(Vec::new());

/// Carry the technology `settings` declares, of `capability`, chosen by
/// `schemes` where it is a transport: from now on its Locations are held
/// to its declaration and the catalogue answers it. Carrying one again
/// changes nothing.
pub fn carry(
    capability: Capability,
    settings: &'static Settings,
    schemes: &'static [&'static str],
) {
    let mut carried = CARRIED.write().unwrap_or_else(PoisonError::into_inner);
    if carried
        .iter()
        .all(|held| held.settings.technology != settings.technology)
    {
        carried.push(Carried {
            capability,
            schemes,
            settings,
        });
        carried.sort_by_key(|held| held.settings.technology);
    }
}

/// Every technology carried, by module name.
#[must_use]
pub fn carried() -> Vec<Carried> {
    CARRIED
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
}

/// The declarations carried, as `configure` holds a Location to them: a
/// transport by each of its schemes, a contract by its module name.
#[must_use]
pub fn declarations() -> Declarations {
    carried()
        .into_iter()
        .flat_map(|held| match held.capability {
            Capability::Transport => held
                .schemes
                .iter()
                .map(|scheme| (*scheme, held.settings))
                .collect::<Vec<_>>(),
            Capability::Contract => vec![(held.settings.technology, held.settings)],
        })
        .collect()
}

#[derive(Serialize)]
struct Answer {
    technologies: Vec<Carried>,
}

/// The catalogue as `xmip_technology_catalogue_v1` answers it: every
/// technology carried when `technology` is empty, that one alone otherwise.
///
/// # Errors
/// One sentence, when the runtime carries no technology of that name.
pub fn catalogue(technology: &str) -> Result<String, String> {
    let technologies: Vec<Carried> = carried()
        .into_iter()
        .filter(|held| technology.is_empty() || held.settings.technology == technology)
        .collect();

    if technologies.is_empty() && !technology.is_empty() {
        return Err(format!("this runtime carries no technology '{technology}'"));
    }

    serde_json::to_string(&Answer { technologies }).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use xcore::settings::{Applies, Kind, Presence, Setting};

    pub(crate) const EXAMPLE: &Settings = &Settings {
        technology: "xmip-core-transport-catalogued",
        settings: &[Setting {
            name: "topic",
            kind: Kind::Text,
            presence: Presence::Required,
            meaning: "The topic a Location reads or writes.",
            applies: Applies::Both,
        }],
    };

    #[test]
    fn a_carried_technology_is_answered_whole_and_by_name() {
        carry(Capability::Transport, EXAMPLE, &["catalogued"]);
        carry(Capability::Transport, EXAMPLE, &["catalogued"]);
        assert_eq!(
            carried()
                .iter()
                .filter(|held| held.settings.technology == EXAMPLE.technology)
                .count(),
            1,
            "carried once"
        );

        let one = catalogue(EXAMPLE.technology).expect("carried");
        assert!(
            one.starts_with("{\"technologies\":[{\"capability\":\"transport\""),
            "{one}"
        );
        assert!(one.contains("\"presence\":\"required\""), "{one}");
        assert!(catalogue("").expect("all").contains(EXAMPLE.technology));
        assert!(declarations().contains_key("catalogued"), "by its scheme");
        assert!(one.contains("\"schemes\":[\"catalogued\"]"), "{one}");

        let refused = catalogue("xmip-core-transport-nowhere").expect_err("not carried");
        assert!(refused.contains("xmip-core-transport-nowhere"));
    }
}
