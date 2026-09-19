//! Whether the host takes the module it just opened — ADR-0012,
//! *Compatibility*, as three comparisons over a descriptor already read.
//!
//! `abi::validate_module_abi` answers whether a descriptor is well formed at
//! all: the ABI version the boundary speaks, a provider and a module named, a
//! standard present unless the provider is `core`. It cannot answer the
//! question a load actually asks, because that question has a second party —
//! the capability doing the loading. One well-formed descriptor is taken by
//! `contract` and refused by `transport`, and only the loader knows which of
//! the two asked for the library.
//!
//! Nothing here dereferences a pointer. The descriptor arrives already copied
//! out of the module's memory, so the rule an operator has to argue with sits
//! in a file with no `unsafe` in it, and every refusal names the field that
//! disagreed and what was expected (ADR-0055: refused at the door, in words).

use abi::{ModuleDescriptor, validate_module_abi};

/// What the loading capability requires of a module offering to serve it.
///
/// ADR-0012 clause 6: each core module versions its own trait, so the trait
/// version here is the loading capability's own and never a platform-wide
/// number. `contract` at 1.0 says nothing about `transport` at 1.0.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Expectation {
    /// The loading capability's name, as `descriptor.module` spells it:
    /// `contract`, `transport`, `message`, `path` (ADR-0011, the second of
    /// the three name parts).
    pub module: String,
    pub trait_major: u32,
    pub trait_minor: u32,
}

impl Expectation {
    #[must_use]
    pub fn new(module: &str, trait_major: u32, trait_minor: u32) -> Self {
        Self {
            module: module.to_string(),
            trait_major,
            trait_minor,
        }
    }
}

/// ADR-0012's compatibility rule, in its own order: `abi_version` equal,
/// `module` equal to the loading capability, `trait_major` equal,
/// `trait_minor` less than or equal.
///
/// The first line is `validate_module_abi`'s, which already refuses a foreign
/// ABI version by name; the other three are here because they need the
/// expectation.
///
/// # Errors
///
/// Names the one field that disagreed and what was expected. An operator
/// reading this is holding a library file and has to know which fact about it
/// to fix — a module built for another capability, a trait generation apart,
/// or a table newer than the host can drive.
pub fn accepts(descriptor: &ModuleDescriptor, expected: &Expectation) -> Result<(), String> {
    validate_module_abi(descriptor)?;

    if descriptor.module != expected.module {
        return Err(format!(
            "{descriptor} answers the '{}' trait and '{}' is loading it: \
             descriptor.module must equal the loading capability",
            descriptor.module, expected.module
        ));
    }

    if descriptor.trait_major != expected.trait_major {
        return Err(format!(
            "{descriptor} is built against trait_major {} and '{}' speaks {}: \
             a major generation apart is a different trait",
            descriptor.trait_major, expected.module, expected.trait_major
        ));
    }

    if descriptor.trait_minor > expected.trait_minor {
        return Err(format!(
            "{descriptor} is built against trait_minor {} and '{}' speaks {}: \
             trait_minor must be less than or equal to the host's",
            descriptor.trait_minor, expected.module, expected.trait_minor
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use abi::XMIP_ABI_VERSION;

    fn contract_rust() -> ModuleDescriptor {
        ModuleDescriptor {
            abi_version: XMIP_ABI_VERSION,
            provider: "core".to_string(),
            module: "contract".to_string(),
            standard: "rust".to_string(),
            trait_major: 1,
            trait_minor: 0,
            module_major: 0,
            module_minor: 1,
            module_patch: 0,
        }
    }

    fn contract() -> Expectation {
        Expectation::new("contract", 1, 0)
    }

    #[test]
    fn the_capability_that_asked_takes_the_module_that_answers_it() {
        assert_eq!(accepts(&contract_rust(), &contract()), Ok(()));
    }

    #[test]
    fn a_foreign_abi_version_is_refused_naming_the_version() {
        let mut foreign = contract_rust();
        foreign.abi_version = XMIP_ABI_VERSION + 1;

        let refusal = accepts(&foreign, &contract()).expect_err("must refuse");

        assert!(refusal.contains("ABI version 2"), "got: {refusal}");
    }

    #[test]
    fn another_capabilitys_module_is_refused_naming_both() {
        let mut transport = contract_rust();
        transport.module = "transport".to_string();

        let refusal = accepts(&transport, &contract()).expect_err("must refuse");

        assert!(refusal.contains("descriptor.module"), "got: {refusal}");
        assert!(refusal.contains("'transport' trait"), "got: {refusal}");
        assert!(
            refusal.contains("'contract' is loading it"),
            "got: {refusal}"
        );
    }

    #[test]
    fn a_major_generation_apart_is_refused_naming_trait_major() {
        let mut older = contract_rust();
        older.trait_major = 2;

        let refusal = accepts(&older, &contract()).expect_err("must refuse");

        assert!(refusal.contains("trait_major 2"), "got: {refusal}");
        assert!(refusal.contains("speaks 1"), "got: {refusal}");
    }

    #[test]
    fn a_newer_minor_is_refused_and_an_older_one_is_taken() {
        let mut newer = contract_rust();
        newer.trait_minor = 3;

        let refusal = accepts(&newer, &Expectation::new("contract", 1, 2))
            .expect_err("the host cannot drive a table it does not know");

        assert!(refusal.contains("trait_minor 3"), "got: {refusal}");
        assert!(refusal.contains("speaks 2"), "got: {refusal}");

        let mut older = contract_rust();
        older.trait_minor = 1;

        assert_eq!(accepts(&older, &Expectation::new("contract", 1, 4)), Ok(()));
    }
}
