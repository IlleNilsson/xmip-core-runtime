//! The role a proven caller holds and the one check every operator's act
//! passes (ADR-0009, amendments 2026-10-03 and 2026-10-06), written once
//! here, beneath every surface: the node's operate listener asks it of
//! every act that reaches it over the network, and `Xmip.Surface`'s
//! `GatedOperator` asks it through `xmip_act_admitted_v1` for every act a
//! screen takes (ADR-0014, amendment 2026-10-12).
//!
//! A caller nothing proved acts on nothing; one proven acts where the role
//! it holds may (Operator and up). Which role a proven caller holds is the
//! host's to say: `RoleAssignment` in `Xmip.Surface` for a web host or the
//! desktop, `[operate] role` for a node's operate listener, where every
//! caller is proven by its certificate and no directory is asked yet.

/// A security role, least first: each includes what the one before it can
/// do. The numbers are what crosses the C boundary.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub enum Role {
    /// Watches. Monitoring only; changes nothing.
    #[default]
    Observer = 0,
    /// Also acts — pauses, resumes, removes, replays, retries,
    /// dismisses — and configures.
    Operator = 1,
    /// Also builds.
    Developer = 2,
}

impl Role {
    /// The role a word names, without regard to case or spaces around it;
    /// Observer for any other word, so a misconfiguration never grants
    /// privilege.
    #[must_use]
    pub fn named(word: &str) -> Self {
        match word.trim().to_ascii_lowercase().as_str() {
            "operator" => Self::Operator,
            "developer" => Self::Developer,
            _ => Self::Observer,
        }
    }

    /// The role a number crossing the C boundary names, if it is one.
    #[must_use]
    pub const fn from_wire(number: i32) -> Option<Self> {
        match number {
            0 => Some(Self::Observer),
            1 => Some(Self::Operator),
            2 => Some(Self::Developer),
            _ => None,
        }
    }

    /// What the role is called.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Observer => "Observer",
            Self::Operator => "Operator",
            Self::Developer => "Developer",
        }
    }

    /// What the role may do, in the words every host's badge uses.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::Observer => "watches — monitoring only",
            Self::Operator => "also acts and configures",
            Self::Developer => "also builds",
        }
    }

    /// Whether the role may act on the running estate (Operator and up).
    #[must_use]
    pub fn may_operate(self) -> bool {
        self >= Self::Operator
    }
}

/// Whether `who` — the identity the connection proved, `None` where nothing
/// did — holding `role` may `act` on `target`: `Ok` where it may, the
/// refusal in words where it may not.
///
/// # Errors
///
/// The refusal: nothing proved who asks, or the role may not act.
pub fn admitted(who: Option<&str>, role: Role, act: &str, target: &str) -> Result<(), String> {
    match who {
        None => Err(format!(
            "REFUSED. Nothing proved who asks to {act} {target}; an act is taken from the \
             identity the connection proved — a client certificate, or the host's own user \
             on loopback — never from what the caller says (ADR-0009)"
        )),
        Some(_) if role.may_operate() => Ok(()),
        Some(who) => Err(format!(
            "REFUSED. {who} may not {act} {target}: {who} is {}, which {} (ADR-0009)",
            role.word(),
            role.describe()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_word_that_is_no_role_grants_nothing() {
        assert_eq!(Role::named(" Operator "), Role::Operator);
        assert_eq!(Role::named("admin"), Role::Observer);
    }

    #[test]
    fn only_an_operator_and_up_proven_is_admitted() {
        assert!(admitted(Some("CN=a"), Role::Operator, "pause", "x").is_ok());
        let observer = admitted(Some("CN=a"), Role::Observer, "pause", "x").unwrap_err();
        assert!(observer.starts_with("REFUSED. CN=a may not pause x: CN=a is Observer"));
        let nobody = admitted(None, Role::Developer, "pause", "x").unwrap_err();
        assert!(nobody.starts_with("REFUSED. Nothing proved who asks to pause x"));
    }
}
