//! The role a proven caller holds and the one check every operator's act
//! passes (ADR-0009, amendments 2026-10-03 and 2026-10-06), written once
//! here, beneath every surface: the node's operate listener asks it of
//! every act that reaches it over the network, and `Xmip.Surface`'s
//! `GatedOperator` asks it through `xmip_act_admitted_v1` for every act a
//! screen takes (ADR-0014, amendment 2026-10-12).
//!
//! A caller nothing proved acts on nothing; one proven acts where the role
//! it holds may (Operator and up). On the listener a caller is what the
//! authentication gate answered for the connection (`plane::caller`,
//! ADR-0009, amendment 2026-11-01), never a name read beside it; on a
//! screen, the caller a handle the runtime handed out holds
//! (`plane::held`), never a name its host passes. Which role
//! a proven caller holds is the host's to say: `RoleAssignment` in
//! `Xmip.Surface` for a web host or the desktop, and for a node's operate
//! listener the role its configuration lists that very caller with
//! (`plane::grant`, `[operate] observers`, `operators` and `developers`),
//! none for a caller it does not list, which acts on nothing and reads
//! nothing.
//!
//! **Every call is decided before it is read**: by its method, the identity
//! the connection proved and the role it holds ([`RULES`], [`admitted`]),
//! never by what the call says.

use authorize::plane::{self, Rule};
use context::AuthenticatedIdentity;

use crate::plane::call;

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

/// Who may call each method of a node's operate listener, by the role the
/// caller holds (`authorize::plane`, the one admission every plane Xmip
/// serves its own parts asks): the publication and its wait, and the
/// cluster's a monitoring node gathered and its wait, to anyone proven
/// holding a role — a monitoring node reading another is an Observer there,
/// listed in its `[operate] observers` (ADR-0009, amendment 2026-11-13) —
/// an act and a secret set, and the secrets' listing, to an Operator and
/// up.
pub const RULES: &[Rule] = &[
    Rule::new("read", call::PUBLICATION, Role::Observer as u8),
    Rule::new("read", call::WAIT, Role::Observer as u8),
    Rule::new("read", call::CLUSTER, Role::Observer as u8),
    Rule::new("read", call::CLUSTER_WAIT, Role::Observer as u8),
    Rule::new("read", call::SECRETS, Role::Operator as u8),
    Rule::new("act", call::ACT, Role::Operator as u8),
    Rule::new("act", call::SECRET, Role::Operator as u8),
];

/// What a method of the listener does, as [`RULES`] names it.
fn action(method: &str) -> &'static str {
    match method {
        call::PUBLICATION | call::WAIT | call::CLUSTER | call::CLUSTER_WAIT | call::SECRETS => {
            "read"
        }
        _ => "act",
    }
}

/// Whether `caller` — the identity the authentication gate answered for
/// the connection (`plane::caller`), `None` where it answered nothing —
/// holding `role`, the one granted that caller (`plane::grant`; `None`
/// where none is), may call `method` of the operate listener ([`RULES`]),
/// to `act` on `target` as its refusal says: the one check the listener
/// asks before it reads a call. Only a caller the gate called proven is
/// anyone; one it called anything weaker acts on nothing, and so does one
/// granted no role. `Ok` where it may, the refusal in words where it may
/// not.
///
/// # Errors
///
/// The refusal: nothing proved who asks, no role is granted it, or its
/// role may not call it.
pub fn admitted(
    caller: Option<&AuthenticatedIdentity>,
    role: Option<Role>,
    method: &str,
    asked: (&str, &str),
) -> Result<(), String> {
    let who = caller
        .filter(|caller| caller.verified.is_proven())
        .map(|caller| caller.value.as_str());
    let (act, target) = asked;
    let (Some(who), None) = (who, role) else {
        return admitted_as(who, role.unwrap_or_default(), method, asked);
    };
    Err(format!(
        "REFUSED. {who} may not {act} {target}: no role on this node is granted {who}; \
         [operate] observers, operators and developers name who holds which (ADR-0009)"
    ))
}

/// [`admitted`] for a caller holding `role`.
fn admitted_as(
    who: Option<&str>,
    role: Role,
    method: &str,
    (act, target): (&str, &str),
) -> Result<(), String> {
    let admitted = plane::admit(who, role as u8, (action(method), method), RULES);
    match (who, admitted) {
        (_, Ok(())) => Ok(()),
        (None, Err(_)) => Err(format!(
            "REFUSED. Nothing proved who asks to {act} {target}; an act is taken from the \
             identity the connection proved — a client certificate, or on the node's local \
             endpoint the account the operating system names — never from what the caller \
             says, nor from where it connects (ADR-0009)"
        )),
        (Some(who), Err(_)) => Err(format!(
            "REFUSED. {who} may not {act} {target}: {who} is {}, which {} (ADR-0009)",
            role.word(),
            role.describe()
        )),
    }
}

/// Whether the caller `held` — a handle the runtime handed out for a caller
/// it proved (`plane::held`): what `xmip_caller_proven_v1` answered for a
/// web host's connection, or `xmip_caller_process_v1` for the account a
/// desktop runs as; 0, or one unknown, released, revoked or expired, for
/// no one — holding `role` may `act` on `target`: the check every surface
/// asks for an act a screen takes (`xmip_act_admitted_v1`), by
/// [`admitted`]'s rule. No name a host passes is read.
///
/// # Errors
///
/// As [`admitted`].
pub fn act_admitted(held: u64, role: Role, asked: (&str, &str)) -> Result<(), String> {
    let caller = crate::plane::held::proven(held);
    admitted(caller.as_ref(), Some(role), call::ACT, asked)
}

#[cfg(test)]
mod tests {
    use super::*;
    use context::Verified;
    use xcore::{Established, mechanism};

    #[test]
    fn a_word_that_is_no_role_grants_nothing() {
        assert_eq!(Role::named(" Operator "), Role::Operator);
        assert_eq!(Role::named("admin"), Role::Observer);
    }

    fn caller(verified: Verified) -> AuthenticatedIdentity {
        AuthenticatedIdentity::new(
            mechanism::mutual_tls(),
            "CN=a",
            Established::Passed,
            verified,
        )
    }

    #[test]
    fn only_an_operator_and_up_proven_is_admitted() {
        let a = caller(Verified::Proven);
        let a = Some(&a);
        let (observer, operator) = (Some(Role::Observer), Some(Role::Operator));
        assert!(admitted(a, operator, call::ACT, ("pause", "x")).is_ok());
        let watching = admitted(a, observer, call::ACT, ("pause", "x")).unwrap_err();
        assert!(watching.starts_with("REFUSED. CN=a may not pause x: CN=a is Observer"));
        let developer = Some(Role::Developer);
        let nobody = admitted(None, developer, call::ACT, ("pause", "x")).unwrap_err();
        assert!(nobody.starts_with("REFUSED. Nothing proved who asks to pause x"));
        // The publication to anyone granted a role; the secrets' names to an
        // Operator.
        let read = ("read", "the publication");
        assert!(admitted(a, observer, call::PUBLICATION, read).is_ok());
        // The cluster's a monitoring node gathered, to an Observer too: what
        // a monitoring node reading another is.
        for method in [call::CLUSTER, call::CLUSTER_WAIT] {
            assert!(admitted(a, observer, method, read).is_ok(), "{method}");
        }
        let names = ("list", "the secrets");
        assert!(admitted(a, observer, call::SECRETS, names).is_err());
        assert!(admitted(a, operator, call::SECRETS, names).is_ok());
        assert!(admitted(a, developer, "Nothing", names).is_err());
    }

    #[test]
    fn a_proven_caller_granted_no_role_reads_nothing_and_acts_on_nothing() {
        let a = caller(Verified::Proven);
        let every = [
            call::PUBLICATION,
            call::WAIT,
            call::CLUSTER,
            call::CLUSTER_WAIT,
        ];
        for method in every.into_iter().chain([call::ACT, call::SECRET]) {
            let refused = admitted(Some(&a), None, method, ("read", "x")).unwrap_err();
            assert!(
                refused.starts_with("REFUSED. CN=a may not read x: no role on this node"),
                "{refused}"
            );
        }
        let nobody = admitted(None, None, call::ACT, ("pause", "x")).unwrap_err();
        assert!(nobody.starts_with("REFUSED. Nothing proved"), "{nobody}");
    }

    #[test]
    fn a_caller_the_gate_did_not_call_proven_is_no_one() {
        for verdict in [Verified::Vouched, Verified::Claimed, Verified::Refused] {
            let weaker = caller(verdict);
            let refused = admitted(
                Some(&weaker),
                Some(Role::Developer),
                call::PUBLICATION,
                ("read", "x"),
            );
            assert!(refused.unwrap_err().starts_with("REFUSED. Nothing proved"));
        }
    }

    #[test]
    fn a_screens_act_is_admitted_by_the_same_rule_and_a_handle_held_by_no_one_is_no_one() {
        use crate::plane::held;
        let a = held::hold(caller(Verified::Proven), None, None, None);
        assert!(act_admitted(a, Role::Operator, ("pause", "x")).is_ok());
        let observer = act_admitted(a, Role::Observer, ("pause", "x"));
        assert!(
            observer
                .unwrap_err()
                .starts_with("REFUSED. CN=a may not pause x")
        );
        assert!(held::release(a));
        for nobody in [a, 0, a ^ 1] {
            let refused = act_admitted(nobody, Role::Developer, ("pause", "x"));
            assert!(refused.unwrap_err().starts_with("REFUSED. Nothing proved"));
        }
    }
}
