//! Which role each proven caller of a node's operate listener holds
//! (ADR-0009, amendment 2026-11-07): its own, by its name, as the node's
//! configuration lists it — `[operate] observers`, `operators` and
//! `developers` — never one role for every caller the anchors let in.
//!
//! A certificate is named by its subject or by an alternative name it
//! carries, a DNS name or a user principal name — the one reading of what a
//! certificate names (`authenticate::x509::name::names`); an account on the
//! local endpoint by the name the operating system gives it, without regard
//! to case on Windows, whose account names are not cased, and exactly
//! elsewhere. A caller no entry names holds no role, and every call it
//! makes is refused (`plane::role::admitted`): the listener is closed by
//! default (`authorize::plane::granted`). A caller a relay vouched for holds
//! the role its own certificate is listed with (`plane::vouched`).

use authenticate::x509::Chain;
use authenticate::x509::name::names;
use authorize::plane::granted;

use crate::plane::role::Role;

/// Who holds which role on one node's operate listeners.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Grants {
    /// Each caller's name, and the role it is listed with.
    named: Vec<(String, Role)>,
}

impl Grants {
    /// The callers each role's list names, least role first, as
    /// `configure::operate::OperateConfiguration::grants` hands them: a
    /// node's configuration, and a program hosting a listener through the
    /// C ABI (`xmip_operate_serve_v2`).
    #[must_use]
    pub fn listed(lists: [&[String]; 3]) -> Self {
        let roles = [Role::Observer, Role::Operator, Role::Developer];
        let named = roles
            .into_iter()
            .zip(lists)
            .flat_map(|(role, names)| {
                names
                    .iter()
                    .map(move |name| (name.trim().to_string(), role))
            })
            .collect();
        Self { named }
    }

    /// The role the caller `names` answers to holds — the least of the
    /// entries naming it — or `None`, no role.
    fn held(&self, names: impl Fn(&str) -> bool) -> Option<Role> {
        let grants = self
            .named
            .iter()
            .map(|(name, role)| (name.as_str(), *role as u8));
        granted(grants, names).and_then(|standing| Role::from_wire(i32::from(standing)))
    }

    /// The role the caller `leaf` (DER) proves holds, by its subject or an
    /// alternative name it carries; `None` for a certificate no entry names.
    #[must_use]
    pub fn certificate(&self, leaf: &[u8]) -> Option<Role> {
        let chain = Chain::from_der(&[leaf]).ok()?;
        self.held(|name| names(chain.leaf(), name).unwrap_or(false))
    }

    /// The role the account the operating system named on the local
    /// endpoint holds; `None` for an account no entry names.
    #[must_use]
    pub fn account(&self, account: &str) -> Option<Role> {
        self.held(|name| {
            if cfg!(windows) {
                name.eq_ignore_ascii_case(account.trim())
            } else {
                name == account
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::Authority;

    fn leaf(authority: &Authority, name: &str) -> Vec<u8> {
        let (pem, _, _) = authority.pem(name);
        Chain::from_pem(&pem).expect("a chain").leaf().to_vec()
    }

    #[test]
    fn a_certificate_holds_the_role_its_own_name_is_listed_with_and_no_other() {
        let authority = Authority::new();
        let (observers, operators, developers) = (
            vec!["CN=watcher".to_string()],
            vec!["CN=alice".to_string(), r"HOST\jane".to_string()],
            vec![],
        );
        let grants = Grants::listed([&observers, &operators, &developers]);
        assert_eq!(
            grants.certificate(&leaf(&authority, "alice")),
            Some(Role::Operator)
        );
        assert_eq!(
            grants.certificate(&leaf(&authority, "watcher")),
            Some(Role::Observer)
        );
        // A second certificate from the same anchors is no one listed.
        assert_eq!(grants.certificate(&leaf(&authority, "mallory")), None);
        assert_eq!(grants.certificate(b"not a certificate"), None);
        assert_eq!(grants.account(r"HOST\jane"), Some(Role::Operator));
        assert_eq!(grants.account(r"HOST\john"), None);
        assert_eq!(
            Grants::default().account(r"HOST\jane"),
            None,
            "closed by default"
        );
    }

    #[test]
    fn an_alternative_name_names_a_certificate_and_the_least_entry_wins() {
        let authority = Authority::new();
        // Every fixture certificate carries localhost as a DNS name.
        let (observers, developers) = (vec!["localhost".to_string()], vec!["CN=alice".to_string()]);
        let grants = Grants::listed([&observers, &[], &developers]);
        assert_eq!(
            grants.certificate(&leaf(&authority, "alice")),
            Some(Role::Observer)
        );
        assert_eq!(
            grants.certificate(&leaf(&authority, "any")),
            Some(Role::Observer)
        );
    }
}
