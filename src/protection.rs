//! How a web host's listener protects its connections (`xmip_operate.h`
//! section 21; ADR-0009, amendment 2026-10-21).

/// How a listener's connections are protected: a parameter, never a name
/// (the owner, 2026-10-21: *technology and security should not be in
/// functions, parameters is ok*). TLS, `xmip-core-library-tls`, is the one
/// built.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Protection {
    /// TLS 1.3 and 1.2, hybrid key exchange first (ADR-0033).
    Tls,
}

impl Protection {
    /// `XMIP_PROTECTION_TLS`, as section 21 passes it.
    pub const TLS: i32 = 1;

    /// The protection `value` names, if it is one built.
    #[must_use]
    pub const fn of(value: i32) -> Option<Self> {
        match value {
            Self::TLS => Some(Self::Tls),
            _ => None,
        }
    }
}
