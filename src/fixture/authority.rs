//! A test authority: one anchor, and a certificate it issues for each end
//! by name, for `localhost` and `127.0.0.1`, as the event cluster's tests
//! make theirs; and a directory of its own for the audit a test reads. The
//! operate plane's tests take it, through the C boundary (`ffi::served`)
//! and around it (`tests/plane`) alike.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

/// The authority, and what issues with it.
pub struct Authority {
    issuer: rcgen::CertifiedIssuer<'static, rcgen::KeyPair>,
    pub directory: PathBuf,
}

impl Default for Authority {
    fn default() -> Self {
        Self::new()
    }
}

impl Authority {
    /// A new authority, and a directory of its own.
    #[must_use]
    pub fn new() -> Self {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let key = rcgen::KeyPair::generate().expect("a key");
        let issuer = rcgen::CertifiedIssuer::self_signed(params, key).expect("self-signed");
        // Numbered within the process, never by the clock: two tests made
        // theirs in the same tick on Windows, and the first to end removed
        // the folder the other's audit was written in.
        static MADE: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "xmip-plane-{}-{}",
            std::process::id(),
            MADE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&directory).expect("a directory");
        Self { issuer, directory }
    }

    /// An identity named `CN=<name>`, issued by this authority and
    /// trusting it.
    #[must_use]
    pub fn identity(&self, name: &str) -> tls::Identity {
        let (certificate, key, anchors) = self.pem(name);
        tls::Identity::from_pem(certificate.as_bytes(), key.as_bytes(), anchors.as_bytes())
            .expect("an identity")
    }

    /// The same as PEM: the certificate, its key and the anchor.
    #[must_use]
    pub fn pem(&self, name: &str) -> (String, String, String) {
        self.issued(name, None)
    }

    /// The same, its serial number `serial`, which a list revokes it by
    /// ([`Authority::revoking`]).
    #[must_use]
    pub fn pem_numbered(&self, name: &str, serial: u64) -> (String, String, String) {
        self.issued(name, Some(serial))
    }

    /// A revocation list this authority signs, revoking the certificates
    /// whose serial numbers are `serials`, valid from 2000 to 2100, DER:
    /// what a cluster's authority keeps as `authority.crl`.
    #[must_use]
    pub fn revoking(&self, serials: &[u64]) -> Vec<u8> {
        let revoked_certs = serials
            .iter()
            .map(|serial| rcgen::RevokedCertParams {
                serial_number: rcgen::SerialNumber::from(*serial),
                revocation_time: rcgen::date_time_ymd(2000, 1, 1),
                reason_code: None,
                invalidity_date: None,
            })
            .collect();
        let params = rcgen::CertificateRevocationListParams {
            this_update: rcgen::date_time_ymd(2000, 1, 1),
            next_update: rcgen::date_time_ymd(2100, 1, 1),
            crl_number: rcgen::SerialNumber::from(1),
            issuing_distribution_point: None,
            revoked_certs,
            key_identifier_method: rcgen::KeyIdMethod::Sha256,
        };
        params
            .signed_by(&*self.issuer)
            .expect("a list")
            .der()
            .to_vec()
    }

    /// A certificate for `name`, numbered `serial` where given.
    fn issued(&self, name: &str, serial: Option<u64>) -> (String, String, String) {
        let key = rcgen::KeyPair::generate().expect("a key");
        let mut params =
            rcgen::CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])
                .expect("params");
        // Server and client authentication, as a node's certificate is
        // (ADR-0034): what the Storage plane admits.
        params.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        ];
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        params.serial_number = serial.map(rcgen::SerialNumber::from);
        let leaf = params.signed_by(&key, &self.issuer).expect("issued");
        (leaf.pem(), key.serialize_pem(), self.issuer.pem())
    }
}

impl Drop for Authority {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}
