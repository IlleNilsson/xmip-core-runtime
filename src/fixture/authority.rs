//! A test authority: one anchor, and a certificate it issues for each end
//! by name, for `localhost` and `127.0.0.1`, as the event cluster's tests
//! make theirs; and a directory of its own for the audit a test reads. The
//! operate plane's tests take it, through the C boundary (`ffi::served`)
//! and around it (`tests/plane`) alike.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

/// The authority, and what issues with it.
pub struct Authority {
    pem: String,
    issuer: rcgen::CertifiedKey,
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
        let key = rcgen::KeyPair::generate().expect("a key");
        let cert = params.self_signed(&key).expect("self-signed");
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
        Self {
            pem: cert.pem(),
            issuer: rcgen::CertifiedKey {
                cert,
                key_pair: key,
            },
            directory,
        }
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
        let key = rcgen::KeyPair::generate().expect("a key");
        let mut params =
            rcgen::CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])
                .expect("params");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        let leaf = params
            .signed_by(&key, &self.issuer.cert, &self.issuer.key_pair)
            .expect("issued");
        (leaf.pem(), key.serialize_pem(), self.pem.clone())
    }
}

impl Drop for Authority {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}
