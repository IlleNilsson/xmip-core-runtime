use crate::{HostBitness, HostServicePlan};
use abi::ModuleManifest;

/// The registered, supervised thing. The System Process it runs as is the
/// Host Process; this is the service. ADR-0018.
#[derive(Clone, Debug)]
pub struct HostService {
    pub plan: HostServicePlan,
    pub state: HostServiceState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostServiceState {
    Planned,
    Starting,
    Running,
    Stopped,
    Failed(String),
}

impl HostService {
    pub fn from_manifest(manifest: ModuleManifest, trusted: bool) -> Self {
        Self {
            plan: HostServicePlan {
                host_type: format!("{}-host", manifest.identity.name),
                trusted,
                bitness: HostBitness::Native,
                modules: vec![manifest],
                verified_extensions: Vec::new(),
            },
            state: HostServiceState::Planned,
        }
    }

    pub fn start(&mut self) {
        self.state = HostServiceState::Starting;
        self.state = HostServiceState::Running;
    }

    pub fn stop(&mut self) {
        self.state = HostServiceState::Stopped;
    }
}

/// ADR-0025 clause 3: a delayed Module is loaded on the first call that needs
/// it, and this is the verification that load performs — ADR-0018 phase 6's
/// check, run late for the delayed set.
///
/// Written before `xmip-core-abi` exported any of this and never compiled
/// until 2026-08-30: the imports named symbols nobody had written
/// (`ModuleAbiDescriptor`, `XMIP_MODULE_ENTRYPOINT`), and the call below moved
/// `request.descriptor` out of a borrow. Both were invisible for as long as
/// nothing built the feature, which is what put `cargo build` on every
/// declared feature in `Test-XmipModule`.
#[cfg(feature = "dynamic-loading")]
pub mod dynamic {
    use abi::{ModuleDescriptor, ModuleManifest, XMIP_ENTRYPOINT, validate_module_abi};

    #[derive(Clone, Debug)]
    pub struct DynamicModuleRequest {
        pub manifest: ModuleManifest,
        pub resolved_library_path: String,
        pub descriptor: ModuleDescriptor,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct VerifiedDynamicModule {
        pub module_name: String,
        pub resolved_library_path: String,
        pub entrypoint_symbol: String,
    }

    /// # Errors
    ///
    /// A request with no library path, a descriptor the host refuses, or a
    /// manifest whose declared symbol is blank. The refusal reaches the first
    /// caller — ADR-0025 clause 4 — so it names what to fix rather than which
    /// call failed.
    pub fn verify_dynamic_module(
        request: &DynamicModuleRequest,
    ) -> Result<VerifiedDynamicModule, String> {
        if request.resolved_library_path.trim().is_empty() {
            return Err("dynamic module request requires a resolved library path".to_string());
        }

        validate_module_abi(&request.descriptor)?;

        let entrypoint_symbol = request
            .manifest
            .entrypoint
            .symbol
            .clone()
            .unwrap_or_else(|| XMIP_ENTRYPOINT.to_string());

        if entrypoint_symbol.trim().is_empty() {
            return Err("dynamic module request requires an exported symbol".to_string());
        }

        Ok(VerifiedDynamicModule {
            module_name: request.manifest.identity.name.clone(),
            resolved_library_path: request.resolved_library_path.clone(),
            entrypoint_symbol,
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use abi::{
            ExecutionHostKind, ModuleCapability, ModuleEntrypoint, ModuleIdentity, XMIP_ABI_VERSION,
        };

        fn request(symbol: Option<&str>) -> DynamicModuleRequest {
            DynamicModuleRequest {
                manifest: ModuleManifest {
                    identity: ModuleIdentity {
                        name: "xmip-core-transport-file".to_string(),
                        version: "0.1.0".to_string(),
                    },
                    capabilities: vec![ModuleCapability {
                        capability: "transport".to_string(),
                        execution_host: ExecutionHostKind::NativeRust,
                        trusted_required: false,
                    }],
                    entrypoint: ModuleEntrypoint {
                        library_path: Some("libxmip_core_transport_file.so".to_string()),
                        executable_path: None,
                        symbol: symbol.map(str::to_string),
                    },
                },
                resolved_library_path: "/opt/xmip/libxmip_core_transport_file.so".to_string(),
                descriptor: ModuleDescriptor {
                    abi_version: XMIP_ABI_VERSION,
                    provider: "core".to_string(),
                    module: "transport".to_string(),
                    standard: "file".to_string(),
                    trait_major: 1,
                    trait_minor: 0,
                    module_major: 0,
                    module_minor: 1,
                    module_patch: 0,
                },
            }
        }

        #[test]
        fn an_unnamed_symbol_defaults_to_the_headers_entrypoint() {
            let verified = verify_dynamic_module(&request(None)).expect("verifies");

            assert_eq!(verified.entrypoint_symbol, XMIP_ENTRYPOINT);
        }

        #[test]
        fn a_declared_symbol_is_kept() {
            let verified =
                verify_dynamic_module(&request(Some("acme_create_v1"))).expect("verifies");

            assert_eq!(verified.entrypoint_symbol, "acme_create_v1");
        }

        #[test]
        fn a_foreign_abi_version_is_refused_before_any_load() {
            let mut foreign = request(None);
            foreign.descriptor.abi_version = XMIP_ABI_VERSION + 1;

            verify_dynamic_module(&foreign).expect_err("the host must refuse it");
        }
    }
}
