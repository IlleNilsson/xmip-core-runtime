//! Starting a node from its configuration, as far as the runtime can today.
//!
//! ADR-0018 gives startup nine phases. What is here performs the first three
//! — read, build the execution tree, validate — and publishes what it planned
//! through `operate.rs`, saying in every record that phases four to nine are
//! not built. An operator reading green over a node that has not loaded a
//! module has been told something false.
//!
//! Split from `operate.rs` on 2026-09-05 when that file passed 400 lines:
//! the table a surface calls and the act of starting a node are two subjects.
//!
//! One `extern "C"` entrypoint lives here, `xmip_start_v1`, and it reads a
//! path a surface handed it — the one reason this file allows `unsafe`.
#![allow(unsafe_code)]

use xmip_abi::ffi::{Str, status};
use xmip_observe::{Health, HealthRecord, Snapshot};

use crate::operate::{publish, scope_text};

/// What a runtime says about itself before any node has published: it is
/// here, and it has nothing to run. Yellow, not red — nothing is failing —
/// and not green, because an operator who sees green over an unconfigured
/// runtime has been told something false. The one line of evidence is the one
/// they need.
pub(crate) fn unconfigured() -> Snapshot {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| {
            i64::try_from(since.as_nanos()).unwrap_or(i64::MAX)
        });

    let mut snapshot = Snapshot::new();

    snapshot.record_health(HealthRecord {
        scope: "xmip:///".into(),
        health: Health::Yellow,
        evidence: "runtime loaded, no node started — give xmip_start_v1 a node TOML".into(),
        observed_unix_nanos: now,
    });

    snapshot
}

/// Start a node from its configuration file, as far as the runtime can today:
/// read it, build the execution tree, validate it, and publish what it plans.
///
/// ADR-0018 gives startup nine phases. This performs the first three and says
/// so in every record it publishes — an operator reading green over a node
/// that has not loaded a module has been told something false, so the
/// evidence names what happened and what did not. Phases four to nine are not
/// built yet.
///
/// Red when the file cannot be read or does not validate, with the errors as
/// evidence. A refusal that names the fault is the point of validating first.
#[must_use]
pub fn start(path: &str) -> Snapshot {
    let now = now_unix_nanos();
    let mut snapshot = Snapshot::new();

    let source = match std::fs::read_to_string(path) {
        Ok(source) => source,
        Err(error) => {
            snapshot.record_health(HealthRecord {
                scope: "xmip:///".into(),
                health: Health::Red,
                evidence: format!("cannot read {path}: {error}"),
                observed_unix_nanos: now,
            });

            return snapshot;
        }
    };

    let configuration = match xmip_configure::parse_service_configuration(&source) {
        Ok(configuration) => configuration,
        Err(error) => {
            snapshot.record_health(HealthRecord {
                scope: "xmip:///".into(),
                health: Health::Red,
                evidence: format!("{path} does not parse: {error}"),
                observed_unix_nanos: now,
            });

            return snapshot;
        }
    };

    let node = format!("xmip:///{}", configuration.node_name);

    if let Err(report) = crate::service::plan_startup_from_toml(&source) {
        snapshot.record_health(HealthRecord {
            scope: node,
            health: Health::Red,
            evidence: format!("configuration refused: {}", report.errors.join("; ")),
            observed_unix_nanos: now,
        });

        return snapshot;
    }

    let modules: Vec<_> = configuration.modules.iter().filter(|m| m.start).collect();
    let processes: Vec<_> = configuration
        .xmip_processes
        .iter()
        .filter(|p| p.start)
        .collect();

    snapshot.record_health(HealthRecord {
        scope: node.clone(),
        health: Health::Yellow,
        evidence: format!(
            "{} module(s), {} process(es) validated and planned; not running \u{2014} \
             phases 4\u{2013}9 (start, load, accept work) are not built yet",
            modules.len(),
            processes.len()
        ),
        observed_unix_nanos: now,
    });

    for module in modules {
        snapshot.record_health(HealthRecord {
            scope: format!("{node}/module/{}", module.name),
            health: Health::Yellow,
            evidence: format!("planned, not loaded ({})", module.manifest.identity.version),
            observed_unix_nanos: now,
        });
    }

    for process in processes {
        snapshot.record_health(HealthRecord {
            scope: format!("{node}/process/{}", process.name),
            health: Health::Yellow,
            evidence: format!(
                "planned, not started; needs {}",
                process.required_modules.join(", ")
            ),
            observed_unix_nanos: now,
        });
    }

    snapshot
}

fn now_unix_nanos() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| {
            i64::try_from(since.as_nanos()).unwrap_or(i64::MAX)
        })
}

/// `xmip_start_v1`: [`start`] from a surface. Publishes whatever it found and
/// returns `XMIP_OK` when the node validated, `XMIP_E_INVALID` when it did
/// not, `XMIP_E_MALFORMED` when the path is not UTF-8. The snapshot says why
/// either way, so a surface reads the table rather than the status.
///
/// # Safety
/// `path` must point at `path.len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_start_v1(path: Str) -> i32 {
    let Some(text) = (unsafe { scope_text(path) }) else {
        return status::MALFORMED;
    };

    let snapshot = start(text);
    let valid = snapshot.worst("xmip:///") != Some(Health::Red);

    publish(snapshot);

    if valid { status::OK } else { status::INVALID }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starting_from_a_missing_file_is_red_and_says_which_file() {
        let snapshot = start("Z:/no/such/node.toml");

        assert_eq!(snapshot.worst("xmip:///"), Some(Health::Red));
        assert!(
            snapshot.health("xmip:///")[0]
                .evidence
                .contains("no/such/node.toml")
        );
    }

    #[test]
    fn starting_from_a_valid_file_plans_the_node_and_says_it_is_not_running() {
        let path = std::env::temp_dir().join("xmip-operate-start-test.toml");
        std::fs::write(
            &path,
            r#"
[service]
name = "xmip-edge-01"
cluster_name = "lab"
node_name = "edge-01"

[[modules]]
name = "file"
start = true
[modules.manifest.identity]
name = "file"
version = "0.1.0"
[[modules.manifest.capabilities]]
capability = "transport:file"
execution_host = "native-rust"
trusted_required = true
[modules.manifest.entrypoint]
library_path = "xmip_core_transport_file"
symbol = "xmip_create_module_v1"

[[xmip_processes]]
name = "approval"
start = true
required_modules = ["file"]
xmip_subprocesses = []
extensions = []
"#,
        )
        .expect("write fixture");

        let snapshot = start(path.to_str().expect("utf-8 path"));

        let records = snapshot.health("xmip:///edge-01");
        assert_eq!(records.len(), 3, "node, one module, one process");
        assert!(
            records.iter().all(|r| r.health == Health::Yellow),
            "planned, not running"
        );
        assert!(
            records
                .iter()
                .any(|r| r.scope == "xmip:///edge-01/module/file")
        );
        assert!(
            records
                .iter()
                .any(|r| r.scope == "xmip:///edge-01/process/approval")
        );
        assert!(records[0].evidence.contains("not built yet"));
    }
}
