//! `xmip_operate.h` section 25 for a node's build: every Report listed,
//! and a Quest probing a node's configuration (ADR-0072, amendment
//! 2026-11-10).
//!
//! The list, each entry's kind and every answer are `xmip-core-report`'s
//! (`report::catalog`, `report::answer`); the runtime hands in the two
//! things the capability cannot know (ADR-0068). When each Quest last
//! probed is read back from the audit its probe was recorded in, through
//! the audit capability's one reader and query ([`AuditProbes`]); no second
//! store keeps it. What a Quest probes is composed here ([`Composed`]): a
//! node's configuration read from a path — a node's own, or a cluster's
//! `cluster.xmip` sliced for one node by `configure::slice`, the two told
//! apart by what each holds and never by the file's name — each Location's
//! wire as its technology declares it, which no transport does yet
//! (ADR-0072 Open 1), and each data domain kept where
//! [`storage::keeping`] decides, the one decision a node starts by. A
//! module adds a Report or a Quest with [`carry`]. The export is
//! `ffi/report.rs`.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::RwLock;
use std::time::Duration;

use configure::{ConfiguredLocation, DocumentKind, XmipConfigurationDocument};
use report::{AtRest, Installation, LastProbes, Report, Reports, Wire, answer};
use serde::Deserialize;
use xaudit::audit_query::AuditQuery;
use xaudit::audit_store;
use xaudit::program_audit::ProgramAudit;
use xcore::lock::ReadWriteLocked;
use xcore::settings::Applies;
use xcore::{ExecutionPhase, Severity};

use crate::storage::{self, Keeping};

/// The action a probe is audited under, and its last one read back by.
pub const PROBED: &str = "quest.probe";

/// Every Report: Xmip's own and each one carried, once the first is
/// carried; Xmip's own alone until then.
static CARRIED: RwLock<Option<Reports>> = RwLock::new(None);

/// Why an act was not answered.
#[derive(Debug, PartialEq, Eq)]
pub enum Unanswered {
    /// Refused, in one sentence opening REFUSED: `XMIP_E_INVALID`.
    Refused(String),
    /// A file could not be read, or the probe's record was kept nowhere,
    /// in one sentence opening FAILED: `XMIP_E_IO`.
    Failed(String),
}

/// Carry `report`: from now on it is listed after Xmip's own, and opened
/// as they are.
///
/// # Errors
/// Where a Report of its name is listed already, saying so.
pub fn carry(report: Box<dyn Report>) -> Result<(), String> {
    CARRIED
        .write_locked()
        .get_or_insert_with(Reports::standard)
        .hold(report)
}

/// `read` over every Report this runtime lists.
fn listed<Read>(read: impl FnOnce(&Reports) -> Read) -> Read {
    let carried = CARRIED.read_locked();
    match carried.as_ref() {
        Some(reports) => read(reports),
        None => read(&Reports::standard()),
    }
}

/// The act `act` on `arguments`, a JSON object, as section 25 answers it,
/// for a caller with `room` bytes for the answer. An `open` whose answer
/// is longer than `room` is answered for its length alone, and its probe is
/// not audited: the caller asks again with room for it (section 5), and
/// that call's probe is the one recorded.
///
/// # Errors
/// As [`Unanswered`] says, for an act that is none, arguments that do not
/// read, and what `list` and `open` refuse or fail at.
pub fn act(act: &str, arguments: &str, room: usize) -> Result<String, Unanswered> {
    let arguments = if arguments.trim().is_empty() {
        "{}"
    } else {
        arguments
    };
    match act {
        "list" => list(&given(arguments)?),
        "open" => open(&given(arguments)?, room),
        other => Err(Unanswered::Refused(format!(
            "REFUSED: {other:?} is no act on the Reports; list or open."
        ))),
    }
}

/// What `list` reads.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Listing {
    /// The one Report to list, by its name; every one where none is named.
    report: Option<String>,
    /// The audit directory, by section 9's rule: empty for the one
    /// `XMIP_AUDIT_DIRECTORY` names.
    #[serde(default)]
    directory: String,
}

/// What `open` reads.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Opening {
    report: String,
    parameter: Option<String>,
    row: Option<String>,
    /// A node's configuration, or a cluster's `cluster.xmip`, by path.
    configuration: String,
    /// The node a `cluster.xmip` is sliced for.
    node: Option<String>,
    /// The program the probe is audited under.
    program: String,
    #[serde(default)]
    directory: String,
}

fn given<'a, Read: Deserialize<'a>>(arguments: &'a str) -> Result<Read, Unanswered> {
    serde_json::from_str(arguments).map_err(|failure| {
        Unanswered::Refused(format!("REFUSED: the arguments do not read: {failure}."))
    })
}

fn stated(directory: &str) -> Option<&Path> {
    (!directory.trim().is_empty()).then(|| Path::new(directory))
}

/// Every Report, or the one asked for, each Quest with its last probe.
fn list(asked: &Listing) -> Result<String, Unanswered> {
    let probes = AuditProbes::read(stated(&asked.directory));
    listed(|reports| answer::listed(reports, &probes, asked.report.as_deref()))
        .map_err(Unanswered::Refused)
}

/// Each Report's last probe as the audit holds it: the newest finished
/// [`PROBED`] record of each; or, where the audit cannot be read, none and
/// why.
struct AuditProbes {
    last: BTreeMap<String, (u64, String)>,
    unread: Option<String>,
}

impl AuditProbes {
    /// The records in `directory`, by section 9's rule.
    fn read(directory: Option<&Path>) -> Self {
        let mut last = BTreeMap::new();
        let Some(file) = audit_store::stated(directory) else {
            return Self { last, unread: None };
        };
        let asked = AuditQuery::from_pairs([
            ("action", PROBED),
            ("sort", "at"),
            ("order", "descending"),
            ("limit", "1000"),
        ])
        .and_then(|query| audit_store::ask(&file, &query).map_err(|failure| failure.to_string()));
        let page = match asked {
            Ok(page) => page,
            Err(failure) => {
                let unread = Some(format!(
                    "FAILED: the last probes could not be read from {}: {failure}.",
                    file.display()
                ));
                return Self { last, unread };
            }
        };
        let finished = page
            .records
            .iter()
            .filter(|entry| ExecutionPhase::worded(&entry.phase) == Some(ExecutionPhase::Finished));
        for entry in finished {
            let report = entry.properties.get("report");
            let took = entry
                .properties
                .get("took_ms")
                .and_then(|took| took.parse().ok());
            if let (Some(report), Some(took)) = (report, took) {
                last.entry(report.clone())
                    .or_insert_with(|| (took, entry.at.clone()));
            }
        }
        Self { last, unread: None }
    }
}

impl LastProbes for AuditProbes {
    fn last(&self, report: &str) -> Option<(u64, String)> {
        self.last.get(report).cloned()
    }

    fn unread(&self) -> Option<&str> {
        self.unread.as_deref()
    }
}

/// The Report asked for opened: its Quest probes the configuration at the
/// path given, and the probe is audited where its answer fits `room`. A
/// Report that cannot be opened is refused before anything is read.
fn open(asked: &Opening, room: usize) -> Result<String, Unanswered> {
    let refused = |said: String| Unanswered::Refused(format!("REFUSED: {said}."));
    if asked.program.trim().is_empty() {
        return Err(refused(
            "open names no program to audit the probe under".to_string(),
        ));
    }
    listed(|reports| {
        answer::probe_of(reports, &asked.report, asked.parameter.as_deref()).map(|_| ())
    })
    .map_err(Unanswered::Refused)?;
    let path = Path::new(&asked.configuration);
    let text = std::fs::read_to_string(path).map_err(|failure| {
        Unanswered::Failed(format!(
            "FAILED: {} could not be read: {failure}.",
            path.display()
        ))
    })?;
    let configuration = configuration(&text, asked.node.as_deref())
        .map_err(|said| refused(format!("{}: {said}", path.display())))?;
    let installation = Composed::of(configuration).map_err(refused)?;
    let (answer, took) = listed(|reports| {
        answer::opened(
            reports,
            &asked.report,
            asked.parameter.as_deref(),
            asked.row.as_deref(),
            &installation,
        )
    })
    .map_err(Unanswered::Refused)?;
    if answer.len() <= room {
        record(asked, &installation, took)?;
    }
    Ok(answer)
}

/// The node's configuration `text` holds: its own, or, of a cluster's,
/// the slice for `node`.
fn configuration(text: &str, node: Option<&str>) -> Result<XmipConfigurationDocument, String> {
    let node = node.map(str::trim).filter(|node| !node.is_empty());
    match (configure::document_kind(text), node) {
        (DocumentKind::Cluster, Some(node)) => {
            configure::parse_toml(&configure::slice(text, node)?)
        }
        (DocumentKind::Cluster, None) => Err(format!(
            "a cluster's cluster.xmip is probed for one of its nodes; name one of {}",
            configure::cluster::nodes(text)?.join(", ")
        )),
        (DocumentKind::Node, node) => {
            let document = configure::parse_toml(text)?;
            match node {
                Some(node) if node != document.service.node_name => Err(format!(
                    "this is the configuration of node {}, not of {node}",
                    document.service.node_name
                )),
                _ => Ok(document),
            }
        }
    }
}

/// One probe audited: the program's record of it, finished.
fn record(asked: &Opening, installation: &Composed, took: Duration) -> Result<(), Unanswered> {
    let node = &installation.configuration.service.node_name;
    let took_ms = answer::milliseconds(took);
    let mut properties = BTreeMap::from([
        ("report".to_string(), asked.report.clone()),
        ("node".to_string(), node.clone()),
        ("took_ms".to_string(), took_ms.to_string()),
    ]);
    let mut probed = format!("node {node}");
    if let Some(parameter) = &asked.parameter {
        properties.insert("parameter".to_string(), parameter.clone());
        probed = format!("{probed} for {parameter}");
    }
    let said = format!(
        "The {} Report's Quest probed {probed} in {took_ms} ms and changed nothing.",
        asked.report
    );
    ProgramAudit::new(&asked.program, stated(&asked.directory))
        .record(
            PROBED,
            ExecutionPhase::Finished,
            Severity::Information,
            Some(&said),
            properties,
        )
        .map(|_| ())
        .map_err(|failure| {
            Unanswered::Failed(format!(
                "FAILED: the probe was answered and its record was kept nowhere: {failure}."
            ))
        })
}

/// What a Quest probes, as the runtime composes it from a node's
/// configuration.
struct Composed {
    configuration: XmipConfigurationDocument,
    kept: [(&'static str, Keeping); 3],
}

impl Composed {
    /// The installation `configuration` describes; refused where it does
    /// not say where its data domains are kept, or a domain's table names
    /// none its database may be kept on, in the words a node starting by it
    /// is refused in.
    fn of(configuration: XmipConfigurationDocument) -> Result<Self, String> {
        let mut problems = Vec::new();
        let kept = storage::keeping(&configuration)?.map(|(word, kept)| {
            let kept = kept.unwrap_or_else(|problem| {
                problems.push(problem);
                Keeping::Listed
            });
            (word, kept)
        });
        if !problems.is_empty() {
            return Err(problems.join("; "));
        }
        Ok(Self {
            configuration,
            kept,
        })
    }
}

impl Installation for Composed {
    fn configuration(&self) -> &XmipConfigurationDocument {
        &self.configuration
    }

    /// Undeclared: no transport declares its wire yet (ADR-0072 Open 1).
    fn wire(&self, _: &ConfiguredLocation, _: Applies) -> Wire {
        Wire::Undeclared
    }

    fn at_rest(&self, domain: &str) -> AtRest {
        let kept = self.kept.iter().find(|(word, _)| *word == domain);
        // A word that names no data domain is kept on no node of its own.
        kept.map_or(AtRest::StorageNodes, |(_, kept)| match kept {
            Keeping::Own => AtRest::Sealed,
            Keeping::Server(server) => AtRest::Server(server.word()),
            Keeping::Listed => AtRest::StorageNodes,
        })
    }
}

#[cfg(test)]
mod tests;
