//! `xmip_operate.h` section 8: a publication, read by the one reader there is
//! and handed to a surface as the header's values.
//!
//! A publisher writes its snapshot to a file and a surface that reads files
//! reads it here. The shape is `observe::Publication`'s: this parses the text
//! by [`Publication::read`] and lays what it read out as the header's
//! structs, borrowing every string from the publication it holds, so no
//! surface writes the file's keys or words again (ADR-0027 and ADR-0052,
//! amendments 2026-09-24; open problem 25). Until then `Xmip.Surface`'s
//! `SnapshotOperator` walked the TOML itself.
//!
//! A handle owns what it read and everything borrowed from it; one call frees
//! it. Nothing here touches a running node.
//!
//! In `ffi/`, the one folder of the runtime that may hold unsafe code
//! (ADR-0050, refined 2026-09-25): a surface hands over where to write.
#![allow(unsafe_code)]

use abi::ffi::{Str, status};
use abi::operate::publication::{
    Publication as Handle, PublicationHead, TopologyLink as Link, TopologyNode as Node, run_list,
};
use abi::operate::{HealthEntry, Measurement};
use observe::{Publication, RunList};

use crate::ffi::operate::{borrow, scope_text};
use crate::ffi::rule::{fill, refuse};
use crate::wire::{wire_counted, wire_health, wire_kind, wire_origin, wire_pattern};

/// A read publication and its values laid out as the header's, each string
/// borrowed from `publication`, whose buffers do not move while it lives.
struct Read {
    publication: Publication,
    records: Vec<HealthEntry>,
    counts: Vec<Measurement>,
    nodes: Vec<Node>,
    links: Vec<Link>,
}

impl Read {
    fn of(publication: Publication) -> Self {
        let records = publication
            .records
            .iter()
            .map(|record| HealthEntry {
                scope: borrow(&record.scope),
                health: wire_health(record.health),
                severity: record.severity,
                evidence: borrow(&record.evidence),
                observed_unix_nanos: record.observed_unix_nanos,
            })
            .collect();
        let counts = publication
            .counts
            .iter()
            .map(|count| Measurement {
                scope: borrow(&count.scope),
                counted: wire_counted(count.counted),
                value: count.value,
                window_start_unix_nanos: count.window_start_unix_nanos,
                window_end_unix_nanos: count.window_end_unix_nanos,
                observed_unix_nanos: count.observed_unix_nanos,
            })
            .collect();
        let (nodes, links) = publication.topology.as_ref().map_or_else(
            || (Vec::new(), Vec::new()),
            |topology| {
                let nodes = topology.nodes.iter().map(|node| Node {
                    id: borrow(&node.id),
                    parent: borrow(&node.parent),
                    label: borrow(&node.label),
                    kind: wire_kind(node.kind),
                    scope: borrow(&node.scope),
                    health: wire_health(node.state),
                    origin: wire_origin(node.origin),
                    load: node.load,
                    activity: node.activity,
                    evidence: borrow(&node.evidence),
                });
                let links = topology.links.iter().map(|link| Link {
                    id: borrow(&link.id),
                    from: borrow(&link.from),
                    to: borrow(&link.to),
                    pattern: wire_pattern(link.pattern),
                    origin: wire_origin(link.origin),
                    protocol: borrow(&link.protocol),
                    health: wire_health(link.state),
                    volume: link.volume,
                    rate: link.rate,
                    latency_ms: link.latency_ms,
                    progress: link.progress,
                    attempts: link.attempts,
                    evidence: borrow(&link.evidence),
                });
                (nodes.collect(), links.collect())
            },
        );

        Self {
            publication,
            records,
            counts,
            nodes,
            links,
        }
    }

    fn head(&self) -> PublicationHead {
        let publication = &self.publication;
        let run = publication.run.as_ref();
        let topology = publication.topology.as_ref();
        PublicationHead {
            source: borrow(&publication.source),
            node: borrow(&publication.node),
            has_run: u8::from(run.is_some()),
            cluster: run.map_or(Str::empty(), |run| borrow(&run.cluster)),
            stress: run.map_or(Str::empty(), |run| borrow(&run.stress)),
            has_topology: u8::from(topology.is_some()),
            topology_source: topology.map_or(Str::empty(), |drawn| borrow(&drawn.source)),
            topology_observed_unix_nanos: topology.map_or(0, |drawn| drawn.observed_unix_nanos),
        }
    }
}

/// The header's fill shape over values already laid out.
///
/// # Safety
/// `out` has room for `cap` entries; `out_len` is writable.
pub(crate) unsafe fn fill_copied<T: Copy>(
    items: &[T],
    out: *mut T,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: at most `cap` entries are written; `out_len` is writable.
    unsafe {
        if cap > 0 {
            core::ptr::copy_nonoverlapping(items.as_ptr(), out, items.len().min(cap));
        }
        *out_len = items.len();
    }
    status::OK
}

/// The read publication behind a handle.
///
/// # Safety
/// `publication` is null or a handle `xmip_publication_read_v1` returned and
/// nobody freed.
unsafe fn held<'a>(publication: *const Handle) -> Option<&'a Read> {
    // SAFETY: per the contract above.
    unsafe { publication.cast::<Read>().as_ref() }
}

/// `observe::Publication::read`, into a handle, or the reader's refusal.
///
/// # Safety
/// `text` points at its stated length of readable bytes; `out` and
/// `out_len` are writable; `report` has room for `cap` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_publication_read_v1(
    text: Str,
    out: *mut *mut Handle,
    report: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: the caller upholds the header's contract on `text`.
    let Some(text) = (unsafe { scope_text(text) }) else {
        return status::MALFORMED;
    };

    match Publication::read(text) {
        Ok(publication) => {
            let read = Box::into_raw(Box::new(Read::of(publication)));
            // SAFETY: `out` and `out_len` are writable per the contract.
            unsafe {
                *out = read.cast::<Handle>();
                *out_len = 0;
            }
            status::OK
        }
        Err(said) => {
            // SAFETY: per the contract above.
            unsafe {
                *out = core::ptr::null_mut();
                refuse(&said, report, cap, out_len);
            }
            status::INVALID
        }
    }
}

/// Release a handle and everything borrowed from it.
///
/// # Safety
/// `publication` is null or a handle `xmip_publication_read_v1` returned and
/// nobody freed; nothing borrowed from it is used afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_publication_free_v1(publication: *mut Handle) {
    if !publication.is_null() {
        // SAFETY: per the contract above, the box this handle was made from.
        drop(unsafe { Box::from_raw(publication.cast::<Read>()) });
    }
}

/// Who published, where, and the run's and the topology's single values.
///
/// # Safety
/// `publication` is a live handle; `out` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_publication_head_v1(
    publication: *const Handle,
    out: *mut PublicationHead,
) -> i32 {
    // SAFETY: per the contract above.
    let Some(read) = (unsafe { held(publication) }) else {
        return status::INVALID;
    };
    // SAFETY: `out` is writable per the contract.
    unsafe { out.write(read.head()) };
    status::OK
}

/// The records, worst first.
///
/// # Safety
/// `publication` is a live handle; `out` has room for `cap` entries;
/// `out_len` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_publication_records_v1(
    publication: *const Handle,
    out: *mut HealthEntry,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: per the contract above.
    unsafe { held(publication) }.map_or(status::INVALID, |read| unsafe {
        fill_copied(&read.records, out, cap, out_len)
    })
}

/// The counts, each at its scope.
///
/// # Safety
/// As for [`xmip_publication_records_v1`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_publication_counts_v1(
    publication: *const Handle,
    out: *mut Measurement,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: per the contract above.
    unsafe { held(publication) }.map_or(status::INVALID, |read| unsafe {
        fill_copied(&read.counts, out, cap, out_len)
    })
}

/// The topology's nodes; none when it draws none.
///
/// # Safety
/// As for [`xmip_publication_records_v1`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_publication_nodes_v1(
    publication: *const Handle,
    out: *mut Node,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: per the contract above.
    unsafe { held(publication) }.map_or(status::INVALID, |read| unsafe {
        fill_copied(&read.nodes, out, cap, out_len)
    })
}

/// The topology's links; none when it draws none.
///
/// # Safety
/// As for [`xmip_publication_records_v1`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_publication_links_v1(
    publication: *const Handle,
    out: *mut Link,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: per the contract above.
    unsafe { held(publication) }.map_or(status::INVALID, |read| unsafe {
        fill_copied(&read.links, out, cap, out_len)
    })
}

/// One of the run's lists: `XMIP_E_NOT_FOUND` when the publication says
/// nothing of its run, `XMIP_E_INVALID` for a list the header does not name.
///
/// # Safety
/// As for [`xmip_publication_records_v1`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_publication_run_v1(
    publication: *const Handle,
    list: u32,
    out: *mut Str,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: per the contract above.
    let Some(read) = (unsafe { held(publication) }) else {
        return status::INVALID;
    };
    let which = match list {
        run_list::TESTS => RunList::Tests,
        run_list::NODES => RunList::Nodes,
        run_list::CAPABILITIES => RunList::Capabilities,
        run_list::ONLINE => RunList::Online,
        _ => return status::INVALID,
    };
    let Some(run) = &read.publication.run else {
        // SAFETY: `out_len` is writable per the contract.
        unsafe { *out_len = 0 };
        return status::NOT_FOUND;
    };

    // SAFETY: per the contract above.
    unsafe {
        fill(
            run.list(which).iter().map(String::as_str),
            out,
            cap,
            out_len,
        )
    };
    status::OK
}

#[cfg(test)]
mod tests {
    use super::*;
    use abi::operate::publication::{self, kind, origin, pattern};
    use abi::operate::{counted, health};

    const ROLL: &str = r#"
source = "playground — xmip:///C1"
node = "xmip:///C1"

[[records]]
scope = "xmip:///C1/node/alpha/receive/tcp"
state = "done"
severity = 90
evidence = "refused"
observed_unix_nanos = 9

[[records]]
scope = "xmip:///C1/node/alpha/capability"
state = "sulking"
severity = 0
evidence = "declares receive; online; x"
observed_unix_nanos = 7

[[counts]]
counted = "streams"
value = 4

[[counts]]
counted = "throughput"
value = 1

[run]
cluster = "C1"
tests = ["RoundTrip"]
nodes = ["alpha"]
capabilities = ["alpha=receive"]
online = ["alpha"]
stress = "harsh"

[topology]
source = "drawn"
observed_unix_nanos = 5

[[topology.nodes]]
id = "cluster"
kind = "cluster"
scope = "xmip:///C1"
state = "fine"
origin = "configured"
activity = 0.5

[[topology.links]]
id = "handoff/alpha/beta"
from = "node/alpha/receive"
to = "node/beta/process"
pattern = "retry"
origin = "observed"
state = "stressed"
volume = 3
attempts = 2
"#;

    fn text(value: Str) -> String {
        if value.ptr.is_null() {
            return String::new();
        }
        // SAFETY: the export promises `len` readable bytes.
        let bytes = unsafe { core::slice::from_raw_parts(value.ptr, value.len) };
        String::from_utf8(bytes.to_vec()).expect("UTF-8")
    }

    fn read(source: &str) -> (i32, *mut Handle, String) {
        let mut handle = core::ptr::null_mut();
        let mut report = [0u8; 512];
        let mut len = 0usize;
        // SAFETY: `source` is live; every out is writable.
        let code = unsafe {
            xmip_publication_read_v1(
                borrow(source),
                &raw mut handle,
                report.as_mut_ptr(),
                report.len(),
                &raw mut len,
            )
        };
        let said = String::from_utf8(report[..len.min(512)].to_vec()).expect("UTF-8");
        (code, handle, said)
    }

    fn listed<T: Copy>(
        handle: *const Handle,
        fill: unsafe extern "C" fn(*const Handle, *mut T, usize, *mut usize) -> i32,
        empty: T,
    ) -> Vec<T> {
        let mut len = 0usize;
        // SAFETY: a live handle; nothing is written for no room.
        assert_eq!(
            unsafe { fill(handle, core::ptr::null_mut(), 0, &raw mut len) },
            status::OK
        );
        let mut out = vec![empty; len];
        // SAFETY: `out` has room for `len` entries.
        assert_eq!(
            unsafe { fill(handle, out.as_mut_ptr(), len, &raw mut len) },
            status::OK
        );
        out
    }

    #[test]
    fn every_export_has_the_shape_the_binding_declares() {
        let _: publication::ReadFn = xmip_publication_read_v1;
        let _: publication::FreeFn = xmip_publication_free_v1;
        let _: publication::HeadFn = xmip_publication_head_v1;
        let _: publication::RecordsFn = xmip_publication_records_v1;
        let _: publication::CountsFn = xmip_publication_counts_v1;
        let _: publication::NodesFn = xmip_publication_nodes_v1;
        let _: publication::LinksFn = xmip_publication_links_v1;
        let _: publication::RunFn = xmip_publication_run_v1;
    }

    #[test]
    fn a_roll_crosses_whole_as_observe_reads_it() {
        let (code, handle, said) = read(ROLL);
        assert_eq!((code, said.as_str()), (status::OK, ""));

        let mut head = PublicationHead {
            source: Str::empty(),
            node: Str::empty(),
            has_run: 9,
            cluster: Str::empty(),
            stress: Str::empty(),
            has_topology: 9,
            topology_source: Str::empty(),
            topology_observed_unix_nanos: 0,
        };
        // SAFETY: a live handle; `head` is writable.
        assert_eq!(
            unsafe { xmip_publication_head_v1(handle, &raw mut head) },
            status::OK
        );
        assert_eq!(text(head.node), "xmip:///C1");
        assert_eq!((head.has_run, text(head.stress)), (1, "harsh".to_string()));
        assert_eq!(
            (head.has_topology, head.topology_observed_unix_nanos),
            (1, 5)
        );

        let empty = HealthEntry {
            scope: Str::empty(),
            health: -1,
            severity: 0,
            evidence: Str::empty(),
            observed_unix_nanos: 0,
        };
        let records = listed(handle, xmip_publication_records_v1, empty);
        let moods: Vec<i32> = records.iter().map(|record| record.health).collect();
        assert_eq!(
            moods,
            [health::DONE, health::STRESSED],
            "an unknown mood shows"
        );

        let none = Measurement {
            scope: Str::empty(),
            counted: 0,
            value: 0,
            window_start_unix_nanos: 0,
            window_end_unix_nanos: 0,
            observed_unix_nanos: 0,
        };
        let counts = listed(handle, xmip_publication_counts_v1, none);
        assert_eq!(counts.len(), 1, "an unknown kind is skipped");
        assert_eq!((counts[0].counted, counts[0].value), (counted::STREAMS, 4));
        assert_eq!(text(counts[0].scope), "xmip:///C1");

        let blank = Node {
            id: Str::empty(),
            parent: Str::empty(),
            label: Str::empty(),
            kind: -1,
            scope: Str::empty(),
            health: -1,
            origin: -1,
            load: 0.0,
            activity: 0.0,
            evidence: Str::empty(),
        };
        let nodes = listed(handle, xmip_publication_nodes_v1, blank);
        assert_eq!(
            (nodes[0].kind, nodes[0].origin),
            (kind::CLUSTER, origin::CONFIGURED)
        );
        assert_eq!(text(nodes[0].label), "cluster", "a missing label is the id");

        let unlinked = Link {
            id: Str::empty(),
            from: Str::empty(),
            to: Str::empty(),
            pattern: -1,
            origin: -1,
            protocol: Str::empty(),
            health: -1,
            volume: 0,
            rate: 0.0,
            latency_ms: 0.0,
            progress: 0.0,
            attempts: 0,
            evidence: Str::empty(),
        };
        let links = listed(handle, xmip_publication_links_v1, unlinked);
        assert_eq!((links[0].pattern, links[0].attempts), (pattern::RETRY, 2));

        let mut words = [Str::empty(); 2];
        let mut len = 0usize;
        // SAFETY: a live handle; `words` has room for two.
        let code = unsafe {
            xmip_publication_run_v1(
                handle,
                run_list::CAPABILITIES,
                words.as_mut_ptr(),
                2,
                &raw mut len,
            )
        };
        assert_eq!(
            (code, len, text(words[0])),
            (status::OK, 1, "alpha=receive".to_string())
        );
        // SAFETY: as above.
        let unknown =
            unsafe { xmip_publication_run_v1(handle, 9, words.as_mut_ptr(), 2, &raw mut len) };
        assert_eq!(unknown, status::INVALID);

        // SAFETY: the handle was read above and is freed once.
        unsafe { xmip_publication_free_v1(handle) };
    }

    #[test]
    fn a_node_file_has_no_run_and_a_stranger_is_refused_with_the_readers_words() {
        let (code, handle, _) = read("node = 'xmip:///alpha'");
        assert_eq!(code, status::OK);
        let mut len = 9usize;
        // SAFETY: a live handle; nothing is written for no room.
        let none = unsafe {
            xmip_publication_run_v1(
                handle,
                run_list::TESTS,
                core::ptr::null_mut(),
                0,
                &raw mut len,
            )
        };
        assert_eq!((none, len), (status::NOT_FOUND, 0));
        // SAFETY: freed once; a null handle is nothing to free.
        unsafe {
            xmip_publication_free_v1(handle);
            xmip_publication_free_v1(core::ptr::null_mut());
        }

        let (code, handle, said) = read("not = [toml");
        assert_eq!(code, status::INVALID);
        assert!(handle.is_null());
        assert!(!said.is_empty());
    }
}
