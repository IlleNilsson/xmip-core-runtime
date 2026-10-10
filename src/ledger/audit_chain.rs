//! A writer's audit chain in Xmip Storage, verified (ADR-0070 clause 5,
//! amended 2026-10-10: *one chain per writer*): the kept records of one
//! node, or of one program where no node writes them, read in the order of
//! their numbers by the kept table's index on the writer and the number,
//! each with the records of the Streams it carries and its body passed
//! chunk by chunk and held to its digest, never whole, digested by Xmip
//! Storage's one canonical form (`persist::storage::chain_digest`) and
//! walked by the audit capability's one walk (`xaudit::audit_chain::walk`),
//! which says the first place the chain breaks, or that it is whole.

use std::io;

use persist::PersistError;
use persist::storage::{Ask, ChunkReader, Chunked, Query, XmipStorage, chain_digest};
use xaudit::audit_chain::{FIRST, Link, Verdict, walk};
use xcore::AuditId;

/// Walk `writer`'s audit chain as Xmip Storage keeps it. A record whose
/// index entry stands and whose record is gone is passed over, so its
/// number reads as deleted; a Stream's row it lacks, or a body not as it
/// was kept, leaves its digest unmatched.
///
/// # Errors
///
/// Xmip Storage could not be asked or read.
pub fn verify_audit_chain(
    storage: &dyn XmipStorage,
    writer: &str,
) -> Result<Verdict, PersistError> {
    let asked = Query {
        ask: Ask::AuditChain {
            writer: writer.to_string(),
            from: 1,
        },
        most: u32::MAX,
        newest_first: false,
    };
    let mut links = Vec::new();
    for id in storage.query(&asked)? {
        let id = AuditId::new(id);
        let Some(kept) = storage.read_kept_audit(id)? else {
            continue;
        };
        let mut streams = Vec::new();
        for stream in &kept.streams {
            streams.extend(storage.read_kept_audit_stream(kept.id, *stream)?);
        }
        // Its body as this row says it, read under the record's own identifier.
        let from = Chunked::AuditBody(kept.id, kept.facts.body_digest);
        let mut body = ChunkReader::new(storage, from, kept.facts.body_length);
        let whole = io::copy(&mut body, &mut io::sink()).is_ok();
        links.push(Link {
            record: kept.id.to_string(),
            position: kept.facts.position,
            previous: kept.facts.previous,
            digest: kept.facts.digest,
            computed: if whole {
                chain_digest(&kept, &streams)
            } else {
                FIRST
            },
        });
    }
    Ok(walk(writer, links))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use persist::fixture::Memory;
    use persist::storage::{Audited, Embedded, Form, KeptStream};
    use secret::{Held, KekName};
    use xaudit::audit_chain::Break;
    use xaudit::audit_record::AuditRecord;
    use xaudit::origin::Origin;
    use xcore::{ExecutionPhase, Severity, StreamId};

    use super::*;
    use crate::ledger::{audit_entry, write_stream};

    type Node = Embedded<Memory, Memory>;

    /// Where the audit database keeps a kept record and a kept
    /// Stream's row, as Xmip Storage names them.
    const KEPT: &str = "audit";
    const KEPT_STREAM: &str = "audit_stream";
    const KEPT_BODY: &str = "audit-body-chunk";

    /// Six records kept: four by the test cluster's first node, the second
    /// of them carrying a Stream, and two by its second node, between them.
    /// The node, the two writers and the first node's records' identifiers.
    fn kept() -> (Node, [String; 2], Vec<AuditId>) {
        let keys = Held::new(secret::fixture::Memory::default());
        let kek = KekName::new(crate::storage::KEK).expect("a name");
        let node = Embedded::open(
            Memory::default(),
            Memory::default(),
            Memory::default(),
            &keys,
            &kek,
        )
        .expect("opened");
        let cluster = configure::fixture::test_cluster();
        let writers = [cluster.node_scope(0), cluster.node_scope(1)];
        let content = b"<Order/>".repeat(300);
        write_stream(&node, StreamId::new(90), &mut content.as_slice(), 1024).expect("stream");
        let mut first = Vec::new();
        for number in 1..=6u128 {
            let mut origin = Origin::here("xmip-service");
            let writer = &writers[usize::from(number % 3 == 0)];
            origin.location = Some(writer.clone());
            let record = AuditRecord {
                audit_id: AuditId::new(number),
                origin,
                scope: None,
                action: "publish".to_string(),
                phase: ExecutionPhase::Finished,
                severity: Severity::Information,
                timestamp_unix_nanos: 42,
                message: None,
                properties: BTreeMap::new(),
            };
            let mut entry = audit_entry(&record);
            if number == 2 {
                entry.audited = Some(Audited {
                    message: b"the Message".to_vec(),
                    streams: vec![StreamId::new(90)],
                });
            }
            if number % 3 != 0 {
                first.push(entry.id);
            }
            node.write_audit(&entry).expect("written");
        }
        assert_eq!(node.keep_audit(10, crate::ledger::CHUNK).expect("kept"), 6);
        (node, writers, first)
    }

    fn broken(node: &Node, writer: &str) -> Option<Break> {
        let verdict = verify_audit_chain(node, writer).expect("walked");
        assert_eq!(verdict.whole(), verdict.broken.is_none());
        verdict.broken
    }

    fn raw(node: &Node, id: AuditId) -> Vec<u8> {
        let key = id.value().to_be_bytes();
        node.audit().get(KEPT, &key).expect("read").expect("there")
    }

    #[test]
    fn each_writer_s_chain_is_whole_as_kept() {
        let (node, writers, _) = kept();
        for writer in &writers {
            let verdict = verify_audit_chain(&node, writer).expect("walked");
            assert!(verdict.whole(), "{}", verdict.said());
        }
        let verdict = verify_audit_chain(&node, &writers[0]).expect("walked");
        assert_eq!(verdict.records, 4);
        assert!(verdict.said().starts_with("OK: "), "{}", verdict.said());
    }

    #[test]
    fn a_deleted_record_is_found_before_the_next_and_the_other_writer_is_whole() {
        let (node, writers, first) = kept();
        let key = first[1].value().to_be_bytes();
        node.audit().remove(KEPT, &key).expect("removed");

        let deleted = Break::Deleted {
            record: first[2].to_string(),
            position: 3,
            from: 2,
            to: 2,
        };
        assert_eq!(broken(&node, &writers[0]), Some(deleted));
        assert_eq!(broken(&node, &writers[1]), None, "a chain of its own");
    }

    #[test]
    fn a_changed_record_and_a_changed_stream_row_are_found_where_they_are() {
        let (node, writers, first) = kept();
        let mut changed =
            persist::storage::KeptAudit::from_bytes(&raw(&node, first[2])).expect("a record");
        changed.facts.severity = "Warning".to_string();
        let key = first[2].value().to_be_bytes();
        node.audit().put(KEPT, &key, &changed.bytes()).expect("put");
        let at_three = Break::Changed {
            record: first[2].to_string(),
            position: 3,
        };
        assert_eq!(broken(&node, &writers[0]), Some(at_three));

        let (node, writers, first) = kept();
        let stream = StreamId::new(90);
        let mut row = node.read_kept_audit_stream(first[1], stream).expect("read");
        let row = row.as_mut().expect("its row");
        row.digest[0] ^= 1;
        let changed = KeptStream {
            audit: first[1],
            stream: *row,
        };
        let key = [first[1].value().to_be_bytes(), stream.value().to_be_bytes()].concat();
        node.audit()
            .put(KEPT_STREAM, &key, &changed.bytes())
            .expect("put");
        let at_two = Break::Changed {
            record: first[1].to_string(),
            position: 2,
        };
        assert_eq!(
            broken(&node, &writers[0]),
            Some(at_two),
            "the payload is chained"
        );

        let (node, writers, first) = kept();
        let key = [
            first[1].value().to_be_bytes().as_slice(),
            &0u32.to_be_bytes(),
        ]
        .concat();
        let mut chunk = node.read_kept_audit_chunk(first[1], None, 0).expect("read");
        let chunk = chunk.as_mut().expect("its body's first chunk");
        chunk[0] ^= 1;
        node.audit().put(KEPT_BODY, &key, chunk).expect("put");
        let at_two = Break::Changed {
            record: first[1].to_string(),
            position: 2,
        };
        assert_eq!(
            broken(&node, &writers[0]),
            Some(at_two),
            "the body is chained"
        );
    }

    #[test]
    fn a_reordered_record_is_found_out_of_order() {
        let (node, writers, first) = kept();
        let (second, third) = (raw(&node, first[1]), raw(&node, first[2]));
        let key = |id: AuditId| id.value().to_be_bytes();
        node.audit().put(KEPT, &key(first[1]), &third).expect("put");
        node.audit()
            .put(KEPT, &key(first[2]), &second)
            .expect("put");

        let moved = Break::OutOfOrder {
            record: first[1].to_string(),
            position: 2,
            after: 3,
        };
        assert_eq!(broken(&node, &writers[0]), Some(moved));
    }

    #[test]
    fn storage_kept_in_memory_is_asked_through_its_trait() {
        let storage: Arc<dyn XmipStorage> = Arc::clone(crate::ledger::in_memory());
        let verdict = verify_audit_chain(storage.as_ref(), "nobody").expect("walked");
        assert!(
            verdict.whole(),
            "a writer with no records has a whole, empty chain"
        );
        assert_eq!(verdict.records, 0);
    }
}
