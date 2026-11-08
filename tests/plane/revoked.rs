//! A certificate the cluster's authority revoked is refused by the operate
//! plane (ADR-0034, amendment 2026-11-07): the node's identity, read as its
//! configuration names it (`presented::identity`), refuses a client the
//! authority's `authority.crl` beside the configuration revokes, and lets
//! its neighbor through.

use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

use xaudit::program_audit::ProgramAudit;
use xmip_core_runtime::fixture::Authority;
use xmip_core_runtime::plane::{Board, Listener, Published, Remote, Role};
use xmip_core_runtime::presented;

use super::endpoint::listing;

/// A surface of `authority`'s named `name`, numbered `serial`, on `address`.
fn surface(authority: &Authority, address: &str, name: &str, serial: u64) -> Remote {
    let (certificate, key, anchors) = authority.pem_numbered(name, serial);
    let identity =
        tls::Identity::from_pem(certificate.as_bytes(), key.as_bytes(), anchors.as_bytes())
            .expect("an identity");
    Remote::retrying(address, &identity, vec![Duration::from_millis(50)]).expect("a remote")
}

#[test]
fn an_operator_the_authority_revoked_is_refused_and_its_neighbor_reads() {
    let authority = Authority::new();
    let base = &authority.directory;
    let (certificate, key, anchors) = authority.pem("node");
    for (name, text) in [
        ("node.pem", &certificate),
        ("node.key", &key),
        ("anchors.pem", &anchors),
    ] {
        std::fs::write(base.join(name), text).expect("written");
    }
    let configuration = base.join("node.xmip");
    let list = presented::list_at(&configuration);
    std::fs::create_dir_all(list.parent().expect("a folder")).expect("a folder");
    std::fs::write(&list, authority.revoking(&[7])).expect("the list");

    let files = ["node.pem", "node.key", "anchors.pem"];
    let identity = presented::identity(&configuration, "operate", files).expect("an identity");
    let board = Arc::new(Board::default());
    board.post("source = \"one\"\n".to_string());
    let audit = ProgramAudit::new("plane-revoked-test", Some(base));
    let listener = Listener::start(
        TcpListener::bind("127.0.0.1:0").expect("bound"),
        &identity,
        Arc::clone(&board) as Arc<dyn Published>,
        listing(Role::Operator, &["CN=revoked", "CN=kept"]),
        &audit,
    )
    .expect("it serves");
    let address = listener.address();

    let refused = surface(&authority, &address, "revoked", 7)
        .publication()
        .expect_err("revoked");
    assert!(refused.contains("unreachable"), "{refused}");
    let kept = surface(&authority, &address, "kept", 8).publication();
    assert_eq!(kept.expect("not revoked").1, "source = \"one\"\n");

    let unread = presented::revocation(&base.join("elsewhere").join("node.xmip"), "operate");
    assert!(unread.expect("nothing kept").is_none(), "no list: none");
    std::fs::write(&list, b"").expect("emptied");
    let refused = presented::revocation(&configuration, "operate").expect_err("no list");
    assert!(refused.starts_with("[operate] "), "{refused}");
}
