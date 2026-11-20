//! A person's certificate signed on the node whose authority signs it
//! (ADR-0034, amendment 2026-10-15): the request a surface made, held to
//! `[provision.operator]` in that node's slice — the authority's folder and
//! how long the certificate lasts — and to the operator purpose's rules.
//! The slice is read as its trust admits it (`start::read`, ADR-0031,
//! amendment 2026-11-19): one edited by hand or unsigned is refused, and
//! the node's active configuration is read where it has one. What is signed
//! and how is `xmip-core-provision`'s; this reads the table and hands it
//! over, for `xmip_operate.h` section 19.

use std::path::Path;

/// The chain, PEM, for the request `request`, PEM, signed by the authority
/// the node configured at `configuration` names in `[provision.operator]`,
/// as its trust admits the slice.
///
/// # Errors
///
/// The trust admits nothing to read, the slice names no
/// `[provision.operator]`, the table is refused, or the authority refuses
/// the request; one sentence each.
pub fn sign(configuration: &Path, request: &str) -> Result<String, String> {
    let (document, _, _) =
        crate::start::read(&configuration.to_string_lossy()).map_err(|unread| unread.reason)?;
    let table = document.provision.get("operator").ok_or_else(|| {
        format!(
            "{} has no [provision.operator]: no authority signs a person's request there",
            configuration.display()
        )
    })?;
    let read =
        provision::read("operator", &table.given(), &[]).map_err(|refused| refused.to_string())?;
    let base = configuration.parent().unwrap_or_else(|| Path::new("."));
    provision::operator::sign(&read.settings, base, request, provision::now())
        .map_err(|refused| refused.message)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use file::temporary::Folder;
    use tls::certificate::Certificate;

    use super::*;
    use crate::fixture::{configuration_folder, unsigned, write_signed};

    /// A node's `[service]`, as its slice says it.
    const NODE: &str = "[service]\nname = \"n\"\ncluster_name = \"c\"\nnode_name = \"d\"\n\n";

    /// The table a slice names its authority and an hour's lifetime in.
    const TABLE: &str = "[provision.operator]\nauthority = \"authority\"\nlifetime = \"1h\"\n";

    /// A hundred years, the lifetime a hand edit asks for.
    const CENTURY: &str = "lifetime = \"876000h\"";

    /// `text`, a node's document, as its cluster's authority signs it into
    /// `node.xmip` in a folder of the test's own, with that authority beside
    /// it: the folder, which goes as the test ends, and the slice's path.
    fn configured(name: &str, text: &str) -> (Folder, PathBuf) {
        let own = Folder::new(&format!("runtime-operator-{name}"));
        let path = configuration_folder(&own).join("node.xmip");
        write_signed(&path, text);
        (own, path)
    }

    /// The file at `path` edited by hand: `from` replaced by `to`.
    fn edited(path: &Path, from: &str, to: &str) {
        let file = std::fs::read_to_string(path).expect("the slice");
        assert!(file.contains(from), "{file}");
        std::fs::write(path, file.replace(from, to)).expect("edited");
    }

    /// A person's request.
    fn request() -> String {
        provision::operator::request("alice@example.org")
            .expect("a request")
            .request
    }

    /// The leaf of `chain`, PEM.
    fn leaf(chain: &str) -> Certificate {
        Certificate::first(chain).expect("a leaf")
    }

    #[test]
    fn a_configuration_without_the_operator_table_is_refused_naming_it() {
        let (_own, path) = configured("table", NODE);
        let refused = sign(&path, "").expect_err("no table");
        assert!(refused.contains("[provision.operator]"), "{refused}");
        let absent = path.with_file_name("absent.xmip");
        let refused = sign(&absent, "").expect_err("no file");
        assert!(refused.contains("absent.xmip"), "{refused}");
    }

    #[test]
    fn a_signed_slice_signs_by_its_authority_for_its_lifetime() {
        let (_own, path) = configured("signed", &format!("{NODE}{TABLE}"));
        let chain = sign(&path, &request()).expect("signed");
        let leaf = leaf(&chain);
        assert_eq!(leaf.not_after - leaf.not_before, 3600);
    }

    #[test]
    fn a_hand_edited_lifetime_is_refused_where_no_slice_ran() {
        let (_own, path) = configured("lifetime", &format!("{NODE}{TABLE}"));
        edited(&path, "lifetime = \"1h\"", CENTURY);
        let refused = sign(&path, &request()).expect_err("a hand edit");
        assert!(refused.contains("changed after it was signed"), "{refused}");
        assert!(refused.contains("no active configuration"), "{refused}");
    }

    #[test]
    fn a_hand_edited_lifetime_signs_by_the_active_slice() {
        let (_own, path) = configured("active", &format!("{NODE}{TABLE}"));
        let admitted = crate::signed::admitted(&path).expect("admitted");
        let slice = admitted.candidate.expect("trusted").expect("a candidate");
        crate::signed::activated(&path, &slice).expect("the slice that ran");
        edited(&path, "lifetime = \"1h\"", CENTURY);
        let chain = sign(&path, &request()).expect("by the active slice");
        let leaf = leaf(&chain);
        assert_eq!(
            leaf.not_after - leaf.not_before,
            3600,
            "the edit is not read"
        );
    }

    #[test]
    fn a_hand_edited_authority_signs_by_no_other() {
        let (_own, path) = configured("other", &format!("{NODE}{TABLE}"));
        let folder = path.parent().expect("a folder");
        let other = provision::Issuer::kept_or_made(
            &folder.join("other"),
            "another authority",
            0,
            3_153_600_000,
        )
        .expect("another authority");
        edited(&path, "authority = \"authority\"", "authority = \"other\"");
        let refused = match sign(&path, &request()) {
            Ok(chain) => {
                let by = leaf(other.certificate()).subject;
                panic!("signed, by the other: {}", leaf(&chain).issuer == by)
            }
            Err(refused) => refused,
        };
        assert!(refused.contains("changed after it was signed"), "{refused}");
    }

    #[test]
    fn an_unsigned_operator_table_is_refused() {
        let (_own, path) = configured("unsigned", &format!("{NODE}{TABLE}"));
        std::fs::write(&path, unsigned(&path)).expect("its signature taken off");
        let refused = sign(&path, &request()).expect_err("unsigned");
        assert!(refused.contains("it is not signed"), "{refused}");
    }
}
