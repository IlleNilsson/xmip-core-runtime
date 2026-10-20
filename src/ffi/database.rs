//! `xmip_operate.h` section 20: a database's schema, its upgrade written
//! (open problem 41; ADR-0015, amendment 2026-10-20). The export only —
//! the schema, its versions and the scripts are `persist::storage::schema`'s;
//! `xmip-cli database` and `Get-XmipDatabaseScript` write and render them,
//! and neither knows a table.
//!
//! In `ffi/`, the one folder of the runtime that may hold unsafe code
//! (ADR-0050, refined 2026-09-25): it reads what a surface handed over and
//! writes its answer where it was told.
#![allow(unsafe_code)]

use abi::ffi::{Str, status};
use persist::storage::database::{Server, Technology};
use persist::storage::schema;
use serde_json::{Value, json};

use crate::ffi::rule::refuse;
use crate::ffi::text::scope_text;

/// `xmip_database_upgrade_v1`: [`schema::upgrade`] for the database
/// server `server` names — `postgresql`, `mssql` or `mariadb` — from schema
/// version `from` to `to`, zero for this build's ([`schema::VERSION`]), as
/// the header's JSON: `{"version", "scripts": [{"name", "text"}]}`.
///
/// # Safety
/// As the header states: `server` readable for its length, `out` room for
/// `cap` bytes, `out_len` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_database_upgrade_v1(
    server: Str,
    from: u32,
    to: u32,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: the caller upholds the header's contract on `server`.
    let Some(word) = (unsafe { scope_text(server) }) else {
        return status::MALFORMED;
    };
    let to = if to == 0 { schema::VERSION } else { to };
    let (code, text) = match named(word).and_then(|server| schema::upgrade(server, from, to)) {
        Err(refusal) => (status::INVALID, refusal),
        Ok(scripts) => {
            let scripts: Vec<Value> = scripts
                .into_iter()
                .map(|(name, text)| json!({ "name": name, "text": text }))
                .collect();
            let answer = json!({ "version": schema::VERSION, "scripts": scripts });
            (status::OK, answer.to_string())
        }
    };

    // SAFETY: `out` has room for `cap` bytes and `out_len` is writable.
    unsafe { refuse(&text, out, cap, out_len) };
    code
}

/// The database server `word` names, or the refusal naming the words.
fn named(word: &str) -> Result<Server, String> {
    match Technology::named(word) {
        Some(Technology::Server(server)) => Ok(server),
        _ => {
            let words: Vec<&str> = Server::ALL.iter().map(|server| server.word()).collect();
            Err(format!(
                "'{word}' is no database server Xmip Storage keeps a database on; write {}",
                words.join(", ")
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::text::borrow;

    fn upgrade(server: &str, from: u32, to: u32) -> (i32, String) {
        let mut buffer = vec![0u8; 4096];
        let mut length = 0usize;
        // SAFETY: a buffer of its stated room and a writable length.
        let code = unsafe {
            xmip_database_upgrade_v1(
                borrow(server),
                from,
                to,
                buffer.as_mut_ptr(),
                buffer.len(),
                &raw mut length,
            )
        };
        (
            code,
            String::from_utf8_lossy(&buffer[..length]).into_owned(),
        )
    }

    #[test]
    fn an_upgrade_is_the_schemas_and_one_that_is_none_is_refused_in_words() {
        let (code, said) = upgrade("postgresql", 1, 0);
        assert_eq!(code, status::INVALID, "{said}");
        let none = format!("1 to {} is none", schema::VERSION);
        assert!(
            said.contains(&none),
            "this build is the first release: {said}"
        );

        let (code, said) = upgrade("mongodb", 1, 2);
        assert_eq!(code, status::INVALID);
        assert!(said.contains("write postgresql, mssql, mariadb"), "{said}");
        assert!(
            !said.contains("rocksdb"),
            "an embedded engine runs no script"
        );

        let refused = upgrade("sqlite", 1, 2).1;
        assert!(
            refused.starts_with("'sqlite' is no database server"),
            "{refused}"
        );
    }
}
