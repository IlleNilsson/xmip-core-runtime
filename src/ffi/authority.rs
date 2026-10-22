//! `xmip_operate.h` section 23: the cluster's authority kept in a folder,
//! and a node's certificate carried across an air gap (ADR-0034, amendment
//! 2026-10-22). One export, an act and its arguments as JSON, the answer as
//! JSON: every act is the capability's (`provision::register`,
//! `provision::carried`, `provision::renewal`), and this forwards and
//! renders. A node's build only, as section 22.
#![allow(unsafe_code)]

use std::path::{Path, PathBuf};

use abi::ffi::{Str, status};
use provision::carried;
use provision::crl::{self, Reason};
use provision::register::{Record, Register};
use provision::renewal::Standing;
use provision::{Issuer, Parsed, pem};
use serde_json::{Value, json};

use crate::ffi::rule::refuse;
use crate::ffi::text::scope_text;

/// How long an authority set up here is valid: ten years. The assistant's
/// draft of 2026-10-22, for the owner to strike.
const AUTHORITY_LIFETIME: i64 = 10 * 365 * 86_400;

/// The act `act` on the arguments `arguments`, a JSON object, answered as
/// JSON in `out`; `XMIP_E_INVALID` with the refusal in words.
///
/// # Safety
/// The strings point at their stated lengths of readable bytes; `out` has
/// room for `cap` bytes and `out_len` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_authority_v1(
    act: Str,
    arguments: Str,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: the caller upholds the header's contract on both strings.
    let read = [act, arguments].map(|text| unsafe { scope_text(text) });
    let [Some(act), Some(arguments)] = read else {
        return status::MALFORMED;
    };
    let answered = serde_json::from_str::<Value>(if arguments.is_empty() {
        "{}"
    } else {
        arguments
    })
    .map_err(|failure| format!("the arguments are not a JSON object: {failure}"))
    .and_then(|given| acted(act, &Given(given), provision::now()));
    let (code, text) = match answered {
        Ok(answer) => (status::OK, answer.to_string()),
        Err(refused) => (status::INVALID, refused),
    };
    // SAFETY: `out` has room for `cap` bytes and `out_len` is writable.
    unsafe { refuse(&text, out, cap, out_len) };
    code
}

/// The arguments an act was given.
struct Given(Value);

impl Given {
    fn text(&self, key: &str) -> Result<&str, String> {
        self.0
            .get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .ok_or_else(|| format!("the act needs {key}"))
    }

    fn optional(&self, key: &str) -> Option<&str> {
        self.text(key).ok()
    }

    fn path(&self, key: &str) -> Result<PathBuf, String> {
        self.text(key).map(PathBuf::from)
    }

    fn names(&self) -> Vec<String> {
        self.0
            .get("names")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect()
    }
}

/// One act, answered.
fn acted(act: &str, given: &Given, now: i64) -> Result<Value, String> {
    let said = |failure: provision::ProvisionError| failure.message;
    match act {
        "set-up" => set_up(given, now),
        "inspect" => inspect(&given.path("authority")?, now),
        "read" => read(&given.path("certificate")?, now),
        "revoke" => {
            let issuer = Issuer::kept(&given.path("authority")?).map_err(said)?;
            let reason =
                Reason::named(given.optional("reason").unwrap_or("unspecified")).map_err(said)?;
            let record = issuer
                .revoke(given.text("serial")?, reason, now)
                .map_err(said)?;
            Ok(record_json(&record))
        }
        "export" => export(given, now),
        "back-up" => {
            let register = Register::at(&given.path("authority")?);
            let copied = register.back_up(&given.path("folder")?).map_err(said)?;
            let copied: Vec<String> = copied.iter().map(|path| shown(path)).collect();
            Ok(json!({ "copied": copied }))
        }
        "request" => {
            let asked =
                carried::request_into(given.text("node")?, &given.names(), &given.path("folder")?)
                    .map_err(said)?;
            Ok(json!({
                "request": shown(&asked.request),
                "key": shown(&asked.key),
                "names": asked.names,
            }))
        }
        "sign" => sign(given, now),
        "import" => {
            let path = given.path("certificate")?;
            let text = std::fs::read_to_string(&path)
                .map_err(|failure| format!("{}: {failure}", path.display()))?;
            let imported = carried::import(&text, &given.path("folder")?, now).map_err(said)?;
            Ok(json!({
                "certificate": shown(&imported.certificate),
                "key": shown(&imported.key),
                "anchors": shown(&imported.anchors),
                "serial": imported.serial,
                "notAfter": imported.not_after,
                "renewAt": imported.renew_at,
                "anchorFingerprint": imported.anchor_fingerprint,
                "anchorTaken": imported.anchor_taken,
            }))
        }
        other => Err(format!(
            "{other:?} is no act on the cluster's authority; one of set-up, inspect, read, \
             revoke, export, back-up, request, sign, import"
        )),
    }
}

/// The authority kept in `authority`, made there called `name` where none
/// is, and the address it publishes at where `publish` says one.
fn set_up(given: &Given, now: i64) -> Result<Value, String> {
    let place = given.path("authority")?;
    let issuer = Issuer::kept_or_made(&place, given.text("name")?, now, AUTHORITY_LIFETIME)
        .map_err(|failure| failure.message)?;
    if let (Some(address), Some(register)) = (given.optional("publish"), issuer.register()) {
        register
            .publish(address)
            .map_err(|failure| failure.message)?;
    }
    inspect(&place, now)
}

/// The authority and everything it signed.
fn inspect(place: &Path, now: i64) -> Result<Value, String> {
    let said = |failure: provision::ProvisionError| failure.message;
    let issuer = Issuer::kept(place).map_err(said)?;
    let register = issuer.register().ok_or("the authority keeps no register")?;
    let own = Parsed::first(issuer.certificate()).map_err(said)?;
    let anchor = pem::decode("CERTIFICATE", issuer.certificate())
        .map_err(said)?
        .pop()
        .unwrap_or_default();
    let listed = crl::read(&issuer.revocation_list(now).map_err(said)?).map_err(said)?;
    let records: Vec<Value> = register
        .records()
        .map_err(said)?
        .iter()
        .map(|record| {
            let mut shown = record_json(record);
            shown["standing"] = json!(record.standing(now));
            shown
        })
        .collect();
    Ok(json!({
        "authority": shown(place),
        "subject": own.common_name().map_err(said)?.unwrap_or_default(),
        "notBefore": own.not_before,
        "notAfter": own.not_after,
        "fingerprint": provision::fingerprint(&anchor),
        "published": register.published().map_err(said)?,
        "list": {
            "number": listed.number,
            "thisUpdate": listed.this_update,
            "nextUpdate": listed.next_update,
            "revoked": listed.revoked.len(),
        },
        "issued": records,
    }))
}

/// A certificate file's leaf and its standing: what a node's operator
/// reads to know when a request is due.
fn read(path: &Path, now: i64) -> Result<Value, String> {
    let said = |failure: provision::ProvisionError| failure.message;
    let text = std::fs::read_to_string(path)
        .map_err(|failure| format!("{}: {failure}", path.display()))?;
    let leaf = Parsed::first(&text).map_err(said)?;
    let standing = Standing::at(&leaf, now);
    Ok(json!({
        "certificate": shown(path),
        "serial": leaf.serial_hex(),
        "subject": leaf.common_name().map_err(said)?.unwrap_or_default(),
        "names": leaf.names().map_err(said)?,
        "notBefore": standing.not_before,
        "notAfter": standing.not_after,
        "renewAt": standing.renew_at,
        "standing": standing.word(),
    }))
}

/// The authority's certificate, PEM or DER, or its revocation list, DER,
/// written to `path`, never over a file.
fn export(given: &Given, now: i64) -> Result<Value, String> {
    let said = |failure: provision::ProvisionError| failure.message;
    let issuer = Issuer::kept(&given.path("authority")?).map_err(said)?;
    let path = given.path("path")?;
    let format = given
        .optional("format")
        .unwrap_or("pem")
        .to_ascii_lowercase();
    let bytes = match format.as_str() {
        "pem" => issuer.certificate().as_bytes().to_vec(),
        "der" => pem::decode("CERTIFICATE", issuer.certificate())
            .map_err(said)?
            .pop()
            .unwrap_or_default(),
        "crl" => issuer.revocation_list(now).map_err(said)?,
        other => {
            return Err(format!(
                "{other:?} is no form the authority is exported in; pem, der or crl"
            ));
        }
    };
    secret::private_file::create_readable(&path, &bytes).map_err(|failure| {
        if failure.kind() == std::io::ErrorKind::AlreadyExists {
            format!(
                "{} is there already; nothing is overwritten.",
                path.display()
            )
        } else {
            format!("writing {}: {failure}", path.display())
        }
    })?;
    Ok(json!({ "written": shown(&path), "format": format }))
}

/// A node's carried request signed, the chain written where `out` says.
fn sign(given: &Given, now: i64) -> Result<Value, String> {
    let said = |failure: provision::ProvisionError| failure.message;
    let request = given.path("request")?;
    let text = std::fs::read_to_string(&request)
        .map_err(|failure| format!("{}: {failure}", request.display()))?;
    let signed =
        carried::sign(&given.path("authority")?, &text, &given.names(), now).map_err(said)?;
    let written = given.optional("out").map(PathBuf::from);
    if let Some(path) = &written {
        provision::operator::keep(path, &signed.chain, false).map_err(said)?;
    }
    Ok(json!({
        "request": shown(&request),
        "serial": signed.serial,
        "names": signed.names,
        "notAfter": signed.not_after,
        "written": written.as_deref().map(shown),
        "chain": signed.chain,
    }))
}

fn record_json(record: &Record) -> Value {
    json!({
        "serial": record.serial,
        "subject": record.subject,
        "names": record.names,
        "purpose": record.purpose,
        "notBefore": record.not_before,
        "notAfter": record.not_after,
        "renewAt": record.renew_at,
        "renewalId": record.renewal_id,
        "revoked": record.revoked.as_ref().map(|revoked| json!({
            "at": revoked.at,
            "reason": revoked.reason.word(),
        })),
    })
}

fn shown(path: &Path) -> String {
    path.display().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::text::borrow;

    fn asked(act: &str, arguments: &Value) -> (i32, Value) {
        let text = arguments.to_string();
        let mut room = vec![0u8; 65_536];
        let mut length = 0usize;
        // SAFETY: both strings are borrowed for the call and the room is ours.
        let code = unsafe {
            xmip_authority_v1(
                borrow(act),
                borrow(&text),
                room.as_mut_ptr(),
                room.len(),
                &raw mut length,
            )
        };
        let said = String::from_utf8_lossy(&room[..length]).to_string();
        let value = serde_json::from_str(&said).unwrap_or(Value::String(said));
        (code, value)
    }

    #[test]
    fn an_authority_is_set_up_and_a_node_carried_across_an_air_gap_is_registered_and_revoked() {
        let base = std::env::temp_dir().join(format!("xmip-ffi-authority-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let authority = base.join("authority");
        let node = base.join("node");
        let (code, set) = asked(
            "set-up",
            &json!({
                "authority": shown(&authority),
                "name": "test cluster authority",
                "publish": "http://ca.example:8080",
            }),
        );
        assert_eq!(code, status::OK, "{set}");
        assert_eq!(set["published"], "http://ca.example:8080");

        let (code, asked_for) = asked(
            "request",
            &json!({ "node": "r1", "names": ["r1.example"], "folder": shown(&node) }),
        );
        assert_eq!(code, status::OK, "{asked_for}");
        let out = base.join("r1.pem");
        let (code, signed) = asked(
            "sign",
            &json!({
                "authority": shown(&authority),
                "request": asked_for["request"],
                "names": ["r1", "r1.example"],
                "out": shown(&out),
            }),
        );
        assert_eq!(code, status::OK, "{signed}");
        let (code, imported) = asked(
            "import",
            &json!({ "certificate": shown(&out), "folder": shown(&node) }),
        );
        assert_eq!(code, status::OK, "{imported}");
        assert_eq!(imported["anchorTaken"], true);

        let (code, read) = asked("read", &json!({ "certificate": imported["certificate"] }));
        assert_eq!(
            (code, read["standing"].as_str()),
            (status::OK, Some("current"))
        );
        let (code, revoked) = asked(
            "revoke",
            &json!({
                "authority": shown(&authority),
                "serial": signed["serial"],
                "reason": "keyCompromise",
            }),
        );
        assert_eq!(code, status::OK, "{revoked}");
        let (_, inspected) = asked("inspect", &json!({ "authority": shown(&authority) }));
        assert_eq!(inspected["list"]["revoked"], 1);
        assert_eq!(inspected["issued"][0]["standing"], "revoked");

        let (code, refused) = asked("rotate", &json!({}));
        assert_eq!(code, status::INVALID);
        assert!(refused.as_str().is_some_and(|said| said.contains("no act")));
        let anchor = base.join("anchor.cer");
        let export =
            json!({ "authority": shown(&authority), "path": shown(&anchor), "format": "der" });
        assert_eq!(asked("export", &export).0, status::OK);
        assert_eq!(
            asked("export", &export).0,
            status::INVALID,
            "never over a file"
        );
        std::fs::remove_dir_all(&base).expect("removes what it wrote");
    }
}
