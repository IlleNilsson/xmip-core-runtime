//! A person's certificate signed on the node whose authority signs it
//! (ADR-0034, amendment 2026-10-15): the request a surface made, held to
//! `[provision.operator]` in that node's configuration — the authority's
//! folder and how long the certificate lasts — and to the operator
//! purpose's rules. What is signed and how is `xmip-core-provision`'s; this
//! reads the table and hands it over, for `xmip_operate.h` section 19.

use std::path::Path;

/// The chain, PEM, for the request `request`, PEM, signed by the authority
/// the node configuration at `configuration` names in
/// `[provision.operator]`.
///
/// # Errors
///
/// The configuration does not read or names no `[provision.operator]`, the
/// table is refused, or the authority refuses the request; one sentence
/// each.
pub fn sign(configuration: &Path, request: &str) -> Result<String, String> {
    let text = std::fs::read_to_string(configuration)
        .map_err(|failure| format!("{}: {failure}", configuration.display()))?;
    let document = configure::parse_toml(&text)?;
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
    use super::*;

    #[test]
    fn a_configuration_without_the_operator_table_is_refused_naming_it() {
        let place =
            std::env::temp_dir().join(format!("xmip-runtime-operator-{}", std::process::id()));
        std::fs::create_dir_all(&place).expect("made");
        let file = place.join("node.toml");
        std::fs::write(
            &file,
            "[service]\nname = \"n\"\ncluster_name = \"c\"\nnode_name = \"d\"\n",
        )
        .expect("written");
        let refused = sign(&file, "").expect_err("no table");
        assert!(refused.contains("[provision.operator]"), "{refused}");
        let refused = sign(&place.join("absent.toml"), "").expect_err("no file");
        assert!(refused.contains("absent.toml"), "{refused}");
        let _ = std::fs::remove_dir_all(&place);
    }
}
