//! A System Process's declaration on disk (ADR-0053 clause 3): the one file
//! each process writes about itself where it starts and takes away where it
//! ends, the directory every process on the machine meets in, and the
//! reading back of every declaration standing there. What a declaration
//! says, its words and its text are `node`'s ([`node::Declaration`],
//! [`node::Standing`]); writing, listing and removing the file is acting,
//! so it is the runtime's (ADR-0058 clause 1, amendment 2026-11-13).
//!
//! A process writes its declaration to one file named for it and its pid; a
//! process that is killed leaves its file behind, and whoever lists the
//! declarations drops the ones whose process is gone. The directory is the
//! node's to say, in [`DIRECTORY_VARIABLE`]; unset, it is `xmip/process`
//! under the system's temporary directory, the same for every process on
//! the machine, so that a reader and a writer who were told nothing still
//! meet.
//!
//! No other language writes, reads or removes a declaration again:
//! `ffi::process` forwards [`declare`], [`standing`] and [`undeclare`] to the
//! surfaces as `xmip_process_declare_v1`, `xmip_process_declarations_v1` and
//! `xmip_process_undeclare_v1` (`xmip_operate.h` section 13), and
//! `Xmip.Surface` and the estate's PowerShell module call those. Until
//! 2026-11-13 the file was `xmip-core-node`'s, a Foundation crate writing and
//! reading one, and .NET and PowerShell each deleted it themselves.

use std::path::{Path, PathBuf};
use std::{env, fs, io};

use node::{Declaration, Standing};
use xcore::{Clock, SystemClock};

/// The environment variable that names the directory declarations are
/// written to.
pub const DIRECTORY_VARIABLE: &str = "XMIP_PROCESS_DIRECTORY";

/// Declare this process, as `declaration` says it, in the directory the
/// node names ([`directory`]).
///
/// # Errors
///
/// The directory could not be made or the file could not be written. A
/// process that cannot declare itself still runs; its caller says so.
pub fn declare(declaration: &Declaration) -> io::Result<Declared> {
    declare_in(declaration, &directory())
}

/// Declare this process, as `declaration` says it, in `directory`.
///
/// # Errors
///
/// The directory could not be made or the file could not be written.
pub fn declare_in(declaration: &Declaration, directory: &Path) -> io::Result<Declared> {
    fs::create_dir_all(directory)?;

    let pid = std::process::id();
    let file = directory.join(format!("{}-{pid}.toml", declaration.name));
    // The file counts whole seconds; the clock is the estate's one.
    let started = u64::try_from(SystemClock.unix_seconds()).unwrap_or(0);
    let path = env::current_exe()
        .map(|path| path.display().to_string())
        .unwrap_or_default();

    fs::write(&file, declaration.to_toml(pid, started, &path))?;
    Ok(Declared { file })
}

/// A declaration that stands while this is held and is taken away when it
/// is dropped.
#[derive(Debug)]
pub struct Declared {
    file: PathBuf,
}

impl Declared {
    /// The file the declaration was written to.
    #[must_use]
    pub fn file(&self) -> &Path {
        &self.file
    }

    /// Leave the declaration standing and hand its file to a holder across
    /// the C boundary, which takes it away where its process ends.
    #[must_use]
    pub fn handed_over(mut self) -> PathBuf {
        // What is dropped then names no file, and removing it removes nothing.
        std::mem::take(&mut self.file)
    }
}

impl Drop for Declared {
    fn drop(&mut self) {
        // Gone already is as good as removed; one handed over names no file.
        let _ = undeclare(&self.file);
    }
}

/// Take away the declaration standing in `file`: where its process ends, or
/// where a reader that sees the operating system's processes finds it gone.
/// A file already gone is as good as removed.
///
/// # Errors
///
/// `file` is not a declaration's: one named `xmip-*.toml`, as every
/// declaration is, and nothing else is removed — REFUSED, as
/// [`io::ErrorKind::InvalidInput`]. Or the file could not be removed.
pub fn undeclare(file: &Path) -> io::Result<()> {
    if !is_declaration(file) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "REFUSED: {} is no declaration's file; a declaration stands in xmip-*.toml.",
                file.display()
            ),
        ));
    }

    match fs::remove_file(file) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        removed => removed,
    }
}

/// Whether `file` is named as a declaration's is: `xmip-`, then what the
/// process is called and its pid, as TOML. A process named `xmip` writes
/// `xmip-<pid>.toml`, so every one begins `xmip-`.
fn is_declaration(file: &Path) -> bool {
    file.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            name.starts_with("xmip-")
                && Path::new(name)
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("toml"))
        })
}

/// Where declarations are written: what the node names, else `xmip/process`
/// under the system's temporary directory.
#[must_use]
pub fn directory() -> PathBuf {
    env::var_os(DIRECTORY_VARIABLE)
        .filter(|named| !named.is_empty())
        .map_or_else(
            || env::temp_dir().join("xmip").join("process"),
            PathBuf::from,
        )
}

/// Every declaration that stands in `directory`, one per `xmip-*.toml` file
/// that holds one, by file name, each read by [`Standing::read`]. A
/// directory that is not there holds none; a file that is not a
/// declaration, or went while it was read — a process ending takes its file
/// with it — is passed over.
///
/// Whether the process that wrote a file still runs is not decided here: a
/// reader that can see the operating system's processes drops the files of
/// the ones that are gone.
#[must_use]
pub fn standing(directory: &Path) -> Vec<Standing> {
    let Ok(entries) = fs::read_dir(directory) else {
        return Vec::new();
    };

    let mut files: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| is_declaration(path))
        .collect();
    files.sort();

    files
        .into_iter()
        .filter_map(|file| {
            let text = fs::read_to_string(&file).ok()?;
            Standing::read(&text, file)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use node::Purpose;

    fn scratch(name: &str) -> PathBuf {
        let directory = env::temp_dir().join("xmip-declared-test").join(name);
        let _ = fs::remove_dir_all(&directory);
        directory
    }

    #[test]
    fn a_declaration_stands_while_held_and_is_gone_when_dropped() {
        let directory = scratch("held");
        // The name is whatever the operator called the node, and nothing here
        // reads anything out of it (ADR-0053).
        let cluster = configure::fixture::test_cluster();
        let name = format!(
            "xmip-essentials-{}-node-{}",
            cluster.name,
            cluster.node(0).name
        );
        let location = cluster.node_scope(0);
        let declaration = Declaration::new(&name, &location, Purpose::Test).expect("a name");

        let declared = declare_in(&declaration, &directory).expect("declared");
        let file = declared.file().to_path_buf();
        let text = fs::read_to_string(&file).expect("the file");

        assert!(
            file.ends_with(format!("{name}-{}.toml", std::process::id())),
            "{}",
            file.display()
        );
        assert!(text.contains(&format!("name = \"{name}\"")), "{text}");
        assert!(
            text.contains(&format!("location = \"{location}\"")),
            "{text}"
        );
        assert!(text.contains("purpose = \"test\""), "{text}");
        assert!(
            text.contains(&format!("pid = {}", std::process::id())),
            "{text}"
        );

        drop(declared);
        assert!(!file.exists(), "taken away where the process ends");
    }

    #[test]
    fn a_declaration_handed_over_stands_until_its_holder_takes_it_away() {
        let directory = scratch("handed");
        let declaration = Declaration::new("xmip", "xmip:///", Purpose::Runtime).expect("a name");
        let declared = declare_in(&declaration, &directory).expect("declared");

        let file = declared.handed_over();

        assert!(file.exists(), "a holder across the boundary removes it");
        undeclare(&file).expect("taken away by its holder");
        assert!(!file.exists(), "taken away");
        undeclare(&file).expect("gone already is as good as removed");
    }

    #[test]
    fn a_file_that_is_no_declarations_is_refused_and_left_where_it_is() {
        let directory = scratch("refused");
        fs::create_dir_all(&directory).expect("made");

        for stranger in ["other-4.toml", "xmip-a-1.txt", "xmip"] {
            let file = directory.join(stranger);
            fs::write(&file, "kept").expect("written");

            let refused = undeclare(&file).expect_err(stranger);

            assert_eq!(refused.kind(), io::ErrorKind::InvalidInput, "{stranger}");
            assert!(refused.to_string().starts_with("REFUSED"), "{refused}");
            assert!(file.exists(), "{stranger} is left where it is");
        }
        assert!(undeclare(Path::new("")).is_err(), "a path naming no file");
    }

    #[test]
    fn what_a_process_declared_is_read_back_whole() {
        let directory = scratch("whole");
        let declaration = Declaration::new("xmip-essentials-node", "a \"b\"\\c", Purpose::Test)
            .and_then(|declaration| declaration.with("online", "true"))
            .expect("a bare key");
        let declared = declare_in(&declaration, &directory).expect("declared");

        let read = standing(&directory);

        assert_eq!(read.len(), 1);
        assert_eq!(read[0].declaration, declaration);
        assert_eq!(read[0].pid, std::process::id());
        assert_eq!(read[0].file, declared.file());
    }

    #[test]
    fn a_file_that_is_no_declaration_and_a_missing_directory_hold_none() {
        let directory = scratch("strangers");
        fs::create_dir_all(&directory).expect("made");
        fs::write(directory.join("xmip-a-1.toml"), "name = \"x\"\n").expect("no pid");
        fs::write(directory.join("xmip-b-2.toml"), "not toml at all").expect("written");
        let declaration = Declaration::new("xmip", "", Purpose::Runtime).expect("a name");
        fs::write(
            directory.join("other-4.toml"),
            declaration.to_toml(4, 1, "other"),
        )
        .expect("a declaration, but not xmip-*");

        assert_eq!(standing(&directory), [] as [Standing; 0]);
        assert_eq!(standing(&directory.join("nowhere")), [] as [Standing; 0]);
    }
}
