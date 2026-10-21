//! The local operate endpoint on Windows: a named pipe under `\\.\pipe\`.
//!
//! **Who may open it** is its security descriptor's to say: the account
//! that made it — the node's — the system and the machine's
//! administrators, fully; each account or group `[operate] admit` names,
//! to read and write it and no more; nobody else, and no caller from
//! another machine. **Who connected** is the account the client's token
//! names, lent for identification alone: every surface opens the pipe so
//! (`ffi::system::open_identifying`), and the node reads the account and
//! can never act as it (open problem 35).
//!
//! A pipe has no read timeout, so a read waiting on its peer is ended by
//! [`Cancel`] — the I/O on the pipe cancelled from another thread, which
//! `interprocess`'s overlapped pipes allow — where a socket's is ended by
//! `net::watched` looking between short timeouts.

use std::io::{Read, Write};
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use interprocess::os::windows::named_pipe::DuplexPipeStream;
use interprocess::os::windows::named_pipe::pipe_mode::Bytes;
#[cfg(feature = "node")]
use interprocess::os::windows::named_pipe::{PipeListener, PipeListenerOptions};
#[cfg(feature = "node")]
use interprocess::os::windows::security_descriptor::SecurityDescriptor;

#[cfg(feature = "node")]
use crate::ffi::system::{account_name, account_sid, impersonated};
use crate::ffi::system::{cancel_io, open_identifying, wait_free};

/// Who may open the pipe always, as Windows writes a security descriptor:
/// the account that made it — the node's — the system and the machine's
/// administrators, each fully. No ACE for anyone else is a refusal of
/// everyone else.
#[cfg(feature = "node")]
const OPENERS: &str = "D:P(A;;GA;;;OW)(A;;GA;;;SY)(A;;GA;;;BA)"; // spellchecker:disable-line

/// What an admitted account or group may do to the pipe: read it, its
/// attributes and its descriptor, write its data and wait on it
/// (`FILE_GENERIC_READ | FILE_WRITE_DATA`) — never make an instance of it,
/// which a generic write would grant, so no admitted caller can stand in
/// for the node.
#[cfg(feature = "node")]
const ADMITTED: &str = "0x12008b";

/// What each direction of the pipe holds before a write waits on the
/// reader: room for a call and its answer's frames.
#[cfg(feature = "node")]
const BUFFER: u32 = 64 * 1024;

/// The security descriptor of a pipe `admitted` names the accounts and
/// groups of beside [`OPENERS`], in SDDL.
///
/// # Errors
///
/// A name Windows knows no account or group by.
#[cfg(feature = "node")]
pub(crate) fn openers(admitted: &[String]) -> Result<String, String> {
    let mut sddl = OPENERS.to_string();
    for name in admitted {
        let sid = account_sid(name)?;
        sddl.push_str(&format!("(A;;{ADMITTED};;;{sid})"));
    }
    Ok(sddl)
}

/// The names of the accounts that connected, by the identifier each
/// token proved ([`Stream::caller`]).
#[cfg(feature = "node")]
static NAMES: std::sync::OnceLock<Mutex<std::collections::HashMap<Vec<u32>, String>>> =
    std::sync::OnceLock::new();

/// How many names [`NAMES`] keeps before it starts again: far more
/// accounts than one machine's surfaces run as.
#[cfg(feature = "node")]
const KEPT_NAMES: usize = 1024;

/// The made end, waiting for a connection.
#[cfg(feature = "node")]
pub(crate) struct Acceptor {
    inner: PipeListener<Bytes, Bytes>,
}

#[cfg(feature = "node")]
impl Acceptor {
    /// Make the pipe at `path`, opened only by whom [`OPENERS`] and
    /// `admitted` name and never from another machine.
    ///
    /// # Errors
    ///
    /// A name Windows does not permit, a pipe of that name another process
    /// already made, or an admitted name Windows does not know.
    pub(crate) fn bind(path: &Path, admitted: &[String]) -> Result<Self, String> {
        let sddl = widestring::U16CString::from_str(openers(admitted)?)
            .map_err(|error| error.to_string())?;
        let openers = SecurityDescriptor::deserialize(&sddl).map_err(|e| e.to_string())?;
        let inner = PipeListenerOptions::new()
            .path(path)
            .accept_remote(false)
            .input_buffer_size_hint(BUFFER)
            .output_buffer_size_hint(BUFFER)
            .security_descriptor(Some(openers))
            .create_duplex::<Bytes>()
            .map_err(|error| format!("{}: {error}", path.display()))?;
        Ok(Self { inner })
    }

    /// The next connection; waits until one comes.
    ///
    /// # Errors
    ///
    /// The pipe's own failure.
    pub(crate) fn accept(&self) -> std::io::Result<Stream> {
        // bounded: a listener waits as long as its node runs; a stop wakes it
        self.inner.accept().map(Stream::new)
    }
}

/// One connection, either end.
pub(crate) struct Stream {
    pipe: DuplexPipeStream<Bytes>,
    open: Arc<Mutex<Option<usize>>>,
    /// What was read to learn who connected, and is read again first.
    read_ahead: Vec<u8>,
}

impl Stream {
    fn new(pipe: DuplexPipeStream<Bytes>) -> Self {
        let handle = pipe.as_raw_handle() as usize;
        Self {
            pipe,
            open: Arc::new(Mutex::new(Some(handle))),
            read_ahead: Vec::new(),
        }
    }

    /// The account the connecting process runs as, `DOMAIN\user`, by its
    /// token's word: the identifier the token proves, named as Windows
    /// names it. Windows takes about 0.35 ms to name an identifier — it
    /// asks the local security authority, which for a directory's account
    /// may ask the directory — so a name is kept for the process's life,
    /// by its identifier: the identifier is what the token proved, and an
    /// account renamed meanwhile keeps its old name until the node
    /// restarts (measured 2026-10-21, open problem 35).
    ///
    /// # Errors
    ///
    /// Where Windows does not say, or the client sent nothing.
    #[cfg(feature = "node")]
    pub(crate) fn caller(&mut self) -> Result<String, String> {
        let (sid, _) = self.lent()?;
        let mut names = NAMES
            .get_or_init(Mutex::default)
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(name) = names.get(&sid) {
            return Ok(name.clone());
        }
        let name = account_name(&sid)?;
        if names.len() >= KEPT_NAMES {
            names.clear();
        }
        names.insert(sid, name.clone());
        Ok(name)
    }

    /// The client's token as it lent it: its user's identifier and the
    /// level it was lent at. Windows lets a pipe's client be impersonated
    /// only once something was read from it, so its first bytes are read
    /// here and handed on first.
    ///
    /// # Errors
    ///
    /// Where Windows does not say, or the client sent nothing.
    #[cfg(feature = "node")]
    pub(crate) fn lent(&mut self) -> Result<(Vec<u32>, i32), String> {
        if self.read_ahead.is_empty() {
            let mut first = [0u8; 64];
            let read = self
                .pipe
                .read(&mut first)
                .map_err(|error| format!("the caller sent nothing: {error}"))?;
            if read == 0 {
                return Err("the caller sent nothing".to_string());
            }
            self.read_ahead.extend_from_slice(&first[..read]);
        }
        let _impersonating = self
            .pipe
            .impersonate_client()
            .map_err(|error| format!("the caller is not known: {error}"))?;
        impersonated().map_err(|why| format!("the caller is not known: {why}"))
    }

    /// A pipe has no read timeout: a wait is ended by [`Cancel`].
    #[allow(clippy::unnecessary_wraps, clippy::unused_self)]
    pub(crate) fn watch(&self, _: Duration) -> std::io::Result<()> {
        Ok(())
    }

    /// What ends a read waiting on this connection, from another thread.
    pub(crate) fn cancel(&self) -> Cancel {
        Cancel(Arc::clone(&self.open))
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        // Before the handle closes, so a cancel never reaches a handle
        // reused for something else.
        *self.open.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }
}

/// How much one read of a pipe asks for where its reader asks for less:
/// HTTP/2 reads a frame's header and then its payload, each a read the pipe
/// answers through an overlapped call and an alertable wait, so a call's
/// few frames are read in one (measured 2026-10-21, open problem 35).
const READ: usize = 16 * 1024;

impl Read for Stream {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if self.read_ahead.is_empty() {
            if buffer.len() >= READ {
                return self.pipe.read(buffer);
            }
            let mut read = [0u8; READ];
            let count = self.pipe.read(&mut read)?;
            self.read_ahead.extend_from_slice(&read[..count]);
            if count == 0 {
                return Ok(0);
            }
        }
        let count = self.read_ahead.len().min(buffer.len());
        buffer[..count].copy_from_slice(&self.read_ahead[..count]);
        self.read_ahead.drain(..count);
        Ok(count)
    }
}

impl Write for Stream {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.pipe.write(bytes)
    }

    /// A write is in the pipe once it returns. Windows' flush of a pipe
    /// waits until the peer has read everything, which two peers flushing
    /// at once would wait on each other for.
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Ends a read waiting on a connection, while the connection lives.
pub(crate) struct Cancel(Arc<Mutex<Option<usize>>>);

impl Cancel {
    /// Cancel every read and write in flight on the connection; nothing
    /// where it has closed.
    pub(crate) fn cancel(&self) {
        cancel_io(&self.0);
    }
}

/// Connect to the pipe at `path`, lending the node this process's account
/// for identification alone, waiting at most `patience` for an instance
/// to be free.
///
/// # Errors
///
/// No pipe there, or none free within `patience`, in words.
pub(crate) fn connect(path: &Path, patience: Duration) -> Result<Stream, String> {
    let said = |error: &dyn std::fmt::Display| format!("{}: {error}", path.display());
    let wide = widestring::U16CString::from_os_str(path.as_os_str()).map_err(|e| said(&e))?;
    let until = Instant::now() + patience;
    loop {
        match open_identifying(&wide) {
            Some(Ok(handle)) => {
                return DuplexPipeStream::<Bytes>::try_from(handle)
                    .map(Stream::new)
                    .map_err(|error| said(&error));
            }
            Some(Err(error)) => return Err(said(&error)),
            None => {
                let left = until.saturating_duration_since(Instant::now());
                if left.is_zero() || !wait_free(&wide, left) {
                    return Err(said(&"every instance of the pipe is busy"));
                }
            }
        }
    }
}

/// Wake a listener waiting at `path` for a connection; whether it connected.
#[cfg(feature = "node")]
pub(crate) fn wake(path: &Path) -> bool {
    connect(path, Duration::from_secs(1)).is_ok()
}

#[cfg(all(test, feature = "node"))]
mod tests {
    use super::*;
    use crate::ffi::system::IDENTIFICATION;

    #[test]
    fn a_caller_lends_its_account_for_identification_alone() {
        let path = crate::plane::local::place(&format!("xmip-lent-{}", std::process::id()))
            .expect("a place");
        let acceptor = Acceptor::bind(&path, &[]).expect("it binds");
        let client = std::thread::spawn({
            let path = path.clone();
            move || {
                let mut stream = connect(&path, Duration::from_secs(5)).expect("connected");
                stream.write_all(b"x").expect("written");
                let mut back = [0u8; 1];
                let _ = stream.read(&mut back);
            }
        });
        let mut served = acceptor.accept().expect("accepted");
        let (_, level) = served.lent().expect("lent");
        assert_eq!(level, IDENTIFICATION, "identification alone");
        let caller = served.caller().expect("named");
        assert!(caller.contains('\\'), "DOMAIN\\user: {caller}");
        served.write_all(b"y").expect("answered");
        client.join().expect("the client ends");
    }

    #[test]
    fn an_admitted_account_may_read_and_write_and_a_name_nobody_has_is_refused() {
        let domain = std::env::var("USERDOMAIN").expect("a domain");
        let user = std::env::var("USERNAME").expect("a user");
        let sddl = openers(&[format!("{domain}\\{user}")]).expect("this test's account");
        let admitted = sddl.strip_prefix(OPENERS).expect("the openers first");
        assert!(admitted.starts_with("(A;;0x12008b;;;S-1-"), "{sddl}");
        assert!(admitted.ends_with(')') && admitted.matches('(').count() == 1);
        assert_eq!(openers(&[]).expect("none"), OPENERS);
        let nobody = openers(&["XMIP-NO-SUCH\\nobody-at-all".to_string()]).unwrap_err();
        assert!(nobody.contains("knows no account or group"), "{nobody}");
    }
}
