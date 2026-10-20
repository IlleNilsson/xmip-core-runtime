//! The local operate endpoint on Windows: a named pipe under `\\.\pipe\`.
//!
//! A pipe has no read timeout, so a read waiting on its peer is ended by
//! [`Cancel`] — the I/O on the pipe cancelled from another thread, which
//! `interprocess`'s overlapped pipes allow — where a socket's is ended by
//! `net::watched` looking between short timeouts.

use std::io::{Read, Write};
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use interprocess::ConnectWaitMode;
use interprocess::os::windows::named_pipe::DuplexPipeStream;
use interprocess::os::windows::named_pipe::pipe_mode::Bytes;
#[cfg(feature = "node")]
use interprocess::os::windows::named_pipe::{PipeListener, PipeListenerOptions};
#[cfg(feature = "node")]
use interprocess::os::windows::security_descriptor::SecurityDescriptor;

use crate::ffi::system::cancel_io;
#[cfg(feature = "node")]
use crate::ffi::system::user_name;

/// Who may open the pipe, as Windows writes a security descriptor: the
/// account that made it — the node's — the system and the machine's
/// administrators, each fully; nobody else. No ACE for anyone else is
/// a refusal of everyone else.
#[cfg(feature = "node")]
const OPENERS: &str = "D:P(A;;GA;;;OW)(A;;GA;;;SY)(A;;GA;;;BA)"; // spellchecker:disable-line

/// What each direction of the pipe holds before a write waits on the
/// reader: room for a call and its answer's frames.
#[cfg(feature = "node")]
const BUFFER: u32 = 64 * 1024;

/// The made end, waiting for a connection.
#[cfg(feature = "node")]
pub(crate) struct Acceptor {
    inner: PipeListener<Bytes, Bytes>,
}

#[cfg(feature = "node")]
impl Acceptor {
    /// Make the pipe at `path`, opened only by whom [`OPENERS`] names and
    /// never from another machine.
    ///
    /// # Errors
    ///
    /// A name Windows does not permit, or a pipe of that name another
    /// process already made.
    pub(crate) fn bind(path: &Path) -> Result<Self, String> {
        let sddl = widestring::U16CString::from_str(OPENERS).map_err(|e| e.to_string())?;
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

    /// The user the connecting process runs as, `DOMAIN\user`: the pipe's
    /// client impersonated for as long as its name is read. Windows lets a
    /// pipe's client be impersonated only once something was read from
    /// it, so its first bytes are read here and handed on first.
    ///
    /// # Errors
    ///
    /// Where Windows does not say, or the client sent nothing.
    #[cfg(feature = "node")]
    pub(crate) fn caller(&mut self) -> Result<String, String> {
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
        user_name()
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

impl Read for Stream {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if self.read_ahead.is_empty() {
            return self.pipe.read(buffer);
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

/// Connect to the pipe at `path`, waiting at most `patience` for an
/// instance to answer.
///
/// # Errors
///
/// No pipe there, or none free within `patience`, in words.
pub(crate) fn connect(path: &Path, patience: Duration) -> Result<Stream, String> {
    DuplexPipeStream::<Bytes>::connect_by_path_with_wait_mode(
        path,
        ConnectWaitMode::Timeout(patience),
    )
    .map(Stream::new)
    .map_err(|error| format!("{}: {error}", path.display()))
}

/// Wake a listener waiting at `path` for a connection; whether it connected.
#[cfg(feature = "node")]
pub(crate) fn wake(path: &Path) -> bool {
    connect(path, Duration::from_secs(1)).is_ok()
}
