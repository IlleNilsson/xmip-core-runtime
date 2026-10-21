//! A web host's HTTPS in Xmip's own TLS (ADR-0009, amendment 2026-10-21;
//! `xmip_operate.h` section 21): the host — a .NET web server — hands the
//! TLS to the runtime and keeps HTTP, so its browsers are served by
//! `xmip-core-library-tls` and never by the platform's stack (the owner,
//! 2026-09-26: *Xmip shall use its own tool chain, dog fooding as much as
//! possible*).
//!
//! A [`SecureListener`] listens on an address, presenting the host's
//! certificate and asking each client for one: one that reaches the anchors
//! names the client, one that does not ends the handshake, and a client
//! that presents none — a browser that declines — is let through as no one
//! (`tls::Identity::server_asking`). HTTP/1.1 is the one protocol agreed
//! (RFC 7301). Each connection's handshake runs on a thread of its own,
//! bounded by [`HANDSHAKE_WITHIN`], so a client that connects and says
//! nothing holds up no other; [`SecureListener::accept`] hands over the next
//! one finished — a [`SecureSession`] — or says why one did not finish, which
//! is reported and never ends the listener. A session is read on one thread
//! and written on another at once (`tls::duplex`), as a web server pumps a
//! connection.

use std::collections::VecDeque;
use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;

use tls::duplex::{ServedReading, ServedWriting};
use tls::peer::Unanswered;

/// How long a client has to finish its handshake once it has connected; a
/// wait on the socket, so one that never speaks costs its own thread this
/// long and no one else anything.
pub const HANDSHAKE_WITHIN: Duration = Duration::from_secs(10);

/// The one application protocol agreed: HTTP/1.1, which the host speaks.
const HTTP_1_1: &[u8] = b"http/1.1";

/// How long a stop waits for each wake of the accepting thread to be heard.
const WAKE: Duration = Duration::from_secs(1);

/// What [`SecureListener::accept`] hands over.
#[derive(Debug)]
pub enum Accepted {
    /// A connection whose handshake finished.
    Session(SecureSession),
    /// A client whose certificate the anchors refused, in words: a host
    /// tells its audit.
    Refused(String),
    /// A client that did not finish its handshake for any other reason —
    /// it stopped, spoke no TLS or ran out of time — in words.
    Failed(String),
    /// The listener was stopped.
    Stopped,
}

/// What the accepting thread and the handshakes share with the accepts.
#[derive(Default)]
struct Waiting {
    finished: Mutex<VecDeque<Result<SecureSession, Unanswered>>>,
    ready: Condvar,
    stopping: AtomicBool,
}

impl Waiting {
    fn finished(&self) -> MutexGuard<'_, VecDeque<Result<SecureSession, Unanswered>>> {
        self.finished.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn hand(&self, handshake: Result<SecureSession, Unanswered>) {
        self.finished().push_back(handshake);
        self.ready.notify_one();
    }
}

/// A web host's HTTPS listener.
pub struct SecureListener {
    local: SocketAddr,
    waiting: Arc<Waiting>,
    accepting: Mutex<Option<JoinHandle<()>>>,
}

impl core::fmt::Debug for SecureListener {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SecureListener")
            .field("local", &self.local)
            .finish_non_exhaustive()
    }
}

/// How a listener's connections are protected: a parameter, never a name
/// (the owner, 2026-10-21: *technology and security should not be in
/// functions, parameters is ok*). TLS, `xmip-core-library-tls`, is the one
/// built.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Protection {
    /// TLS 1.3 and 1.2, hybrid key exchange first (ADR-0033).
    Tls,
}

impl Protection {
    /// `XMIP_PROTECTION_TLS`, as section 21 passes it.
    pub const TLS: i32 = 1;

    /// The protection `value` names, if it is one built.
    #[must_use]
    pub const fn of(value: i32) -> Option<Self> {
        match value {
            Self::TLS => Some(Self::Tls),
            _ => None,
        }
    }
}

impl SecureListener {
    /// Listen on `address`, `host:port`, protected by `protection`:
    /// presenting `certificate` (a PEM chain, leaf first) with `key` (its PEM
    /// private key) and verifying a client's certificate against `anchors`
    /// (PEM).
    ///
    /// # Errors
    ///
    /// Where the identity does not read or pair, the anchors hold no
    /// certificate, or the address cannot be bound; in words.
    pub fn listen(
        protection: Protection,
        address: &str,
        certificate: &str,
        key: &str,
        anchors: &str,
    ) -> Result<Self, String> {
        let Protection::Tls = protection;
        let identity =
            tls::Identity::from_pem(certificate.as_bytes(), key.as_bytes(), anchors.as_bytes())
                .map_err(|failure| failure.message)?;
        let asking = identity
            .server_asking()
            .map_err(|failure| failure.message)?;
        let config = Arc::new(tls::alpn::selecting(asking, &[HTTP_1_1]));
        let bound = TcpListener::bind(address)
            .map_err(|failure| format!("binding {address}: {failure}"))?;
        let local = bound
            .local_addr()
            .map_err(|failure| format!("where {address} is bound: {failure}"))?;
        let waiting = Arc::new(Waiting::default());
        let shared = Arc::clone(&waiting);
        let accepting = std::thread::Builder::new()
            .name("xmip-secure-accept".to_string())
            .spawn(move || accept_all(&bound, &config, &shared))
            .map_err(|failure| format!("starting the listener's thread: {failure}"))?;
        Ok(Self {
            local,
            waiting,
            accepting: Mutex::new(Some(accepting)),
        })
    }

    /// Where it listens, the port a bind to port 0 was given included.
    #[must_use]
    pub const fn address(&self) -> SocketAddr {
        self.local
    }

    /// The next connection whose handshake has finished, or why one did
    /// not, waiting until there is one or the listener is stopped.
    #[must_use]
    pub fn accept(&self) -> Accepted {
        let mut finished = self.waiting.finished();
        loop {
            if self.waiting.stopping.load(Ordering::SeqCst) {
                return Accepted::Stopped;
            }
            if let Some(handshake) = finished.pop_front() {
                return match handshake {
                    Ok(session) => Accepted::Session(session),
                    Err(Unanswered::Refused(said)) => Accepted::Refused(said.message),
                    Err(Unanswered::Failed(said)) => Accepted::Failed(said.message),
                };
            }
            finished = self
                .waiting
                .ready
                .wait(finished)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// Stop: nothing accepted after, every accept waiting woken and told
    /// [`Accepted::Stopped`], the accepting thread joined. A connection
    /// already handed over is its holder's to close.
    pub fn stop(&self) {
        self.waiting.stopping.store(true, Ordering::SeqCst);
        {
            let _finished = self.waiting.finished();
            self.waiting.ready.notify_all();
        }
        let accepting = self
            .accepting
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(accepting) = accepting {
            let local = self.local;
            let _ = net::accepting::woken(accepting, WAKE, || net::accepting::knock(local, WAKE));
        }
    }
}

impl Drop for SecureListener {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Accept until stopped, each handshake on a thread of its own.
fn accept_all(bound: &TcpListener, config: &Arc<tls::ServerConfig>, waiting: &Arc<Waiting>) {
    loop {
        // bounded: a listener accepts as long as its host serves; a stop knocks
        let accepted = bound.accept();
        if waiting.stopping.load(Ordering::SeqCst) {
            return;
        }
        let Ok((tcp, _)) = accepted else {
            // Out of handles, or a connection reset before it was taken:
            // asked again after a moment, never in a loop holding a
            // processor.
            std::thread::sleep(Duration::from_millis(1));
            continue;
        };
        let config = Arc::clone(config);
        let shared = Arc::clone(waiting);
        let spawned = std::thread::Builder::new()
            .name("xmip-secure-handshake".to_string())
            .spawn(move || shared.hand(SecureSession::handshaken(tcp, config)));
        if let Err(failure) = spawned {
            waiting.hand(Err(Unanswered::Failed(tls::TlsError::new(format!(
                "starting a handshake's thread: {failure}"
            )))));
        }
    }
}

/// One connection a web host's client made, its handshake finished.
pub struct SecureSession {
    reading: Mutex<ServedReading>,
    writing: Mutex<ServedWriting>,
    socket: TcpStream,
    presented: Option<Vec<u8>>,
    local: SocketAddr,
    remote: SocketAddr,
}

impl core::fmt::Debug for SecureSession {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SecureSession")
            .field("local", &self.local)
            .field("remote", &self.remote)
            .finish_non_exhaustive()
    }
}

impl SecureSession {
    /// The handshake on `tcp`, bounded by [`HANDSHAKE_WITHIN`], and the
    /// session it finished.
    fn handshaken(tcp: TcpStream, config: Arc<tls::ServerConfig>) -> Result<Self, Unanswered> {
        let failed = |what: &str, failure: std::io::Error| {
            Unanswered::Failed(tls::TlsError::new(format!("{what}: {failure}")))
        };
        let local = tcp
            .local_addr()
            .map_err(|f| failed("the local address", f))?;
        let remote = tcp
            .peer_addr()
            .map_err(|f| failed("the client's address", f))?;
        let bounded = Some(HANDSHAKE_WITHIN);
        tcp.set_read_timeout(bounded)
            .and_then(|()| tcp.set_write_timeout(bounded))
            .and_then(|()| tcp.set_nodelay(true))
            .map_err(|f| failed("bounding the handshake", f))?;
        let guarded = tls::peer::handshaken(tcp, config)?;
        let presented = tls::peer::presented(&guarded.conn);
        guarded
            .sock
            .set_read_timeout(None)
            .and_then(|()| guarded.sock.set_write_timeout(None))
            .map_err(|f| failed("unbounding the session", f))?;
        let socket = guarded
            .sock
            .try_clone()
            .map_err(|f| failed("holding the socket", f))?;
        let split = tls::duplex::split(guarded).map_err(Unanswered::Failed)?;
        Ok(Self {
            reading: Mutex::new(split.reading),
            writing: Mutex::new(split.writing),
            socket,
            presented,
            local,
            remote,
        })
    }

    /// The leaf the client presented, DER; `None` where it presented none.
    #[must_use]
    pub fn presented(&self) -> Option<&[u8]> {
        self.presented.as_deref()
    }

    /// Where the connection was accepted, and where the client is.
    #[must_use]
    pub const fn ends(&self) -> (SocketAddr, SocketAddr) {
        (self.local, self.remote)
    }

    /// What the client sent next, into `buffer`, waiting for it; 0 where
    /// the connection has ended — closed, cleanly or not, or reset.
    ///
    /// # Errors
    ///
    /// Where the record could not be read.
    pub fn read(&self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let read = self
            .reading
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .read(buffer);
        match read {
            Err(ended) if ended_by(&ended) => Ok(0),
            read => read,
        }
    }

    /// `bytes` written whole and sent.
    ///
    /// # Errors
    ///
    /// Where the connection has ended or the socket refused them.
    pub fn write(&self, bytes: &[u8]) -> std::io::Result<()> {
        let mut writing = self.writing.lock().unwrap_or_else(PoisonError::into_inner);
        writing.write_all(bytes)?;
        writing.flush()
    }

    /// Close: the client told the session is closing where no write holds
    /// the connection, and the socket shut both ways, so a read waiting on
    /// another thread wakes to its end — at once, a write blocked on a
    /// client that reads nothing included.
    pub fn close(&self) {
        if let Ok(mut writing) = self.writing.try_lock() {
            writing.close();
        }
        let _ = self.socket.shutdown(Shutdown::Both);
    }
}

/// Whether `failure` is a connection ending rather than a record that
/// could not be read: a client that closes without saying so first, as a
/// browser does, or one that resets.
fn ended_by(failure: &std::io::Error) -> bool {
    matches!(
        failure.kind(),
        ErrorKind::UnexpectedEof
            | ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::NotConnected
    )
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;
    use crate::fixture::Authority;

    fn listening(authority: &Authority) -> SecureListener {
        let (certificate, key, anchors) = authority.pem("xmip-web-host");
        SecureListener::listen(Protection::Tls, "127.0.0.1:0", &certificate, &key, &anchors)
            .expect("listening")
    }

    /// A browser at `listener`: presenting `identity`'s certificate, or none
    /// where it is `None`, trusting `authority`; it says `word` and reads
    /// the answer, a word as long.
    fn browse(
        listener: &SecureListener,
        authority: &Authority,
        identity: Option<&tls::Identity>,
        word: &'static [u8],
    ) -> std::thread::JoinHandle<std::io::Result<Vec<u8>>> {
        let address = listener.address();
        let config = match identity {
            Some(identity) => identity.client().expect("a client"),
            None => tls::trusting(authority.pem("anchor").2.as_bytes()).expect("trusting"),
        };
        let config = Arc::new(tls::alpn::offering(config, &[b"h2", HTTP_1_1]));
        std::thread::spawn(move || {
            let tcp = TcpStream::connect(address)?;
            let mut stream = tls::client_with("localhost", tcp, config)
                .map_err(|failure| std::io::Error::other(failure.message))?;
            let agreed = tls::alpn::agreed(&mut stream)
                .map_err(|failure| std::io::Error::other(failure.message))?;
            assert_eq!(agreed.as_deref(), Some(HTTP_1_1));
            stream.write_all(word)?;
            stream.flush()?;
            let mut answer = vec![0u8; word.len()];
            stream.read_exact(&mut answer)?;
            Ok(answer)
        })
    }

    fn session(listener: &SecureListener) -> SecureSession {
        match listener.accept() {
            Accepted::Session(session) => session,
            other => panic!("a session, not {other:?}"),
        }
    }

    /// The word a session reads, answered in capitals.
    fn answer(session: &SecureSession, length: usize) {
        let mut heard = vec![0u8; length];
        let mut at = 0;
        while at < length {
            let read = session.read(&mut heard[at..]).expect("read");
            assert_ne!(read, 0, "ended early");
            at += read;
        }
        session
            .write(&heard.to_ascii_uppercase())
            .expect("answered");
    }

    #[test]
    fn a_client_of_the_anchors_is_named_one_without_is_no_one_and_a_stranger_is_told() {
        let authority = Authority::new();
        let listener = listening(&authority);

        let operator = authority.identity("alice@example.org");
        let browser = browse(&listener, &authority, Some(&operator), b"get");
        let named = session(&listener);
        let leaf = named.presented().expect("the operator's certificate");
        assert!(
            tls::Name::subject_of(leaf)
                .expect("a subject")
                .to_string()
                .contains("alice")
        );
        answer(&named, 3);
        assert_eq!(
            browser.join().expect("the browser").expect("answered"),
            b"GET"
        );
        assert_eq!(named.ends().0, listener.address());

        let watcher = browse(&listener, &authority, None, b"look");
        let nobody = session(&listener);
        assert_eq!(nobody.presented(), None);
        answer(&nobody, 4);
        assert_eq!(
            watcher.join().expect("the watcher").expect("answered"),
            b"LOOK"
        );

        let theirs = Authority::new();
        let (certificate, key, _) = theirs.pem("mallory");
        let stranger = tls::Identity::from_pem(
            certificate.as_bytes(),
            key.as_bytes(),
            authority.pem("anchor").2.as_bytes(),
        )
        .expect("an identity");
        let refused = browse(&listener, &authority, Some(&stranger), b"act");
        assert!(matches!(listener.accept(), Accepted::Refused(said) if said.contains("handshake")));
        assert!(refused.join().expect("the stranger").is_err());

        let silent = TcpStream::connect(listener.address()).expect("connected");
        drop(silent);
        assert!(matches!(listener.accept(), Accepted::Failed(_)));
        let again = browse(&listener, &authority, Some(&operator), b"ok");
        answer(&session(&listener), 2);
        assert_eq!(again.join().expect("the browser").expect("answered"), b"OK");
    }

    #[test]
    fn a_close_wakes_a_read_on_another_thread_and_a_stop_wakes_an_accept() {
        let authority = Authority::new();
        let listener = Arc::new(listening(&authority));
        let operator = authority.identity("alice@example.org");
        let browser = browse(&listener, &authority, Some(&operator), b"wait");
        let held = Arc::new(session(&listener));
        let reader = Arc::clone(&held);
        let reading = std::thread::spawn(move || {
            let mut word = [0u8; 4];
            let _ = reader.read(&mut word);
            reader.read(&mut word)
        });
        std::thread::sleep(Duration::from_millis(20));
        let closed = Instant::now();
        held.close();
        assert_eq!(reading.join().expect("the reader").expect("ended"), 0);
        assert!(
            closed.elapsed() < Duration::from_secs(1),
            "{:?}",
            closed.elapsed()
        );
        assert!(browser.join().expect("the browser").is_err());

        let accepting = Arc::clone(&listener);
        let waiting = std::thread::spawn(move || accepting.accept());
        std::thread::sleep(Duration::from_millis(20));
        let stopped = Instant::now();
        listener.stop();
        assert!(matches!(
            waiting.join().expect("the accept"),
            Accepted::Stopped
        ));
        assert!(
            stopped.elapsed() < Duration::from_secs(1),
            "{:?}",
            stopped.elapsed()
        );
    }

    #[test]
    fn an_identity_that_does_not_read_or_anchors_that_hold_nothing_are_refused_in_words() {
        let authority = Authority::new();
        let (certificate, key, _) = authority.pem("xmip-web-host");
        let refused =
            SecureListener::listen(Protection::Tls, "127.0.0.1:0", &certificate, &key, "")
                .expect_err("no anchors");
        assert!(!refused.is_empty());
        let refused =
            SecureListener::listen(Protection::Tls, "127.0.0.1:0", "", &key, &certificate)
                .expect_err("no chain");
        assert!(refused.contains("certificate"), "{refused}");
    }
}
