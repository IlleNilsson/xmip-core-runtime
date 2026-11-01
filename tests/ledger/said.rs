//! A line said by a test or a child at once, for whoever reads the test's
//! output: the Ledger tests' and the module's timing program's.

use std::io::Write;

/// A line said and on its way at once.
pub fn say(line: &str) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}
