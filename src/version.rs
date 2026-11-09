//! One source of truth for the version string.
//!
//! `0.0.1` used to be written out by hand in eight places, one of which was a
//! parser: `stop` only recognised a pidfile header whose version was exactly
//! the current one, so bumping the version silently disarmed the boot-id
//! check. Everything now reads `CARGO_PKG_VERSION`, and the pidfile header is
//! parsed without interpreting the version at all.

use crate::str;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// `psgen <version>\n`, the output of `--version`.
pub const LINE: &[u8] = concat!("psgen ", env!("CARGO_PKG_VERSION"), "\n").as_bytes();

/// `psgen <version>`, without the newline.
pub const BARE: &[u8] = concat!("psgen ", env!("CARGO_PKG_VERSION")).as_bytes();

/// The first bytes of every pidfile psgen writes.
pub const PIDFILE_PREFIX: &[u8] = b"# psgen ";

/// The marker that separates the version from the boot id in the header.
pub const PIDFILE_BOOT: &[u8] = b" boot ";

/// The boot id from a `# psgen <version> boot <boot-id>` line.
///
/// The version is not interpreted, so a pidfile written by a different release
/// is still recognised after an upgrade. `None` means the line is not a psgen
/// header at all.
pub fn pidfile_boot_id(line: &[u8]) -> Option<Vec<u8>> {
    let rest = line.strip_prefix(PIDFILE_PREFIX)?;
    let at = str::find(rest, PIDFILE_BOOT)?;
    Some(str::trim(&rest[at + PIDFILE_BOOT.len()..]).to_vec())
}
