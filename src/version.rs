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

/// The marker that introduces the run nonce after the boot id. The nonce is a
/// run identifier, not a secret: it travels in every stub's environment so a
/// later `stop` can tell this run's rows from an unrelated process that happens
/// to share an executable name.
pub const PIDFILE_NONCE: &[u8] = b" nonce ";

/// The boot id from a `# psgen <version> boot <boot-id>` line.
///
/// The version is not interpreted, so a pidfile written by a different release
/// is still recognised after an upgrade. A psgen header without a `boot`
/// marker yields an empty boot id rather than `None`, so `stop` can refuse it
/// instead of silently skipping the boot check. `None` means the line is not a
/// psgen header at all.
pub fn pidfile_boot_id(line: &[u8]) -> Option<Vec<u8>> {
    let rest = line.strip_prefix(PIDFILE_PREFIX)?;
    match str::find(rest, PIDFILE_BOOT) {
        Some(at) => {
            let tail = &rest[at + PIDFILE_BOOT.len()..];
            // The nonce follows the boot id, so the boot id ends where it
            // starts rather than at the end of the line.
            let end = str::find(tail, PIDFILE_NONCE).unwrap_or(tail.len());
            Some(str::trim(&tail[..end]).to_vec())
        }
        None => Some(Vec::new()),
    }
}

/// The run nonce from a `# psgen <version> boot <boot-id> nonce <hex>` line,
/// or empty when the header carries none.
///
/// A header from an older release has no nonce. Nothing in a one-field line can
/// identify a process without it, so `stop` refuses that line rather than
/// falling back to an executable test that every psgen process would pass.
pub fn pidfile_nonce(line: &[u8]) -> Vec<u8> {
    let rest = match line.strip_prefix(PIDFILE_PREFIX) {
        Some(r) => r,
        None => return Vec::new(),
    };
    match str::find(rest, PIDFILE_NONCE) {
        Some(at) => {
            let tail = &rest[at + PIDFILE_NONCE.len()..];
            // The nonce is the last field, so a stray space before the line
            // ending must not become part of it.
            str::trim(tail).to_vec()
        }
        None => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pidfile_header_boot_id_ignores_the_version() {
        // The check that disarms the boot-id guard must not depend on which
        // release wrote the file.
        assert_eq!(
            pidfile_boot_id(b"# psgen 0.0.1 boot abc-123"),
            Some(b"abc-123".to_vec())
        );
        assert_eq!(
            pidfile_boot_id(b"# psgen 9.9.9 boot abc-123"),
            Some(b"abc-123".to_vec())
        );
        assert_eq!(pidfile_boot_id(b"# temp /tmp/x"), None);
        assert_eq!(pidfile_boot_id(b"1234\t5\tcomm"), None);
        // A header without a boot marker is still a psgen header. It yields an
        // empty boot id so `stop` refuses it instead of skipping the check.
        assert_eq!(pidfile_boot_id(b"# psgen 0.0.1"), Some(Vec::new()));
        assert_eq!(pidfile_boot_id(b"# psgen 0.0.1 boot "), Some(Vec::new()));
    }

    /// The nonce follows the boot id on the same line, so the boot id must end
    /// where the nonce marker starts. Reading to the end of the line made every
    /// header this release writes look like it came from another boot.
    #[test]
    fn the_boot_id_stops_before_the_nonce() {
        assert_eq!(
            pidfile_boot_id(b"# psgen 0.0.1 boot abc-123 nonce deadbeef"),
            Some(b"abc-123".to_vec())
        );
        assert_eq!(
            pidfile_boot_id(b"# psgen 0.0.1 boot abc-123 nonce "),
            Some(b"abc-123".to_vec())
        );
    }

    #[test]
    fn a_nonce_is_read_only_from_a_header_that_has_one() {
        assert_eq!(
            pidfile_nonce(b"# psgen 0.0.1 boot abc-123 nonce deadbeef"),
            b"deadbeef".to_vec()
        );
        // A header from an older release carries none.
        assert_eq!(
            pidfile_nonce(b"# psgen 0.0.1 boot abc-123"),
            Vec::<u8>::new()
        );
        // A non-header line never supplies one.
        assert_eq!(
            pidfile_nonce(b"# temp /tmp/nonce deadbeef"),
            Vec::<u8>::new()
        );
        assert_eq!(pidfile_nonce(b"1234\t5\tcomm"), Vec::<u8>::new());
    }

    #[test]
    fn version_is_the_one_in_cargo_toml() {
        let cargo = include_str!("../Cargo.toml");
        let want = cargo
            .lines()
            .find_map(|l| l.strip_prefix("version = \""))
            .and_then(|l| l.strip_suffix('"'))
            .expect("a version line in Cargo.toml");
        assert_eq!(VERSION, want);
    }
}
