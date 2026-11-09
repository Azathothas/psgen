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
        assert_eq!(pidfile_boot_id(b"# psgen 0.0.1"), None);
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
