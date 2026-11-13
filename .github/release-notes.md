Static Linux binaries for psgen.

All assets are statically linked musl builds. Each `psgen-<target>` binary and
each `psgen-<version>-<target>.tar.gz` is listed in `SHA256SUMS`; the list does
not include itself, because a file cannot hold its own checksum. Verify the
assets you downloaded with `sha256sum -c SHA256SUMS --ignore-missing`; a plain
`sha256sum -c` reports every asset you did not download as missing and exits
non-zero.

The entries for this release are below, taken from `CHANGELOG.md`, in this
order: the section for the tag itself (`## 0.0.1-beta.1` for
`v0.0.1-beta.1`), then `## Unreleased` when the tag is a prerelease, then the
section for the base version (`## 0.0.1`), then `## Unreleased` again. The
release job stops before it creates a release when none of those sections
exists.
