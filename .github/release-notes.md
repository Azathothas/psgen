Static Linux binaries for `psgen`.

Every release asset is a statically linked musl build.
`SHA256SUMS` lists each `psgen-<target>` binary and each `psgen-<version>-<target>.tar.gz` archive.
`SHA256SUMS` does not include itself, because a file cannot hold its own checksum.
Verify the downloaded assets with `sha256sum -c SHA256SUMS --ignore-missing`.
A plain `sha256sum -c SHA256SUMS` command reports every missing asset as an error and exits non-zero.

The release job selects the changelog entries below from `CHANGELOG.md` in this order:

1. The section for the exact tag (`## 0.0.1-beta.1` for `v0.0.1-beta.1`),
   then `## Unreleased` when the tag is a prerelease.
2. The section for the base version (`## 0.0.1`).
3. `## Unreleased` again.

If none of these sections exists in `CHANGELOG.md`, the release job stops before creating the GitHub release.
