#!/bin/sh
# Decide and build the notes for a release, from the tag.
#
# The workflow calls this instead of keeping the logic inline in YAML, so the
# rules are ordinary shell that runs and is tested outside GitHub. Everything
# here is exercised by `tests/workflow.sh`.
#
#   release-notes.sh section <tag>      print the CHANGELOG section for a tag
#   release-notes.sh prerelease <tag>   "yes" when the tag is a prerelease
#   release-notes.sh publish <tag>      "yes" when the crate should be published
#   release-notes.sh tag-matches <tag>  fail unless <tag> is v<Cargo version>
#   release-notes.sh notes <tag> <out>  write the full release notes
#
# A tag is `v<base>[-<prerelease>][+<build>]` and only `<base>` is the version
# the crate carries: `v0.0.2-beta.1` and `v0.0.2+build.1` both name 0.0.2.
#
# The exit status is part of the interface: 0 when the question was answered,
# 1 when the tag is not one this tree may release, 2 on a usage error. A caller
# that reads `publish`'s output as a boolean without checking the status cannot
# tell "no" from "the script refused the tag", so every caller checks both.
set -eu

usage() {
    echo "usage: $0 section|prerelease|publish|tag-matches|notes <tag> [out]" >&2
    exit 2
}

cmd=${1:-}
tag=${2:-}
[ -n "$cmd" ] && [ -n "$tag" ] || usage

# A release tag is `v<semver>`. Anything else is not a release: `--verify-tag`
# would resolve `0.0.1` to whichever ref happens to carry that name, and the
# notes and prerelease rules are written for the `v`-prefixed form.
case "$tag" in
    v*) ;;
    *)
        echo "release-notes.sh: $tag is not a v<version> tag" >&2
        exit 1
        ;;
esac
if ! printf '%s\n' "${tag#v}" | grep -Eq \
        '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$'; then
    echo "release-notes.sh: $tag is not a v<version> tag" >&2
    exit 1
fi

# `v0.0.1-beta.1` -> tag suffix `0.0.1-beta.1`, base `0.0.1`, prerelease yes.
#
# Build metadata is not part of the version a crate carries: semver ignores it
# for precedence and Cargo rejects a `+` in `[package] version`, so
# `v0.0.1+build.1` releases 0.0.1. It is stripped before the base is taken so a
# hyphen inside the metadata (`v0.0.1+build-1`) is not read as a prerelease.
full=${tag#v}
build_free=${full%%+*}
base=${build_free%%-*}
case "$build_free" in
    *-*) pre=yes ;;
    *) pre=no ;;
esac

section() {
    # The body of `## <heading>`: every line until the next `## ` or EOF.
    awk -v want="$1" '
        $0 == want { on = 1; next }
        /^## / && on { exit }
        on { print }
    ' "${CHANGELOG:-CHANGELOG.md}"
}

nonempty() {
    printf '%s' "$1" | grep -q '[^[:space:]]'
}

# The section `notes` writes, in order: the tag's own heading, `## Unreleased`
# for a prerelease, the base version's heading, then `## Unreleased` for a final
# tag. `section` answers the same question, so the two cannot disagree about
# which body a release carries.
pick_section() {
    body=$(section "## $full")
    if ! nonempty "$body"; then
        if [ "$pre" = yes ]; then
            body=$(section "## Unreleased")
        fi
    fi
    if ! nonempty "$body"; then
        body=$(section "## $base")
    fi
    if ! nonempty "$body"; then
        body=$(section "## Unreleased")
    fi
    printf '%s\n' "$body"
}

case "$cmd" in
    prerelease)
        printf '%s\n' "$pre"
        ;;
    publish)
        # The crate is published for a final tag only. A workflow_dispatch run
        # is judged by the tag it was given, never by the branch it ran on.
        printf '%s\n' "$([ "$pre" = no ] && echo yes || echo no)"
        ;;
    tag-matches)
        # The tag names the version the release publishes, so the tree it was
        # built from must carry the same version. Only the *base* is compared:
        # a prerelease tag (`v0.0.2-beta.1`) and a tag with build metadata
        # (`v0.0.2+build.1`) both publish 0.0.2, which is what the manifest
        # says for the tag that is cut from it. Publishing 0.0.1 under the tag
        # v0.0.2 is unrecoverable: crates.io never reuses a version.
        manifest=${CARGO_MANIFEST:-Cargo.toml}
        version=$(sed -n 's/^version = "\(.*\)"$/\1/p' "$manifest" 2>/dev/null |
            head -1)
        if [ -z "$version" ]; then
            echo "release-notes.sh: cannot read a version from $manifest" >&2
            exit 1
        fi
        if [ "$version" != "$base" ]; then
            echo "release-notes.sh: $tag names version $base but" \
                "$manifest says $version" >&2
            exit 1
        fi
        printf '%s\n' "$base"
        ;;
    section)
        body=$(pick_section)
        if ! nonempty "$body"; then
            echo "release-notes.sh: no CHANGELOG section for $tag" >&2
            exit 1
        fi
        printf '%s\n' "$body"
        ;;
    notes)
        out=${3:-}
        if [ -z "$out" ]; then
            echo "notes needs an output path" >&2
            exit 2
        fi
        body=$(pick_section)
        if ! nonempty "$body"; then
            echo "release-notes.sh: no CHANGELOG section for $tag" >&2
            exit 1
        fi
        {
            cat "${NOTES_HEADER:-.github/release-notes.md}"
            echo
            printf '%s\n' "$body"
        } > "$out"
        ;;
    *)
        echo "release-notes.sh: unknown command $cmd" >&2
        exit 2
        ;;
esac
