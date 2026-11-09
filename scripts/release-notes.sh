#!/bin/sh
# Decide and build the notes for a release, from the tag.
#
# The workflow calls this instead of keeping the logic inline in YAML, so the
# rules are ordinary shell that runs and is tested outside GitHub. Everything
# here is exercised by `tests/workflow.sh`.
#
#   release-notes.sh section <tag>        print the CHANGELOG section for a tag
#   release-notes.sh prerelease <tag>     "yes" when the tag is a prerelease
#   release-notes.sh publish <tag>        "yes" when the crate should be published
#   release-notes.sh notes <tag> <out>    write the full release notes
#
# A tag is `v<version>`; a version with a `-` in it is a prerelease.
set -eu

tag=${2:-}
if [ -z "$tag" ]; then
    echo "usage: $0 section|prerelease|publish|notes <tag> [out]" >&2
    exit 2
fi

# `v0.0.1-beta.1` -> `0.0.1-beta.1`, base `0.0.1`, prerelease yes.
full=${tag#v}
base=${full%%-*}
case "$full" in
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

case "$1" in
    prerelease)
        printf '%s\n' "$pre"
        ;;
    publish)
        # The crate is published for a final tag only. A workflow_dispatch run
        # is judged by the tag it was given, never by the branch it ran on.
        printf '%s\n' "$([ "$pre" = no ] && echo yes || echo no)"
        ;;
    section)
        section "## $full"
        if ! nonempty "$(section "## $full")"; then
            if [ "$pre" = yes ]; then
                section "## Unreleased"
            fi
        fi
        ;;
    notes)
        out=${3:-}
        if [ -z "$out" ]; then
            echo "notes needs an output path" >&2
            exit 2
        fi
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
        {
            cat "${NOTES_HEADER:-.github/release-notes.md}"
            echo
            printf '%s\n' "$body"
        } > "$out"
        ;;
    *)
        echo "release-notes.sh: unknown command $1" >&2
        exit 2
        ;;
esac
