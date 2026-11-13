#!/bin/sh
# Check the pieces of the release pipeline that can be run outside GitHub.
#
# What this exercises:
#
#   - the tag -> notes / prerelease / publish / tag-matches decisions, through
#     the same script the workflow calls. `tag-matches` is what the release job
#     refuses a tag on, so it is tested against the base version a prerelease
#     tag names, a tag with build metadata, a mismatched version and the shapes
#     that are not `v<version>` at all;
#   - the workflows themselves, by parsing the YAML and *executing* the step
#     bodies that decide something, with `cargo`, `gh`, `readelf` and `file`
#     faked (tests/helpers/check_workflows.py). The unit step is run against
#     five sabotaged units, and the required assertion list lives in the
#     checker, so deleting the same grep from both workflows still fails;
#   - every `run:` body parses as shell, inline and block alike;
#   - `sh tests/smoke.sh` runs every gate CI runs, and the skip rule is the
#     same rule in both;
#   - each gate can fail: a sabotaged *copy* of the workflow must be rejected,
#     and by the message it was made to produce. A copy that rejects for an
#     unrelated reason is a failure of the meta-test, not a pass. Every
#     sabotage is applied to a fresh copy under `$TMP`, never to the checkout,
#     so a run of this file cannot leave a workflow edited.
#
# What it cannot exercise: GitHub's own evaluation of `${{ }}` expressions, the
# runner image, and the network calls themselves.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
. "$ROOT/tests/helpers/gate.sh"
cd "$ROOT"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

notes=scripts/release-notes.sh
[ -x "$notes" ] || fail "$notes is not executable"
checker=tests/helpers/check_workflows.py
[ -f "$checker" ] || fail "$checker is missing"

echo "== release decisions"
# A final tag publishes; a prerelease does not; the base version is `0.0.1`.
for row in \
    "v0.0.1:no:yes" \
    "v0.0.1-beta.1:yes:no" \
    "v0.0.2-beta.1:yes:no" \
    "v0.0.2:no:yes"
do
    tag=${row%%:*}
    rest=${row#*:}
    want_pre=${rest%%:*}
    want_pub=${rest#*:}
    got_pre=$(sh "$notes" prerelease "$tag")
    got_pub=$(sh "$notes" publish "$tag")
    [ "$got_pre" = "$want_pre" ] || fail "prerelease($tag) = $got_pre, want $want_pre"
    [ "$got_pub" = "$want_pub" ] || fail "publish($tag) = $got_pub, want $want_pub"
    echo "   $tag prerelease=$got_pre publish=$got_pub"
done

echo "== tag-matches: the tag names the version the crate carries"
# `tag-matches` is the one decision the release job gates on before it creates
# anything, and it went untested: it compared the whole tag suffix to the
# manifest, so every `-beta` tag was refused against the base version the crate
# actually carries and no prerelease could publish. Only the base is compared,
# because a prerelease tag and a tag with build metadata both name the base
# version the crate holds.
tag_manifest=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -1)
[ -n "$tag_manifest" ] || fail "cannot read a version from Cargo.toml"
for row in \
    "v$tag_manifest:$tag_manifest" \
    "v$tag_manifest-beta.1:$tag_manifest" \
    "v$tag_manifest-rc.2+build.7:$tag_manifest" \
    "v$tag_manifest+build.1:$tag_manifest"
do
    tag=${row%%:*}
    want=${row#*:}
    got=$(sh "$notes" tag-matches "$tag") ||
        fail "tag-matches $tag was refused; the manifest says $tag_manifest"
    [ "$got" = "$want" ] || fail "tag-matches $tag printed $got, want $want"
    echo "   $tag matches $want"
done

# A tag whose base names another version must be refused, and the message has
# to name both versions: the operator needs to know which side is wrong.
base=${tag_manifest%.*}
next="$base.$(( ${tag_manifest##*.} + 1 ))"
if out=$(sh "$notes" tag-matches "v$next" 2>&1); then
    fail "tag-matches v$next passed against a $tag_manifest manifest"
fi
printf '%s\n' "$out" | grep -q "v$next" ||
    fail "the mismatch error does not name the tag: $out"
printf '%s\n' "$out" | grep -q "$tag_manifest" ||
    fail "the mismatch error does not name the manifest version: $out"
echo "   v$next refused against $tag_manifest: $out"

# The clause the release job depends on, with a manifest that has moved on: a
# prerelease cut from the new version passes and the one after it does not.
printf '[package]\nname = "psgen"\nversion = "%s"\n' "$next" > "$TMP/Cargo.toml"
if ! out=$(CARGO_MANIFEST=$TMP/Cargo.toml sh "$notes" tag-matches "v$next-beta.1"); then
    fail "tag-matches v$next-beta.1 was refused against a $next manifest"
fi
[ "$out" = "$next" ] || fail "tag-matches v$next-beta.1 printed $out, want $next"
later="$base.$(( ${tag_manifest##*.} + 2 ))"
if out=$(CARGO_MANIFEST=$TMP/Cargo.toml sh "$notes" tag-matches "v$later-beta.1" 2>&1); then
    fail "tag-matches v$later-beta.1 passed against a $next manifest"
fi
printf '%s\n' "$out" | grep -q "v$later-beta.1" ||
    fail "the mismatch error does not name the tag: $out"
printf '%s\n' "$out" | grep -q "$next" ||
    fail "the mismatch error does not name the manifest version: $out"
echo "   v$next-beta.1 matches $next; v$later-beta.1 refused against $next"

# Anything that is not `v<semver>` is not a release. `--verify-tag` would
# resolve a bare `0.0.1` to whichever ref carries that name, and a branch name
# is not a version at all.
for tag in "$tag_manifest" main v1.0 v1.0.0.0; do
    if out=$(sh "$notes" tag-matches "$tag" 2>&1); then
        fail "tag-matches $tag passed, but $tag is not a v<version> tag"
    fi
    printf '%s\n' "$out" | grep -q 'not a v<version> tag' ||
        fail "tag-matches $tag failed for another reason: $out"
    echo "   $tag refused: $out"
done

echo "== changelog section selection"
# The fixtures use a synthetic CHANGELOG so that cutting a release — which
# removes `## Unreleased` and adds a version section — cannot change what this
# checks. The rules are about tag shapes, not about the tree's own history.
cat > "$TMP/CHANGELOG.md" <<'SYNTH'
# Changelog

## Unreleased

unreleased-body

## 2.0.0

final-body

## 1.0.0

older-body
SYNTH
CHANGELOG=$TMP/CHANGELOG.md sh "$notes" notes v2.0.0 "$TMP/final.md"
grep -q '^## 2.0.0' "$TMP/final.md" && fail "the notes for v2.0.0 still contain a heading"
grep -q 'final-body' "$TMP/final.md" || fail "v2.0.0 did not select its own section"
grep -q 'older-body\|unreleased-body' "$TMP/final.md" &&
    fail "v2.0.0 selected another section"
# A prerelease with no section of its own falls back to Unreleased, never to the
# final section of the same base version.
CHANGELOG=$TMP/CHANGELOG.md sh "$notes" notes v2.0.0-beta.1 "$TMP/pre.md"
grep -q 'unreleased-body' "$TMP/pre.md" ||
    fail "a prerelease did not fall back to Unreleased"
grep -q 'final-body' "$TMP/pre.md" && fail "a prerelease selected the final section"
# The boilerplate is always first.
head -1 "$TMP/final.md" | grep -q 'psgen' || fail "the notes lost the boilerplate"

echo "== a tag with no changelog section fails"
# The fallback chain ends at `## Unreleased`; with none of its sections present
# it must fail instead of writing notes that describe nothing.
printf '# Changelog\n\n## 1.0.0\nold\n' > "$TMP/CHANGELOG.md"
if CHANGELOG=$TMP/CHANGELOG.md sh "$notes" section v9.9.9 \
        >"$TMP/sec.out" 2>"$TMP/sec.err"; then
    fail "section v9.9.9 succeeded with no matching section"
fi
grep -q 'no CHANGELOG section for v9.9.9' "$TMP/sec.err" ||
    fail "the missing-section error does not name the tag"
if CHANGELOG=$TMP/CHANGELOG.md sh "$notes" notes v9.9.9 "$TMP/none.md" \
        2>"$TMP/notes.err"; then
    fail "notes v9.9.9 fell back to a section that does not exist"
fi
grep -q 'no CHANGELOG section for v9.9.9' "$TMP/notes.err" ||
    fail "notes did not name the missing section"
if [ -s "$TMP/none.md" ]; then
    fail "notes wrote a file without a section"
fi

echo "== workflows: parsed structure, executed steps"
# The checker runs the release step bodies against a fake `cargo` and `gh`, and
# asks the real binary for the unit it prints. It exits non-zero on any
# structural or behavioural defect. The run is recorded rather than aborted on,
# so the sabotage meta-tests below always execute: a gate that cannot be shown
# to fail is not a gate.
real_status=0
if [ -x "$ROOT/target/release/psgen" ]; then
    python3 "$checker" --root "$ROOT" --bin "$ROOT/target/release/psgen" ||
        real_status=$?
    unit_state=ok
else
    python3 "$checker" --root "$ROOT" || real_status=$?
    unit_state=skipped
fi

echo "== each gate can fail (sabotage)"
# Every sabotage below is applied to a *copy* under $TMP, never to the
# checkout: a run of this file must not be able to leave a workflow edited.
# Only the files the checker reads are copied; each case copies the tree
# again, so a failed edit cannot leak into the next case.
stage_tree() {
    dir=$1
    rm -rf "$dir"
    mkdir -p "$dir"
    cp -R "$ROOT/.github" "$dir/.github"
    cp -R "$ROOT/scripts" "$dir/scripts"
    # The smoke-parity and sabotage checks read the test tree, so it is part
    # of the copy the checker is pointed at.
    mkdir -p "$dir/tests/helpers"
    cp "$ROOT/tests/smoke.sh" "$ROOT/tests/workflow.sh" "$dir/tests/"
    cp "$ROOT/tests/helpers/"*.sh "$dir/tests/helpers/" 2>/dev/null || true
    cp "$ROOT/Cargo.toml" "$dir/Cargo.toml"
    for f in CHANGELOG.md LICENSE README.md; do
        [ -f "$ROOT/$f" ] && cp "$ROOT/$f" "$dir/$f"
    done
    cp "$checker" "$dir/check_workflows.py"
}

# `sabotage_check <name> <only-check> <expected-message> <dir>`
#
# Runs the checker against <dir> and requires it to reject the copy by naming
# <expected-message>. A non-zero exit alone proves nothing — a copy with an
# unrelated file removed, a body that no longer parses, a check that crashed
# all produce one — so a wrong reason is a failure of this meta-test.
sabotage_check() {
    name=$1
    only=$2
    want=$3
    dir=$4
    status=0
    # The unit gate needs a binary to produce a unit; the copy has no build,
    # so the real one is named explicitly. Without it `--only unit` skips and
    # a sabotage of that gate would look like a pass.
    bin_args=""
    if [ -x "$ROOT/target/release/psgen" ]; then
        bin_args="--bin $ROOT/target/release/psgen"
    fi
    # shellcheck disable=SC2086
    python3 "$dir/check_workflows.py" --root "$dir" --only "$only" $bin_args \
        >"$TMP/sab.out" 2>&1 || status=$?
    if [ "$status" -eq 0 ]; then
        cat "$TMP/sab.out" >&2
        fail "$name: the checker passed a sabotaged workflow"
    fi
    if ! grep -qF -- "$want" "$TMP/sab.out"; then
        cat "$TMP/sab.out" >&2
        fail "$name: the checker rejected the copy for another reason; wanted
a failure naming '$want'"
    fi
    echo "   $name: rejected ($want)"
}

# `sabotage <name> <only-check> <expected-message> <sed-expr> <file>
#           [<sed-expr> <file> ...]`
#
# Builds a fresh copy, applies one edit, and requires the named check to reject
# it for the stated reason. The checkout is only ever read.
sabotage() {
    name=$1
    only=$2
    want=$3
    shift 3
    dir=$TMP/sabotage-$name
    stage_tree "$dir"
    while [ "$#" -gt 0 ]; do
        expr=$1
        file=$2
        sed -i "$expr" "$dir/$file" || fail "$name: cannot edit $file"
        shift 2
    done
    sabotage_check "$name" "$only" "$want" "$dir"
    rm -rf "$dir"
}

# A meta-test of the meta-test. `sabotage_check` is only worth something if it
# refuses a rejection that names the wrong defect, so this copy is broken in a
# way that has nothing to do with the `exclude` list and the helper must call
# the wrong reason a failure.
echo "== the sabotage helper requires the expected reason"
probe=$TMP/wrong-reason
stage_tree "$probe"
rm -f "$probe/Cargo.toml"
if ( sabotage_check "wrong-reason-probe" package \
        "Cargo.toml has no \`exclude\` for the package" "$probe" ) \
        >"$TMP/wrong.out" 2>&1; then
    cat "$TMP/wrong.out" >&2
    fail "the sabotage helper accepted a copy that rejected for another reason"
fi
grep -q 'rejected the copy for another reason' "$TMP/wrong.out" ||
    fail "the sabotage helper failed, but not for the reason it should:
$(cat "$TMP/wrong.out")"
rm -rf "$probe"
echo "   a wrong-reason rejection is a meta-test failure"

# 1. Invert the publish guard: a prerelease would publish the crate.
sabotage "publish-guard-inverted" publish-guard \
    "publish-crate ran" \
    's/ != yes ]/ = yes ]/' .github/workflows/release.yml

# 2. Blank a cross entry's qemu: nothing would execute the binary, and the
#    smoke step would still pass.
sabotage "cross-qemu-blanked" matrix \
    "loongarch64-unknown-linux-musl: qemu is ''" \
    '/target: loongarch64-unknown-linux-musl/{n;n;s/qemu: loong64/qemu: ""/}' \
    .github/workflows/release.yml

# 3. Strip `-D warnings`, which turns clippy into an advisory print.
sabotage "clippy-advisory" clippy \
    "clippy does not pass \`-D warnings\`" \
    's/ -- -D warnings//' .github/workflows/ci.yml

# 4. Remove `--verify-tag` from the release create.
sabotage "verify-tag-removed" gh-release \
    "gh release create does not pass --verify-tag" \
    's/ --verify-tag//' .github/workflows/release.yml

# 5. Make the release job's unit gate assert less than CI's. The two jobs used
#    to disagree, so a unit CI rejects could still ship.
sabotage "release-unit-gate-weaker" unit \
    "the release unit gate differs from CI's" \
    "/^          if ! grep -q '\^ConditionPathExists/d" \
    .github/workflows/release.yml

# 6. Delete the same assertion from *both* workflows. Parity alone accepts
#    this: the two files still agree, so the gate quietly stops covering the
#    directive. The pinned assertion list is what rejects it.
sabotage "unit-gate-dropped-from-both" unit \
    "no longer asserts RuntimeDirectory=psgen" \
    "/^          if ! grep -q '\^RuntimeDirectory=psgen\\$/d" \
    .github/workflows/ci.yml \
    "/^          if ! grep -q '\^RuntimeDirectory=psgen\\$/d" \
    .github/workflows/release.yml

# 7. Remove the psgen-stop assertions from *both* workflows, leaving the rest of
#    the body valid. `grep -q '^ExecStop=-'` is satisfied by the unrelated
#    `ExecStop=-/bin/rm` cleanup line, so this is the gate that cannot fail:
#    the required-assertion list rejects it, and parity cannot, because both
#    files are edited.
sabotage "unit-stop-assertions-dropped" unit \
    "no longer asserts an ExecStop line that runs the psgen stop" \
    "/^          if ! grep -q '\^ExecStop=.* stop --pidfile'/,/^          fi\$/d" \
    .github/workflows/ci.yml \
    "/^          if ! grep -q '\^ExecStop=.* stop --pidfile'/,/^          fi\$/d" \
    .github/workflows/release.yml

# 8. Remove only the *guard* half, from both workflows: the unit still has to
#    carry a psgen stop, but an unguarded one passes. This is the exact defect
#    the assertion exists for, and the one that used to ship.
sabotage "unit-stop-guard-dropped" unit \
    "no longer asserts the psgen stop is guarded" \
    "/^          if grep '\^ExecStop=.* stop --pidfile'/,/^          fi\$/d" \
    .github/workflows/ci.yml \
    "/^          if grep '\^ExecStop=.* stop --pidfile'/,/^          fi\$/d" \
    .github/workflows/release.yml

# 9. Move `publish-crate` above `publish`, so the crate is uploaded before the
#    release it is meant to accompany exists. Renaming the steps is how the
#    order is expressed in the parsed job: `checksums` (earlier) becomes
#    `publish-crate`, the old `publish-crate` becomes `publish`.
sabotage "publish-crate-before-publish" order \
    "publish-crate runs before publish" \
    's/- name: publish-crate/- name: TMPMOVE/;s/- name: checksums/- name: publish-crate/;s/- name: TMPMOVE/- name: publish/' \
    .github/workflows/release.yml

# 10. Drop the `exclude` list, so the published crate carries the test tree.
sabotage "package-exclude-dropped" package \
    "Cargo.toml has no \`exclude\` for the package" \
    '/^exclude = /d' Cargo.toml

# 11. Drop the `test -f` guard, so a missing binary takes the same branch as a
#     static one. That is the defect the old `if readelf | grep` shape had, and
#     the shape the current body must not fall back into.
sabotage "static-check-no-test-f" static \
    "the static check never uses \`test -f\`" \
    '/test -f "\$b"/d' \
    .github/workflows/release.yml

# 12. Drop `PSGEN_REQUIRE_ALL` from each workflow's suite job, so a skip on a
#     runner that lost a capability goes green. Both files are edited: the
#     release job was the one nothing covered, and a per-file case would let
#     the other file keep the gate green for the wrong reason.
sabotage "require-all-dropped" require-all \
    "PSGEN_REQUIRE_ALL is None" \
    '/^      PSGEN_REQUIRE_ALL: "1"$/d' .github/workflows/ci.yml \
    '/^      PSGEN_REQUIRE_ALL: "1"$/d' .github/workflows/release.yml

# 13. Make `section` answer a different body from `notes`, so a release could
#     publish one section and document another. Both succeed; the bodies differ
#     by a marker, which is what the check compares.
sabotage "section-notes-diverge" section-notes \
    "section and notes select different bodies" \
    '/^    section)$/,/^    notes)$/{s/body=\$(pick_section)/body="$(pick_section) EXTRA"/}' \
    scripts/release-notes.sh

# 14. Replace the `tag-matches` call with a no-op, so every tag creates a
#     release whatever version the crate carries. This is the step the release
#     job gates on, and nothing else exercises whether it is wired.
sabotage "tag-matches-unwired" tag-matches \
    "not \`release-notes.sh tag-matches\`" \
    's|^        run: sh scripts/release-notes.sh tag-matches "\$TAG"$|        run: "true"|' \
    .github/workflows/release.yml

# 15. Move `verify tag` below `publish`, so a release exists before the tag is
#     checked and a mismatch leaves assets behind that cannot be unpublished.
sabotage "tag-matches-after-publish" tag-matches \
    "runs after \`publish\`" \
    's/- name: verify tag/- name: TMPVERIFY/;s/- name: publish$/- name: verify tag/;s/- name: TMPVERIFY/- name: publish/' \
    .github/workflows/release.yml

# 16. Delete the guard assertion from `tests/smoke.sh`, which is the gate a
#     developer runs. The workflows keep theirs, so nothing but the pinned
#     smoke list can see it go.
sabotage "smoke-unit-guard-dropped" smoke-unit \
    "tests/smoke.sh no longer asserts the psgen stop is guarded" \
    "/^if grep '\^ExecStop=.* stop --pidfile'/,/^fi\$/d" tests/smoke.sh

# 17. Restore the fallback the workflow refuses: the header promises "the
#     newest section", which `release-notes.sh` never selects.
sabotage "notes-header-newest-section" notes \
    "promises 'the newest section'" \
    '/then `## Unreleased` when the tag is a prerelease/a\
the newest section when the tag has none of its own,\
then `## Unreleased` when the tag is a prerelease' \
    .github/release-notes.md

# 18. Drop the sentence that keeps the header honest about SHA256SUMS listing
#     every asset, which the `psgen-*` glob cannot do.
sabotage "notes-header-sums-overclaim" notes \
    "does not say SHA256SUMS leaves itself out" \
    's/not include itself, because a file cannot hold its own checksum/covers every asset of the release/' \
    .github/release-notes.md

# 19. Make the checksum step hash every file in `dist`, including the manifest
#     it has just truncated; the line for SHA256SUMS would then be a checksum
#     of the empty file the shell created.
sabotage "checksums-includes-itself" notes \
    "not \`sha256sum psgen-*\`" \
    's/sha256sum psgen-\*/sha256sum -b * > SHA256SUMS/' \
    .github/workflows/release.yml

# 20. A negative control: the unchanged copy must pass every check the
#     sabotages target, so a gate that fails everything cannot pass for a good
#     one. Each sabotage above names the message it produced, and this proves
#     the same check accepts the tree when the defect is absent — without both
#     halves a checker that always fails would satisfy every case.
control=$TMP/control
stage_tree "$control"
# Same reason as the sabotage runs: the copy has no build, so the real binary
# is named explicitly. Without it `--only unit` skips under
# PSGEN_REQUIRE_ALL=1 and the control reports a failure that is not a defect.
bin_args=""
if [ -x "$ROOT/target/release/psgen" ]; then
    bin_args="--bin $ROOT/target/release/psgen"
fi
control_checks=""
for name in publish-guard matrix clippy gh-release unit order package static \
    notes tag-matches section-notes smoke-unit require-all; do
    control_checks="$control_checks --only $name"
done
# shellcheck disable=SC2086
if ! python3 "$control/check_workflows.py" --root "$control" $control_checks \
        $bin_args >"$TMP/control.out" 2>&1; then
    cat "$TMP/control.out" >&2
    fail "the unsabotaged copy does not pass the workflow checks"
fi
rm -rf "$control"
echo "   the untouched copy passes every sabotaged gate"

# The checkout must be exactly as it was: a sabotage that escaped the copy is
# the one way this file could damage a release.
if command -v git >/dev/null 2>&1 && [ -d "$ROOT/.git" ]; then
    dirty=$(git -C "$ROOT" status --porcelain -- .github Cargo.toml 2>/dev/null || true)
    [ -z "$dirty" ] || fail "the sabotage meta-tests modified the checkout:
$dirty"
fi

if [ "$real_status" -ne 0 ]; then
    fail "the workflows still have the defects printed above"
fi
if [ "$unit_state" = skipped ]; then
    skip "no built binary, the unit gate could not run"
    echo "workflow: ok (unit gate SKIPPED)"
    exit 0
fi
echo "workflow: ok"
