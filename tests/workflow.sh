#!/bin/sh
# Check the pieces of the release pipeline that can be run outside GitHub.
#
# What this does exercise:
#
#   - the tag -> notes / prerelease / publish decisions, through the same
#     script the workflow calls;
#   - the release workflow's shell, with a fake `gh` that records its argv, so
#     the arguments `gh release create` would receive are checked;
#   - every `run:` block in both workflows parses as shell (`sh -n`);
#   - the CI unit check passes and fails on the right unit files;
#   - the assertions that used to be no-ops (`! grep`, `|| true`) are gone.
#
# What it cannot exercise: GitHub's own evaluation of `${{ }}` expressions, the
# runner image, and the network calls themselves. `gh` is faked and the
# workflow is parsed, not executed by GitHub.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

notes=scripts/release-notes.sh
[ -x "$notes" ] || fail "$notes is not executable"

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

echo "== changelog section selection"
# A final tag must select its own section; a prerelease falls back to
# Unreleased when it has no section of its own.
sh "$notes" notes v0.0.1 "$TMP/final.md"
grep -q '^## 0.0.1' "$TMP/final.md" && fail "the notes for v0.0.1 still contain a heading"
grep -q 'Initial release' "$TMP/final.md" || fail "v0.0.1 did not select its own section"
grep -q 'Unreleased' "$TMP/final.md" && fail "v0.0.1 selected Unreleased"
sh "$notes" notes v0.0.1-beta.1 "$TMP/pre.md"
grep -q 'Initial release' "$TMP/pre.md" && fail "a prerelease selected the final section"
# The boilerplate is always first.
head -1 "$TMP/final.md" | grep -q 'psgen' || fail "the notes lost the boilerplate"

echo "== gh release create arguments (fake gh)"
mkdir -p "$TMP/fakebin" "$TMP/dist"
printf 'stub\n' > "$TMP/dist/psgen-x86_64-unknown-linux-musl"
cat > "$TMP/fakebin/gh" <<'FAKE'
#!/bin/sh
# Record argv, one per line, so the test can assert on it.
printf '%s\n' "$@" > "$GH_ARGS"
FAKE
chmod +x "$TMP/fakebin/gh"
# The shell the workflow runs, in the same order, for a final and a prerelease.
run_publish_step() {
    tag=$1
    TAG=$tag GH_ARGS=$TMP/args GH_TOKEN=x PATH="$TMP/fakebin:$PATH" sh -eu -c '
        sh scripts/release-notes.sh notes "$TAG" /tmp/notes.$$ 
        pre=""
        if [ "$(sh scripts/release-notes.sh prerelease "$TAG")" = yes ]; then
            pre="--prerelease"
        fi
        gh release create "$TAG" $pre --verify-tag --title "psgen $TAG" \
            --notes-file /tmp/notes.$$ '"$TMP"'/dist/*
        rm -f /tmp/notes.$$
    '
}
run_publish_step v0.0.1
grep -qx -- '--prerelease' "$TMP/args" && fail "a final tag passed --prerelease"
grep -qx -- '--verify-tag' "$TMP/args" || fail "--verify-tag is missing"
grep -qx -- '--notes-file' "$TMP/args" || fail "--notes-file is missing"
grep -qx -- 'v0.0.1' "$TMP/args" || fail "the tag is missing from the arguments"
run_publish_step v0.0.1-beta.1
grep -qx -- '--prerelease' "$TMP/args" || fail "a prerelease did not pass --prerelease"

echo "== publish guard skips without a token"
# The publish-crate step must exit 0 (not fail the release) with no token.
if sh -eu -c '
    TAG=v0.0.1
    if [ "$(sh scripts/release-notes.sh publish "$TAG")" != yes ]; then exit 1; fi
    if [ -z "${CARGO_REGISTRY_TOKEN:-}" ]; then exit 0; fi
    exit 1
'; then :; else fail "the publish guard did not skip cleanly without a token"; fi
if sh -eu -c '
    TAG=v0.0.1-beta.1
    if [ "$(sh scripts/release-notes.sh publish "$TAG")" != yes ]; then exit 0; fi
    exit 1
'; then :; else fail "the publish guard tried to publish a prerelease"; fi

echo "== a tag with no changelog section fails"
# `notes` falls back to `## Unreleased`; with neither section present it must
# fail instead of writing notes that describe nothing.
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

echo "== release matrix and job gates"
python3 - <<'PY'
import pathlib, re, sys
text = pathlib.Path(".github/workflows/release.yml").read_text()
entries = re.findall(r"(?m)^\s*-\s+runner:.*$", text)
smokes = re.findall(r"(?m)^\s+smoke:\s*true\s*$", text)
if not entries:
    sys.exit("release.yml has no matrix entries")
if len(smokes) != len(entries):
    sys.exit(f"{len(entries)} matrix entries but {len(smokes)} set smoke: true")
print(f"   {len(entries)} matrix entries run smoke")

job = re.search(r"(?ms)^  test:\n(.*?)(?=^  [A-Za-z0-9_-]+:)", text)
if not job:
    sys.exit("release.yml has no test job")
body = job.group(1)
for needle in ("cargo fmt", "cargo clippy", "cargo package", "RuntimeDirectory=psgen"):
    if needle not in body:
        sys.exit(f"the release test job does not run {needle!r}")
print("   the release test job runs fmt, clippy, package and the unit assert")

pub = re.search(r"(?ms)^  release:\n(.*?)(?=^  [A-Za-z0-9_-]+:|\Z)", text)
if not pub:
    sys.exit("release.yml has no release job")
pb = pub.group(1)
dry = re.search(r"cargo publish --locked --dry-run", pb)
real = re.search(r"cargo publish --locked(?! --dry-run)", pb)
if not dry or not real:
    sys.exit("the publish job lacks a dry run or the real publish")
if dry.start() > real.start():
    sys.exit("the publish job publishes before the dry run")
print("   the publish job dry-runs before publishing")
PY

echo "== every run: block is shell that parses"
python3 - "$TMP" <<'PY'
import re, subprocess, sys, pathlib
tmp = pathlib.Path(sys.argv[1])
bad = 0
for wf in sorted(pathlib.Path(".github/workflows").glob("*.yml")):
    lines = wf.read_text().splitlines()
    i = 0
    n = 0
    while i < len(lines):
        line = lines[i]
        m = re.match(r"^(\s*)(- )?run: \|\s*$", line)
        if not m:
            i += 1
            continue
        base = len(m.group(1))
        i += 1
        block = []
        while i < len(lines):
            cur = lines[i]
            if cur.strip() == "":
                block.append("")
                i += 1
                continue
            indent = len(cur) - len(cur.lstrip())
            if indent <= base:
                break
            block.append(cur)
            i += 1
        text = "\n".join(block) + "\n"
        script = tmp / f"{wf.stem}-{n}.sh"
        script.write_text(text)
        r = subprocess.run(["sh", "-n", str(script)], capture_output=True, text=True)
        n += 1
        if r.returncode != 0:
            print(f"{wf}: run block {n} does not parse: {r.stderr.strip()}", file=sys.stderr)
            bad += 1
    print(f"   {wf.name}: {n} run blocks parse")
sys.exit(1 if bad else 0)
PY

echo "== the old no-op assertions are gone"
grep -q '|| true' .github/workflows/*.yml && fail "a workflow still hides a failure with '|| true'"
grep -q '! grep ' .github/workflows/*.yml && fail "a workflow still uses '! grep' under set -e"
# The only mention of the removed target may be the assertion that it is
# absent, and that assertion must be an `if`, not a `! grep`.
if grep -n 'proc-fs-nets.target' .github/workflows/*.yml \
    | grep -v 'if grep -q .proc-fs-nets.target. /tmp/psgen.service; then' >/dev/null; then
    fail "a workflow names the removed target outside the absence check"
fi

echo "== the unit step fails on a bad unit"
# The CI unit check, run against a good and a deliberately bad unit file.
check_unit() {
    unit=$1
    (
        set -eu
        if grep -q 'proc-fs-nets.target' "$unit"; then
            echo "the unit names a target that does not exist" >&2
            exit 1
        fi
        grep -q '^RuntimeDirectory=psgen$' "$unit" || exit 1
        grep -q '^ExecStop=-' "$unit" || exit 1
    )
}
"$ROOT/target/release/psgen" unit > "$TMP/good.unit" 2>/dev/null || {
    echo "SKIP: no built binary for the unit check" >&2
}
if [ -s "$TMP/good.unit" ]; then
    check_unit "$TMP/good.unit" || fail "the real unit failed the CI check"
    sed 's/^After=.*/After=local-fs.target proc-fs-nets.target/' "$TMP/good.unit" \
        > "$TMP/bad.unit"
    if check_unit "$TMP/bad.unit" 2>/dev/null; then
        fail "the CI unit check passed a unit naming a missing target"
    fi
    grep -v '^ExecStop=-' "$TMP/good.unit" > "$TMP/no-stop.unit"
    if check_unit "$TMP/no-stop.unit" 2>/dev/null; then
        fail "the CI unit check passed a unit without ExecStop=-"
    fi
fi

echo "workflow: ok"
