#!/usr/bin/env python3
"""Check the workflow files the way the release depends on them.

`tests/workflow.sh` used to grep the workflow text for words, so a workflow
that mentioned `--verify-tag` anywhere passed even when the publish step no
longer passed it, and a `qemu: ""` in a cross matrix entry was invisible. This
checker parses the YAML, executes the step bodies that decide something
(with `cargo`, `gh`, `readelf` and `file` faked), and asserts the arguments and
the exit codes rather than the spelling.

The same entry point runs on the real tree and on a sabotaged copy, which is
how `tests/workflow.sh` proves each gate can fail.

Usage: check_workflows.py [--root DIR] [--bin PATH] [--only NAME]
"""

from __future__ import annotations

import os
import re
import resource
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

FAILURES: list[str] = []
NOTES: list[str] = []


def fail(msg: str) -> None:
    FAILURES.append(msg)
    print(f"FAIL: {msg}", file=sys.stderr)


def note(msg: str) -> None:
    NOTES.append(msg)


# --------------------------------------------------------------------------
# A parser for the YAML subset these workflows use: block mappings, block
# sequences, `|`/`>` block scalars with chomping, inline lists, quoted
# scalars and trailing comments. It is not a general YAML implementation and
# refuses anything it does not understand instead of guessing.
# --------------------------------------------------------------------------

BLOCK = ("|", ">", "|-", ">-", "|+", ">+")


class YamlError(Exception):
    pass


def indent_of(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def skip_blank(lines: list[str], i: int) -> int:
    while i < len(lines):
        stripped = lines[i].strip()
        if stripped == "" or stripped.startswith("#"):
            i += 1
        else:
            return i
    return i


def strip_comment(text: str) -> str:
    quote = None
    for i, ch in enumerate(text):
        if quote:
            if ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
            continue
        if ch == "#" and (i == 0 or text[i - 1] in " \t"):
            return text[:i].rstrip()
    return text.strip()


def scalar(text: str):
    text = strip_comment(text)
    if text in ("", "~", "null"):
        return None
    if text in ("true", "True"):
        return True
    if text in ("false", "False"):
        return False
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return text[1:-1]
    if text.startswith("[") and text.endswith("]"):
        inner = text[1:-1].strip()
        if not inner:
            return []
        return [scalar(part) for part in inner.split(",")]
    if text.startswith("{") and text.endswith("}"):
        inner = text[1:-1].strip()
        out = {}
        if not inner:
            return out
        for part in inner.split(","):
            key, _, value = part.partition(":")
            out[key.strip()] = scalar(value)
        return out
    return text


def key_value(text: str):
    """Split `key: value` on the first colon that is followed by space or EOL."""
    quote = None
    for i, ch in enumerate(text):
        if quote:
            if ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
            continue
        if ch == ":" and (i + 1 == len(text) or text[i + 1] in " \t"):
            return text[:i].strip(), text[i + 1:].strip()
    return None, None


def block_scalar(lines: list[str], i: int, base: int):
    body: list[str] = []
    while i < len(lines):
        line = lines[i]
        if line.strip() == "":
            body.append("")
            i += 1
            continue
        if indent_of(line) <= base:
            break
        body.append(line)
        i += 1
    nonempty = [line for line in body if line.strip()]
    cut = min(indent_of(line) for line in nonempty) if nonempty else 0
    text = "\n".join(line[cut:] if line.strip() else "" for line in body)
    return text.strip("\n") + "\n", i


def parse_node(lines: list[str], i: int, indent: int):
    i = skip_blank(lines, i)
    if i >= len(lines) or indent_of(lines[i]) < indent:
        return None, i
    if lines[i].lstrip().startswith("- "):
        return parse_seq(lines, i, indent_of(lines[i]))
    return parse_map(lines, i, indent_of(lines[i]))


def parse_map(lines: list[str], i: int, indent: int):
    out: dict = {}
    while True:
        i = skip_blank(lines, i)
        if i >= len(lines) or indent_of(lines[i]) != indent:
            break
        text = lines[i].lstrip()
        if text.startswith("- "):
            break
        key, rest = key_value(text)
        if key is None:
            raise YamlError(f"line {i + 1}: not a mapping entry: {text!r}")
        i += 1
        if rest in BLOCK:
            out[key], i = block_scalar(lines, i, indent)
        elif rest == "":
            j = skip_blank(lines, i)
            if j < len(lines) and indent_of(lines[j]) > indent:
                out[key], i = parse_node(lines, j, indent_of(lines[j]))
            else:
                out[key] = None
        else:
            out[key] = scalar(rest)
    return out, i


def parse_seq(lines: list[str], i: int, indent: int):
    out: list = []
    while True:
        i = skip_blank(lines, i)
        if i >= len(lines) or indent_of(lines[i]) != indent:
            break
        text = lines[i].lstrip()
        if not text.startswith("- "):
            break
        rest = text[2:]
        item_indent = indent + 2
        key, value = key_value(rest)
        if key is None:
            out.append(scalar(rest))
            i += 1
            continue
        item: dict = {}
        i += 1
        if value in BLOCK:
            item[key], i = block_scalar(lines, i, item_indent)
        elif value == "":
            j = skip_blank(lines, i)
            if j < len(lines) and indent_of(lines[j]) > item_indent:
                item[key], i = parse_node(lines, j, indent_of(lines[j]))
            else:
                item[key] = None
        else:
            item[key] = scalar(value)
        # The remaining keys of this sequence entry.
        while True:
            j = skip_blank(lines, i)
            if j >= len(lines) or indent_of(lines[j]) != item_indent:
                break
            text = lines[j].lstrip()
            if text.startswith("- "):
                break
            key2, value2 = key_value(text)
            if key2 is None:
                raise YamlError(f"line {j + 1}: not a mapping entry: {text!r}")
            i = j + 1
            if value2 in BLOCK:
                item[key2], i = block_scalar(lines, i, item_indent)
            elif value2 == "":
                k = skip_blank(lines, i)
                if k < len(lines) and indent_of(lines[k]) > item_indent:
                    item[key2], i = parse_node(lines, k, indent_of(lines[k]))
                else:
                    item[key2] = None
            else:
                item[key2] = scalar(value2)
        out.append(item)
    return out, i


def load_yaml(path: Path):
    lines = path.read_text().splitlines()
    value, i = parse_node(lines, 0, 0)
    i = skip_blank(lines, i)
    if i < len(lines):
        raise YamlError(f"{path}: unparsed content at line {i + 1}: "
                        f"{lines[i]!r}")
    return value


# --------------------------------------------------------------------------
# Executing a step body with the expressions substituted and the tools faked.
# --------------------------------------------------------------------------

GH_EXPR = re.compile(r"\$\{\{(.*?)\}\}", re.S)


def evaluate(expr: str, ctx: dict) -> str:
    """Resolve one `${{ }}` expression against the substitution context."""
    for alternative in expr.split("||"):
        value = evaluate_atom(alternative.strip(), ctx)
        if value:
            return value
    return ""


def evaluate_atom(atom: str, ctx: dict) -> str:
    if atom == "":
        return ""
    if atom.startswith("matrix."):
        # The context is keyed by the full `matrix.<field>` name, because that
        # is how the expression reads and how the substitution sites spell it.
        # Looking up the bare field name left every `${{ matrix.target }}`
        # empty, so an executed step body ran with `b=""`: `file ""` succeeds
        # and the checks that mean to read the artifact passed vacuously.
        return str(ctx.get(atom, ctx.get(atom[len("matrix."):], "")))
    if atom == "github.ref_name":
        return ctx.get("ref_name", "")
    if atom == "github.ref":
        return ctx.get("ref", "")
    if atom == "github.token":
        return "fake-token"
    if atom == "github.event.inputs.tag":
        return ctx.get("tag_input", "")
    if atom.startswith("secrets."):
        return ctx.get("token", "") if atom == "secrets.CARGO_REGISTRY_TOKEN" else ""
    if atom.startswith("'"):
        return atom.strip("'")
    if atom.startswith("startsWith(") or atom.startswith("contains("):
        # Step conditions are not executed; only the text is checked.
        return ""
    return ctx.get("_unknown", "UNSUBSTITUTED")


def substitute(text: str, ctx: dict) -> str:
    return GH_EXPR.sub(lambda m: evaluate(m.group(1), ctx), text)


class Workdir:
    """A scratch copy of the repository parts the workflows read, with fake tools.

    The files are copied rather than linked: the step bodies run from this
    directory, and a copy keeps a step that writes (a notes file, a staged
    binary) from touching the checkout.

    `stage_binary` needs a copy of the whole binary, which a finite
    RLIMIT_FSIZE refuses; `can_stage` says so, so the caller can skip the two
    checks that need it instead of dying with a traceback.
    """

    def __init__(self, root: Path, bin_path: Path | None):
        self.dir = Path(tempfile.mkdtemp(prefix="psgen-wf-"))
        self.bin = Path(self.dir / "fakebin")
        self.bin.mkdir()
        for name in ("CHANGELOG.md", "LICENSE", "README.md", "Cargo.toml"):
            src = root / name
            if src.exists():
                shutil.copy2(src, self.dir / name)
        for name in (".github", "scripts"):
            src = root / name
            if src.exists():
                shutil.copytree(src, self.dir / name)
        dist = self.dir / "dist"
        dist.mkdir()
        (dist / "psgen-x86_64-unknown-linux-musl").write_text("stub\n")
        self.bin_path = bin_path
        self._fake_tools()

    def can_stage(self) -> bool:
        """False when a copy of the built binary would hit RLIMIT_FSIZE.

        A write is bounded by the *soft* limit, which is what a caller lowers
        to provoke the failure, so the smaller of the two is the real bound.
        """
        if self.bin_path is None or not Path(self.bin_path).exists():
            return False
        try:
            soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
        except (OSError, ValueError):
            return True
        bounds = [v for v in (soft, hard) if v != resource.RLIM_INFINITY]
        if not bounds:
            return True
        return Path(self.bin_path).stat().st_size <= min(bounds)

    def close(self) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)

    def tool(self, name: str, body: str) -> Path:
        path = self.bin / name
        path.write_text("#!/bin/sh\n" + body)
        path.chmod(0o755)
        return path

    def _fake_tools(self) -> None:
        # `cargo` records its argv instead of building anything.
        self.tool("cargo", 'printf "cargo %s\\n" "$*" >> "$CALLS"\n')
        # `gh` records its argv the same way.
        self.tool("gh", 'printf "gh %s\\n" "$*" >> "$CALLS"\n')
        # A static ELF has no dynamic section and no interpreter.
        self.tool("readelf", "exit 0\n")
        self.tool("file", 'printf "%s: ELF 64-bit LSB executable, static\\n" "$1"\n')

    def stage_binary(self, target: str, want: bool) -> None:
        rel = self.dir / "target" / target / "release"
        rel.mkdir(parents=True, exist_ok=True)
        path = rel / "psgen"
        if path.exists() or path.is_symlink():
            path.unlink()
        if want and self.can_stage():
            shutil.copy2(self.bin_path, path)

    def run(self, script: str, ctx: dict, env: dict | None = None):
        calls = self.dir / "calls.log"
        calls.write_text("")
        full_env = dict(os.environ)
        full_env["PATH"] = f"{self.bin}{os.pathsep}{os.environ['PATH']}"
        full_env["CALLS"] = str(calls)
        for key, value in (env or {}).items():
            full_env[key] = value
        p = subprocess.run(["sh", "-eu", "-c", script], cwd=self.dir,
                           capture_output=True, text=True, env=full_env,
                           timeout=120)
        return p, calls.read_text().splitlines()


def step_env(step: dict, ctx: dict) -> dict:
    env = {}
    for key, value in (step.get("env") or {}).items():
        env[key] = substitute(str(value), ctx)
    return env


# --------------------------------------------------------------------------
# The checks.
# --------------------------------------------------------------------------

def check_line_endings(root: Path) -> None:
    """The files a workflow runs carry LF, not CRLF.

    `.gitattributes` says `* text=auto eol=lf`, so a checkout is LF and a
    CRLF copy can only come from an edit that ignored it. A CRLF `run:` body is
    a line the shell reads with `\\r` glued to its last token: `set -eu` becomes
    `set -eu\\r`, and `git status` in `tests/workflow.sh` then reports a clean
    tree that edited files. The YAML parser here splits on `\\n` too, so the
    defect would show up as a parse failure with no line number.
    """
    files = [
        root / ".github" / "workflows" / "ci.yml",
        root / ".github" / "workflows" / "release.yml",
        root / ".github" / "release-notes.md",
        root / "scripts" / "release-notes.sh",
        root / "tests" / "smoke.sh",
        root / "tests" / "workflow.sh",
        root / "tests" / "helpers" / "check_workflows.py",
    ]
    for path in files:
        if not path.exists():
            fail(f"{path.relative_to(root)} is missing")
            continue
        if b"\r\n" in path.read_bytes():
            fail(f"{path.relative_to(root)} has CRLF line endings, so the "
                 f"shell it runs sees a trailing \\r on every line")
    note("the workflow, script and test files are LF")


def find_jobs(workflow: dict) -> dict:
    jobs = workflow.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        raise YamlError("workflow has no jobs mapping")
    return jobs


def steps_of(job: dict, where: str) -> list:
    steps = job.get("steps")
    if not isinstance(steps, list):
        raise YamlError(f"{where} has no steps")
    return steps


def named_step(steps: list, name: str, where: str) -> dict:
    for step in steps:
        if isinstance(step, dict) and step.get("name") == name:
            return step
    raise YamlError(f"{where} has no step named {name!r}")


def check_run_blocks_parse(root: Path) -> None:
    """Every `run:` body parses as shell, including the inline ones.

    Inline `run: cmd` and folded `run: >-` bodies used to be skipped by the
    block-only matcher, so 16 of 27 bodies were never checked.
    """
    ver = manifest_version(root)
    total = 0
    for wf_path in sorted((root / ".github" / "workflows").glob("*.yml")):
        workflow = load_yaml(wf_path)
        jobs = find_jobs(workflow)
        for job_name, job in jobs.items():
            for index, step in enumerate(steps_of(job, f"{wf_path.name}:{job_name}")):
                if not isinstance(step, dict) or "run" not in step:
                    continue
                body = step["run"]
                if body is None:
                    continue
                ctx = {
                    "matrix.target": "x86_64-unknown-linux-musl",
                    "matrix.qemu": "x86_64",
                    "matrix.native": "false",
                    "matrix.runner": "ubuntu-24.04",
                    "matrix.smoke": "true",
                    "ref_name": f"v{ver}",
                    "ref": f"refs/tags/v{ver}",
                    "tag_input": "",
                    "token": "x",
                }
                script = substitute(body, ctx)
                total += 1
                p = subprocess.run(["sh", "-n", "-c", script],
                                   capture_output=True, text=True)
                if p.returncode != 0:
                    label = step.get("name") or f"step {index}"
                    fail(f"{wf_path.name}: `{label}` does not parse as shell: "
                         f"{p.stderr.strip()[:160]}")
    note(f"{total} run blocks parse as shell (inline and block)")


def check_clippy(root: Path) -> None:
    """Every clippy invocation denies warnings.

    A clippy run without `-D warnings` still prints the lint and exits 0, so
    the gate silently becomes advisory.
    """
    seen = 0
    for wf_path in sorted((root / ".github" / "workflows").glob("*.yml")):
        workflow = load_yaml(wf_path)
        for job_name, job in find_jobs(workflow).items():
            for step in steps_of(job, f"{wf_path.name}:{job_name}"):
                if not isinstance(step, dict):
                    continue
                body = step.get("run") or ""
                if "cargo clippy" not in body:
                    continue
                seen += 1
                flat = " ".join(body.split())
                label = f"{wf_path.name} {job_name} {step.get('name')!r}"
                if "-D warnings" not in flat:
                    fail(f"{label}: clippy does not pass `-D warnings`")
                if "--all-targets" not in flat:
                    fail(f"{label}: clippy does not check --all-targets")
    if seen == 0:
        fail("no workflow runs `cargo clippy`")


def matrix_entries(workflow: dict) -> list:
    build = find_jobs(workflow).get("build")
    if not isinstance(build, dict):
        raise YamlError("release.yml has no build job")
    strategy = build.get("strategy") or {}
    matrix = strategy.get("matrix") or {}
    include = matrix.get("include")
    if not isinstance(include, list) or not include:
        raise YamlError("the build job has no matrix include list")
    return include


def check_matrix(root: Path) -> None:
    """Every entry that needs an emulator names one, and every entry smokes.

    `native` selects the *build* path (`cargo build` versus `cargo zigbuild`),
    so it says nothing about whether the runner can execute the result. A
    cross-built binary whose target arch differs from the runner's needs
    `qemu:` (which is what registers binfmt), and a `qemu: ""` on such an
    entry means the smoke step runs a binary nothing can execute and passes
    for the wrong reason.
    """
    emulator = {
        "aarch64": "aarch64",
        "riscv64gc": "riscv64",
        "armv7": "arm",
        "loongarch64": "loong64",
        "powerpc64le": "ppc64le",
    }
    workflow = load_yaml(root / ".github" / "workflows" / "release.yml")
    entries = matrix_entries(workflow)
    targets = set()
    for entry in entries:
        if not isinstance(entry, dict):
            fail(f"matrix entry is not a mapping: {entry!r}")
            continue
        target = entry.get("target")
        if not target:
            fail(f"matrix entry has no target: {entry!r}")
            continue
        targets.add(target)
        runner = str(entry.get("runner") or "")
        if not runner:
            fail(f"matrix {target}: no runner")
        arch = target.split("-", 1)[0]
        runner_arch = "aarch64" if "arm" in runner else "x86_64"
        if "native" not in entry:
            fail(f"matrix {target}: no `native` key, so the build path is "
                 f"implicit")
        want_qemu = "" if arch == runner_arch or (arch == "i686" and runner_arch == "x86_64") \
            else emulator.get(arch, "")
        if arch != runner_arch and arch != "i686" and not want_qemu:
            fail(f"matrix {target}: no known emulator for {arch}")
            continue
        got_qemu = entry.get("qemu")
        got_qemu = "" if got_qemu is None else str(got_qemu)
        if got_qemu != want_qemu:
            fail(f"matrix {target}: qemu is {got_qemu!r}, wanted {want_qemu!r} "
                 f"for a {arch} binary on a {runner_arch} runner")
        if entry.get("smoke") is not True:
            fail(f"matrix {target}: smoke is {entry.get('smoke')!r}, not true")
        if arch == "aarch64" and entry.get("native") is True and "arm" not in runner:
            fail(f"matrix {target}: a native aarch64 build needs an arm runner, "
                 f"got {runner!r}")
    required = {
        "x86_64-unknown-linux-musl",
        "aarch64-unknown-linux-musl",
        "i686-unknown-linux-musl",
        "riscv64gc-unknown-linux-musl",
        "armv7-unknown-linux-musleabihf",
        "loongarch64-unknown-linux-musl",
        "powerpc64le-unknown-linux-musl",
    }
    missing = required - targets
    if missing:
        fail(f"the release matrix does not build {sorted(missing)}")
    note(f"{len(entries)} matrix entries, each with a runner, an emulator "
         f"where needed and a smoke")


def release_job(root: Path) -> tuple[dict, list]:
    workflow = load_yaml(root / ".github" / "workflows" / "release.yml")
    jobs = find_jobs(workflow)
    job = jobs.get("release")
    if not isinstance(job, dict):
        raise YamlError("release.yml has no release job")
    return job, steps_of(job, "release.yml:release")


def check_publish_guard(root: Path, work: Workdir) -> None:
    """A final tag publishes the crate; a prerelease and a tokenless run do not.

    The step body is executed with `cargo` faked, so the decision is measured
    by the arguments the real script produces, not by the spelling of its
    `if`.
    """
    _, steps = release_job(root)
    ver = manifest_version(root)
    step = named_step(steps, "publish-crate", "release.yml:release")
    body = step["run"]

    ctx = {"ref_name": f"v{ver}", "ref": f"refs/tags/v{ver}", "tag_input": "",
           "token": "secret-token"}
    env = step_env(step, ctx)
    p, calls = work.run(substitute(body, ctx), ctx, env)
    published = [line for line in calls if line.startswith("cargo publish")]
    if p.returncode != 0:
        fail(f"publish-crate failed for a final tag: {p.stderr.strip()[:160]}")
    if len(published) != 2:
        fail(f"publish-crate ran {published} for a final tag, wanted a dry run "
             f"and a publish")
    elif not published[0].endswith("--dry-run"):
        fail(f"publish-crate published before its dry run: {published}")
    if not any(c.startswith("cargo info psgen@") for c in calls):
        fail("publish-crate never verifies that the registry serves the "
             "version, so a release can pass while `cargo install` still "
             "installs the name reservation")

    ctx = {"ref_name": f"v{ver}-beta.1", "ref": f"refs/tags/v{ver}-beta.1",
           "tag_input": "", "token": "secret-token"}
    env = step_env(step, ctx)
    p, calls = work.run(substitute(body, ctx), ctx, env)
    published = [line for line in calls if line.startswith("cargo publish")]
    if p.returncode != 0:
        fail(f"publish-crate failed for a prerelease: {p.stderr.strip()[:160]}")
    if published:
        fail(f"publish-crate published a prerelease: {published}")

    # A fork without the secret fails on a final tag rather than announcing a
    # release the registry cannot serve (#49). Nothing may be published.
    ctx = {"ref_name": f"v{ver}", "ref": f"refs/tags/v{ver}", "tag_input": "",
           "token": ""}
    env = step_env(step, ctx)
    p, calls = work.run(substitute(body, ctx), ctx, env)
    published = [line for line in calls if line.startswith("cargo publish")]
    if p.returncode == 0:
        fail("publish-crate passed without a token; a final tag the registry "
             "cannot serve has to fail the job")
    if "CARGO_REGISTRY_TOKEN is not set" not in p.stderr:
        fail(f"publish-crate failed without naming the token: "
             f"{p.stderr.strip()[:160]}")
    if published:
        fail(f"publish-crate published without a token: {published}")

    # A workflow_dispatch run is judged by the tag it was given.
    ctx = {"ref_name": "main", "ref": "refs/heads/main",
           "tag_input": "v0.0.2-beta.1", "token": "secret-token"}
    env = step_env(step, ctx)
    p, calls = work.run(substitute(body, ctx), ctx, env)
    published = [line for line in calls if line.startswith("cargo publish")]
    if published:
        fail(f"publish-crate published a dispatched prerelease: {published}")
    note("the publish guard publishes a final tag only")


def check_gh_release(root: Path, work: Workdir) -> None:
    """`gh release create` verifies the tag and passes the prerelease flag."""
    _, steps = release_job(root)
    ver = manifest_version(root)
    step = named_step(steps, "publish", "release.yml:release")
    body = step["run"]

    ctx = {"ref_name": f"v{ver}", "ref": f"refs/tags/v{ver}", "tag_input": "",
           "token": ""}
    env = step_env(step, ctx)
    p, calls = work.run(substitute(body, ctx), ctx, env)
    if p.returncode != 0:
        fail(f"the release step failed for a final tag: {p.stderr.strip()[:160]}")
    gh = [line for line in calls if line.startswith("gh release create")]
    if len(gh) != 1:
        fail(f"the release step called gh {len(gh)} times for a final tag")
    else:
        line = gh[0]
        if "--verify-tag" not in line.split():
            fail(f"gh release create does not pass --verify-tag: {line}")
        if "--prerelease" in line.split():
            fail(f"a final tag passed --prerelease: {line}")
        if "--notes-file" not in line.split():
            fail(f"gh release create has no --notes-file: {line}")
        if f"v{ver}" not in line.split():
            fail(f"gh release create does not name the tag: {line}")
        if not any(part.startswith("dist/") for part in line.split()):
            fail(f"gh release create uploads no dist asset: {line}")
        if "--title" not in line.split():
            fail(f"gh release create has no --title: {line}")

    ctx = {"ref_name": f"v{ver}-beta.1", "ref": f"refs/tags/v{ver}-beta.1",
           "tag_input": "", "token": ""}
    env = step_env(step, ctx)
    p, calls = work.run(substitute(body, ctx), ctx, env)
    gh = [line for line in calls if line.startswith("gh release create")]
    if len(gh) != 1:
        fail(f"the release step called gh {len(gh)} times for a prerelease")
    elif "--prerelease" not in gh[0].split():
        fail(f"a prerelease did not pass --prerelease: {gh[0]}")
    note("gh release create verifies the tag and marks a prerelease")


def check_publish_order(root: Path) -> None:
    """`publish-crate` runs after `publish`, so the crate follows the assets."""
    _, steps = release_job(root)
    names = [step.get("name") for step in steps if isinstance(step, dict)]
    for wanted in ("publish", "publish-crate"):
        if wanted not in names:
            fail(f"release.yml:release has no {wanted!r} step")
            return
    if names.index("publish-crate") < names.index("publish"):
        fail("release.yml: publish-crate runs before publish")


def manifest_version(root: Path) -> str:
    """The `[package] version`, which a release tag must name.

    Derived rather than hardcoded: a fixture pinned to one release stops
    testing the rule as soon as the tree cuts the next one.
    """
    for line in (root / "Cargo.toml").read_text().splitlines():
        if line.startswith('version = "'):
            return line.split('"')[1]
    raise AssertionError("Cargo.toml has no version line")


def check_static(root: Path, work: Workdir) -> None:
    """The static check fails on a missing binary and on a dynamic one.

    The old body was `if readelf ... | grep -q NEEDED; then ... fi`, which is
    false both for a static binary and for one that does not exist, so a
    missing artifact passed. `test -f` and `&&`-guards make the two cases
    different.
    """
    workflow = load_yaml(root / ".github" / "workflows" / "release.yml")
    build = find_jobs(workflow).get("build")
    if not isinstance(build, dict):
        fail("release.yml has no build job")
        return
    step = named_step(steps_of(build, "release.yml:build"), "static check",
                      "release.yml:build")
    body = step["run"]

    ctx = {"matrix.target": "x86_64-unknown-linux-musl",
           "matrix.qemu": "x86_64", "matrix.native": "true",
           "matrix.runner": "ubuntu-24.04", "matrix.smoke": "true"}
    script = substitute(body, ctx)

    # Structure first: the body must prove the file exists before it reads it.
    # `if readelf ... | grep -q NEEDED; then ... fi` is false both for a static
    # binary and for one that was never built.
    flat = " ".join(script.split())
    if "test -f" not in flat:
        fail("the static check never uses `test -f` on the binary, so a "
             "missing artifact takes the same branch as a static one")
    if re.search(r"if\s+readelf[^;]*\|\s*grep", flat):
        fail("the static check guards a pipeline with `if`, which cannot tell a "
             "missing binary from a static one")

    if not work.can_stage():
        print("SKIP: no room to stage a copy of the binary under RLIMIT_FSIZE",
              file=sys.stderr)
        return

    work.stage_binary("x86_64-unknown-linux-musl", want=True)
    p, _ = work.run(script, ctx)
    if p.returncode != 0:
        fail(f"static check rejected a static binary: {p.stderr.strip()[:160]}")

    work.stage_binary("x86_64-unknown-linux-musl", want=False)
    p, _ = work.run(script, ctx)
    if p.returncode == 0:
        fail("static check passed with no binary at all")

    # A binary with a dynamic section must be rejected.
    work.tool("readelf", 'case "$1" in -d) printf " 0x01 NEEDED libc.so.6\\n";; esac\nexit 0\n')
    work.stage_binary("x86_64-unknown-linux-musl", want=True)
    p, _ = work.run(script, ctx)
    if p.returncode == 0:
        fail("static check passed a binary with a NEEDED entry")
    work.tool("readelf", "exit 0\n")
    note("the static check rejects a missing and a dynamic binary")


# The assertions each workflow's unit step must carry, as (label, literal code
# text). The list is a floor the checker owns: comparing ci.yml to release.yml
# only proves the two agree, so deleting the same assertion from both used to
# pass. Each literal must appear outside the step's comments, so a comment
# saying "we assert X" cannot stand in for the assertion.
REQUIRED_UNIT_ASSERTS = [
    ("the unit has no proc-fs-nets.target",
     "grep -q 'proc-fs-nets.target'"),
    ("RuntimeDirectory=psgen",
     "grep -q '^RuntimeDirectory=psgen$'"),
    ("an ExecStop line that runs the psgen stop",
     "grep -q '^ExecStop=.* stop --pidfile'"),
    ("the psgen stop is guarded",
     "grep -v -E '^ExecStop=(-|/bin/sh -c )'"),
    ("ConditionPathExists=/proc/1/stat",
     "grep -q '^ConditionPathExists=/proc/1/stat$'"),
]

# Each mutation below restores one defect the unit gate exists to catch, with
# the message the failing step must print. A step that rejects the unit for a
# different reason — `systemd-analyze` refusing the path, a grep that matched
# nothing because the mutation broke the file — proves nothing about the
# assertion it is supposed to exercise, so the message is part of the test.

def _exe_of(unit: str) -> str:
    """The executable the unit's ExecStart runs, so a mutation keeps it real.

    `psgen unit` quotes a path that carries a space or a quote, so the value is
    read as a whole field and a quoted one keeps its quotes.
    """
    m = re.search(r"(?m)^ExecStart=(\"[^\"]*\"|\S+)", unit)
    return m.group(1) if m else "/bin/true"


def _unguarded_stop(unit: str) -> str:
    """Restore the defect: the psgen stop carries neither guard.

    The executable stays the one ExecStart names, so the step fails on the
    guard assertion and not because `systemd-analyze` cannot find a path.
    """
    stop = f"ExecStop={_exe_of(unit)} stop --pidfile /run/psgen/psgen.pid"
    return re.sub(r"(?m)^ExecStop=/bin/sh -c .*$", stop, unit)


UNIT_MUTATIONS = [
    ("an unguarded psgen stop", _unguarded_stop, "psgen stop is unguarded"),
    ("no RuntimeDirectory",
     lambda u: re.sub(r"(?m)^RuntimeDirectory=.*$", "", u),
     "no RuntimeDirectory=psgen"),
    ("no ConditionPathExists",
     lambda u: re.sub(r"(?m)^ConditionPathExists=.*$", "", u),
     "ConditionPathExists does not name /proc/1/stat"),
    ("a nonexistent target",
     lambda u: u.replace("After=local-fs.target sysinit.target",
                         "After=local-fs.target proc-fs-nets.target"),
     "nonexistent target"),
    ("no ExecStop line for the psgen stop",
     lambda u: re.sub(r"(?m)^ExecStop=.*$", "", u),
     "has no ExecStop line that runs the psgen stop"),
]


def check_unit_gate(root: Path, work: Workdir) -> bool:
    """Both workflows run the same unit assertions, and they can fail.

    Returns False when there is no built binary, so the caller can print the
    skip (or fail under PSGEN_REQUIRE_ALL).
    """
    if work.bin_path is None or not Path(work.bin_path).exists():
        return False
    if not work.can_stage():
        print("SKIP: no room to stage a copy of the binary under RLIMIT_FSIZE",
              file=sys.stderr)
        return False
    target = work.dir / "target" / "release"
    target.mkdir(parents=True, exist_ok=True)
    link = target / "psgen"
    if link.exists() or link.is_symlink():
        link.unlink()
    shutil.copy2(work.bin_path, link)

    bodies = {}
    for wf_name in ("ci.yml", "release.yml"):
        workflow = load_yaml(root / ".github" / "workflows" / wf_name)
        for job_name, job in find_jobs(workflow).items():
            for step in steps_of(job, f"{wf_name}:{job_name}"):
                if isinstance(step, dict) and step.get("name") == "unit":
                    bodies[wf_name] = (step, job_name)
    if "ci.yml" not in bodies:
        fail("ci.yml has no unit step")
        return True
    if "release.yml" not in bodies:
        fail("release.yml has no unit step")
        return True

    # The required assertions are pinned here rather than compared between the
    # two files. Parity alone is blind to the case that matters: delete the
    # same grep from *both* workflows and the two still agree, so the gate
    # stops covering anything and nothing fails. Each entry below is text the
    # step body must contain outside its comments, plus the unit mutation that
    # text has to reject, so a comment cannot satisfy it and neither can a
    # grep that matches a different line.
    for wf_name, (step, _) in bodies.items():
        code = "\n".join(
            line for line in (step["run"] or "").splitlines()
            if not line.lstrip().startswith("#")
        )
        for label, needle in REQUIRED_UNIT_ASSERTS:
            if needle not in code:
                fail(f"{wf_name}: the unit step no longer asserts {label} "
                     f"(no {needle} outside its comments)")

    # The two gates must be the same gate: the release job's unit step used to
    # assert less than CI's, so a unit that CI rejects could still ship.
    def assertions(body: str) -> set[str]:
        return {m.group(0) for m in re.finditer(r"grep -q '[^']+'", body)}

    ci_asserts = assertions(bodies["ci.yml"][0]["run"])
    rel_asserts = assertions(bodies["release.yml"][0]["run"])
    if ci_asserts != rel_asserts:
        only_ci = sorted(ci_asserts - rel_asserts)
        only_rel = sorted(rel_asserts - ci_asserts)
        fail(f"the release unit gate differs from CI's: only in ci.yml "
             f"{only_ci}, only in release.yml {only_rel}")

    ctx = {"matrix.target": "x86_64-unknown-linux-musl", "matrix.native": "true",
           "matrix.qemu": "", "matrix.runner": "ubuntu-24.04",
           "matrix.smoke": "true"}
    for wf_name, (step, _) in bodies.items():
        p, _ = work.run(substitute(step["run"], ctx), ctx)
        if p.returncode != 0:
            fail(f"{wf_name}: the unit step rejected the real unit: "
                 f"{p.stderr.strip()[:200]}")

    # The assertions must be able to fail. Each mutation below restores one
    # defect the gate exists to catch, and the failing body must name it: a
    # step that rejects the unit for an unrelated reason (`systemd-analyze`
    # refusing a path, a grep that matches nothing because the mutation broke
    # the file) proves nothing about the assertion.
    good = subprocess.run([str(work.bin_path), "unit"], capture_output=True,
                          text=True)
    if good.returncode != 0:
        fail(f"cannot produce a unit to sabotage: {good.stderr.strip()[:120]}")
        return True
    real_release = work.bin_path
    shim = work.dir / "badbin"
    shim.mkdir(exist_ok=True)
    shim_bin = shim / "psgen"
    try:
        for label, mutate, expect in UNIT_MUTATIONS:
            bad = mutate(good.stdout)
            if bad == good.stdout:
                fail(f"{label}: the mutation changed nothing, so it cannot "
                     f"prove the gate rejects it")
                continue
            (work.dir / "bad-unit.service").write_text(bad)
            shim_bin.write_text("#!/bin/sh\ncat " + str(work.dir / "bad-unit.service") + "\n")
            shim_bin.chmod(0o755)
            link.unlink()
            shutil.copy2(shim_bin, link)
            for wf_name, (step, _) in bodies.items():
                p, _ = work.run(substitute(step["run"], ctx), ctx)
                if p.returncode == 0:
                    fail(f"{wf_name}: the unit step passed a unit with "
                         f"{label}, which it exists to reject")
                elif expect not in p.stderr:
                    fail(f"{wf_name}: the unit step rejected a unit with "
                         f"{label} for another reason: "
                         f"{p.stderr.strip()[:200]}")
            link.unlink()
            shutil.copy2(real_release, link)
    finally:
        if not link.exists():
            shutil.copy2(real_release, link)
    note(f"both workflows' unit steps reject {len(UNIT_MUTATIONS)} sabotaged units")
    return True


def check_release_notes(root: Path) -> None:
    """The release-notes header describes only behaviour that can happen.

    The header is prepended to every release body, so a claim in it is read as
    fact by everyone who downloads an asset. Two claims drifted from the code:

    * the fallback chain said "the newest section when the tag has none of its
      own", but `release-notes.sh` falls back to `## Unreleased` and to the
      base version, never to whatever section is newest — and the release job
      refuses a tag with none of those;
    * `SHA256SUMS` was described as covering every asset, but the checksum step
      hashes `psgen-*`, so the manifest cannot list itself.
    """
    header = root / ".github" / "release-notes.md"
    if not header.exists():
        fail(".github/release-notes.md is missing")
        return
    text = header.read_text()
    flat = " ".join(text.split())
    if "newest section" in flat:
        fail(".github/release-notes.md promises 'the newest section', which "
             "release-notes.sh never selects")
    if "## Unreleased" not in text:
        fail(".github/release-notes.md does not name the `## Unreleased` "
             "fallback, which is the one that exists")
    if "does not include itself" not in flat:
        fail(".github/release-notes.md does not say SHA256SUMS leaves itself "
             "out, so its checksum paragraph is wrong about the asset count")

    # The checksum step's glob is what decides which assets are listed. It must
    # not name SHA256SUMS as an input: the redirect truncates the file, so a
    # line for it is either absent or a checksum of empty.
    _, steps = release_job(root)
    step = named_step(steps, "checksums", "release.yml:release")
    body = " ".join((step.get("run") or "").split())
    if "sha256sum psgen-*" not in body:
        fail(f"release.yml: the checksums step hashes {body!r}, not `sha256sum "
             f"psgen-*`, so SHA256SUMS may list itself or miss an asset")
    note("the release-notes header describes reachable behaviour")


def check_tag_matches_wired(root: Path) -> None:
    """The release job runs `tag-matches` before it creates anything.

    `tag-matches` decides whether a tag names the version the crate carries.
    Running it after `publish` would leave a GitHub release for a tag the crate
    does not hold, and skipping it would let `v0.0.2` publish a `0.0.1` crate.
    The step order is the property, and it is measured, not grepped: the check
    fails when the step is missing or comes after `publish`.
    """
    _, steps = release_job(root)
    names = [step.get("name") for step in steps if isinstance(step, dict)]
    for wanted in ("verify tag", "publish"):
        if wanted not in names:
            fail(f"release.yml:release has no {wanted!r} step")
            return
    if names.index("verify tag") > names.index("publish"):
        fail("release.yml: `verify tag` runs after `publish`, so a tag that "
             "names another version can still create a release")
    step = named_step(steps, "verify tag", "release.yml:release")
    body = " ".join((step.get("run") or "").split())
    if "release-notes.sh tag-matches" not in body:
        fail(f"release.yml: `verify tag` runs {body!r}, not "
             f"`release-notes.sh tag-matches`")
    note("release.yml runs tag-matches before publish")


def check_section_notes(root: Path) -> None:
    """`section` and `notes` select the same CHANGELOG body.

    They answer the same question — which section a tag carries — so a release
    whose notes file disagreed with `section` would publish one section and
    document another. The bodies are compared for a final tag, a prerelease,
    and a tag that has to fall back, so no branch of the chain can drift on
    one side only.
    """
    ver = manifest_version(root)
    script = root / "scripts" / "release-notes.sh"
    header = root / ".github" / "release-notes.md"
    for path in (script, header):
        if not path.exists():
            fail(f"{path.relative_to(root)} is missing")
            return
    with tempfile.TemporaryDirectory(prefix="psgen-sect-") as tmp:
        out = Path(tmp)
        for tag in (f"v{ver}", f"v{ver}-beta.1"):
            # `notes` writes the header, a blank line, then the body.
            notes_file = out / f"notes-{tag}.md"
            p = subprocess.run(
                ["sh", str(script), "notes", tag, str(notes_file)],
                cwd=root, capture_output=True, text=True)
            if p.returncode != 0:
                fail(f"notes {tag} failed: {p.stderr.strip()[:120]}")
                continue
            p = subprocess.run(["sh", str(script), "section", tag],
                               cwd=root, capture_output=True, text=True)
            if p.returncode != 0:
                fail(f"section {tag} failed: {p.stderr.strip()[:120]}")
                continue
            lines = notes_file.read_text().splitlines()
            header_lines = len(header.read_text().splitlines())
            body = "\n".join(lines[header_lines + 1:]).strip("\n")
            if body != p.stdout.strip("\n"):
                fail(f"section and notes select different bodies for {tag}")
    note("section and notes select the same body for a final and a prerelease tag")


# The same floor for `tests/smoke.sh`, which is the entry point a developer
# runs and the gate the CI test job runs. Its unit block is separate code, so
# pinning only the workflows would let smoke lose an assertion the workflows
# keep — and smoke is what a green local run is trusted for.
REQUIRED_SMOKE_UNIT_ASSERTS = [
    ("the unit has no proc-fs-nets.target",
     "grep -q 'proc-fs-nets.target'"),
    ("RuntimeDirectory=psgen",
     "grep -q '^RuntimeDirectory=psgen$'"),
    ("an ExecStop line that runs the psgen stop",
     "grep -q '^ExecStop=.* stop --pidfile'"),
    ("the psgen stop is guarded",
     "grep -v -E '^ExecStop=(-|/bin/sh -c )'"),
    ("ConditionPathExists=/proc/1/stat",
     "grep -q '^ConditionPathExists=/proc/1/stat$'"),
]


def check_smoke_unit_asserts(root: Path) -> None:
    """`tests/smoke.sh`'s unit block carries every required assertion.

    `smoke.sh` is the gate a developer trusts, so it has to reject the same
    units the workflows reject. Comments do not count: the assertion has to be
    code, because a comment describing an assertion is exactly how a deleted
    one hides.
    """
    path = root / "tests" / "smoke.sh"
    if not path.exists():
        fail("tests/smoke.sh is missing")
        return
    code = "\n".join(
        line for line in path.read_text().splitlines()
        if not line.lstrip().startswith("#")
    )
    for label, needle in REQUIRED_SMOKE_UNIT_ASSERTS:
        if needle not in code:
            fail(f"tests/smoke.sh no longer asserts {label} (no {needle} "
                 f"outside its comments)")
    note(f"smoke.sh's unit block carries all "
         f"{len(REQUIRED_SMOKE_UNIT_ASSERTS)} assertions")


def check_package(root: Path) -> None:
    """The published crate excludes the test and CI trees."""
    text = (root / "Cargo.toml").read_text()
    section = None
    exclude = None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped
            continue
        if section != "[package]":
            continue
        if stripped.startswith("exclude"):
            exclude = stripped
    if exclude is None:
        fail("Cargo.toml has no `exclude` for the package")
        return
    for wanted in ("tests", "bench", "scripts", ".github", "Makefile"):
        if wanted not in exclude:
            fail(f"Cargo.toml's exclude omits {wanted!r}")
    note("Cargo.toml excludes the test, bench and CI trees")


# The commands CI runs as gates, mapped to the text `tests/smoke.sh` must run
# for the same gate. `make test` is `smoke.sh`, so smoke is the entry point a
# developer uses; a gate that exists only in a workflow is one a local run
# cannot see, and one that smoke runs with a different flag is worse than
# absent because it is expected to be the same.
SMOKE_GATES = [
    ("fmt", "cargo fmt --all -- --check"),
    ("clippy", "cargo clippy --locked --all-targets -- -D warnings"),
    ("unit tests", "cargo test --quiet --locked --release"),
    ("package", "cargo package --locked --no-verify"),
    ("systemd-analyze", "systemd-analyze verify"),
    ("workflow", "tests/workflow.sh"),
    ("invariants", "tests/invariants.py"),
    ("per-issue proof", "tests/proof_cases/report.sh"),
    ("per-issue proof: pidfile", "tests/proof_cases/pidfile.sh"),
    ("per-issue proof: generator", "tests/proof_cases/generator.sh"),
    ("per-issue proof: table", "tests/proof_cases/table.sh"),
    ("per-issue proof: stop", "tests/proof_cases/stop.sh"),
    ("per-issue proof: inject", "tests/proof_cases/inject.sh"),
    ("per-issue proof: surface", "tests/proof_cases/surface.sh"),
]


def smoke_body(root: Path) -> str:
    return (root / "tests" / "smoke.sh").read_text()


def check_smoke_parity(root: Path) -> None:
    """`sh tests/smoke.sh` runs every gate CI runs, with the same flags.

    The two used to drift: CI ran fmt and clippy and smoke did not, so a
    developer's green run said nothing about the lint gate. Each entry below
    is a gate in `ci.yml` or `release.yml` and the exact command smoke has to
    contain, so a flag cannot be softened on one side only.
    """
    body = " ".join(smoke_body(root).replace("\\\n", " ").split())
    for name, command in SMOKE_GATES:
        if command not in body:
            fail(f"tests/smoke.sh does not run `{command}`, which is the "
                 f"{name} gate CI runs")
    # The skip rule is the same rule in smoke and in the Python suite: a
    # capability that CI cannot use must fail, not skip.
    if "PSGEN_REQUIRE_ALL" not in body:
        fail("tests/smoke.sh never mentions PSGEN_REQUIRE_ALL, so a skip "
             "cannot be told from a pass")
    if "require_all_check.sh" not in body:
        fail("tests/smoke.sh does not run tests/helpers/require_all_check.sh, "
             "so the skip rule is asserted nowhere")
    if not (root / "tests" / "helpers" / "require_all_check.sh").exists():
        fail("tests/helpers/require_all_check.sh is missing")
    note(f"smoke runs all {len(SMOKE_GATES)} CI gates and asserts the skip rule")


def check_sabotage_is_staged(root: Path) -> None:
    """`tests/workflow.sh` sabotages a copy, never the checkout.

    A meta-test is an edit of a workflow by design; pointing it at the real
    tree means a run of the suite can leave a workflow changed, and the next
    commit then carries a sabotage. Every `sabotage` call must name a file
    relative to the staged copy, and the edit must be applied with
    `sed -i "$dir/$file"`.
    """
    body = (root / "tests" / "workflow.sh").read_text()
    if "$stage/$file" in body or "$ROOT/.github" in body.replace(
            'cp -R "$ROOT/.github"', "").replace(
            "[ -d \"$ROOT/.git\" ]", ""):
        fail("tests/workflow.sh edits a path under the checkout")
    if 'sed -i "$expr" "$dir/$file"' not in body:
        fail("tests/workflow.sh does not apply its sabotages to the staged "
             "copy ($dir), so a meta-test can edit the real workflow")
    if "stage_tree" not in body:
        fail("tests/workflow.sh has no stage_tree, so a sabotage has no copy "
             "to land in")
    note("the sabotage meta-tests edit a staged copy only")


def check_require_all(root: Path) -> None:
    """Every job that runs `tests/smoke.sh` as the gate sets `PSGEN_REQUIRE_ALL`.

    The variable turns a skip into a failure. The job that runs the suite on a
    runner with every capability must set it, because otherwise a runner that
    lost one capability goes green with a check that stopped covering anything.
    That is each workflow's single non-matrix suite job: the matrix `build` job
    in release.yml also runs `tests/smoke.sh`, against a cross binary under an
    emulator, and it is deliberately allowed to skip — the skip rule there
    would fail on capabilities the emulated binary cannot exercise.

    A step-level `env:` that forgets the variable, or a job-level one removed,
    is the regression this holds.
    """
    gates = {}
    for wf_path in sorted((root / ".github" / "workflows").glob("*.yml")):
        workflow = load_yaml(wf_path)
        for job_name, job in find_jobs(workflow).items():
            # A matrix job runs the suite against a cross binary under an
            # emulator; it is not the workflow's capability gate.
            if job.get("strategy"):
                continue
            steps = steps_of(job, f"{wf_path.name}:{job_name}")
            runs = any("tests/smoke.sh" in " ".join((step.get("run") or "").split())
                       for step in steps if isinstance(step, dict))
            if not runs:
                continue
            gates.setdefault(wf_path.name, []).append(job_name)
    for wf_name in ("ci.yml", "release.yml"):
        if not gates.get(wf_name):
            fail(f"{wf_name} has no job that runs tests/smoke.sh as its gate")
    for wf_name, job_names in sorted(gates.items()):
        if len(job_names) > 1:
            fail(f"{wf_name} runs tests/smoke.sh as the gate in "
                 f"{len(job_names)} jobs ({job_names}); the skip rule can only "
                 f"be asserted once")
        workflow = load_yaml(root / ".github" / "workflows" / wf_name)
        job = find_jobs(workflow)[job_names[0]]
        value = (job.get("env") or {}).get("PSGEN_REQUIRE_ALL")
        if str(value) != "1":
            fail(f"{wf_name}: the {job_names[0]} job runs tests/smoke.sh as the "
                 f"gate but PSGEN_REQUIRE_ALL is {value!r}, so a skip passes as "
                 f"a check that ran")
    note("the suite gate job in each workflow sets PSGEN_REQUIRE_ALL=1")


def check_readme_ci_gates(root: Path) -> None:
    """The README's CI-gate list must describe the assertions the workflow makes.

    #35: the list said the unit check greps for `ExecStop=-`, which the
    workflow deliberately does not (the `/bin/rm` cleanup line satisfies it).
    Every literal the unit step greps for has to appear in the README
    paragraph, so deleting an assertion or adding one cannot leave the
    documentation describing a weaker check.
    """
    readme = (root / "README.md").read_text()
    start = readme.find("### CI gates")
    if start < 0:
        fail("#35: README has no `### CI gates` section")
        return
    end = readme.find("\n### ", start + 1)
    section = readme[start:end if end > 0 else len(readme)]
    norm = " ".join(section.split())
    ci = (root / ".github" / "workflows" / "ci.yml").read_text()
    lits = re.findall(r"grep -q '([^']+)' /tmp/psgen\.service", ci)
    lits += re.findall(r"grep -v -E '([^']+)'", ci)
    if not lits:
        fail("#35: the unit check has no greps to compare the README with")
        return
    for lit in lits:
        for frag in re.split(r"[\^\$\.\*\(\)\|\+\[\]\{\}\\]", lit):
            frag = frag.strip()
            if len(frag) < 4:
                continue
            if frag not in norm:
                fail(f"#35: the README CI list does not name {frag!r} from "
                     f"the workflow's {lit!r}")
    if "`ExecStop=-`" in norm and "does not grep for `ExecStop=-`" not in norm:
        fail("#35: the README still lists `ExecStop=-` as an assertion")


def main(argv: list[str]) -> int:
    root = Path(".").resolve()
    bin_path = None
    only = set()
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--root":
            root = Path(argv[i + 1]).resolve()
            i += 2
        elif arg == "--bin":
            bin_path = Path(argv[i + 1]).resolve()
            i += 2
        elif arg == "--only":
            only.add(argv[i + 1])
            i += 2
        else:
            raise SystemExit(f"check_workflows.py: unknown argument {arg!r}")
    if bin_path is None:
        candidate = root / "target" / "release" / "psgen"
        bin_path = candidate if candidate.exists() else None

    checks = [
        ("run-blocks", lambda: check_run_blocks_parse(root)),
        ("line-endings", lambda: check_line_endings(root)),
        ("clippy", lambda: check_clippy(root)),
        ("matrix", lambda: check_matrix(root)),
        ("order", lambda: check_publish_order(root)),
        ("package", lambda: check_package(root)),
        ("notes", lambda: check_release_notes(root)),
        ("tag-matches", lambda: check_tag_matches_wired(root)),
        ("section-notes", lambda: check_section_notes(root)),
        ("smoke", lambda: check_smoke_parity(root)),
        ("smoke-unit", lambda: check_smoke_unit_asserts(root)),
        ("require-all", lambda: check_require_all(root)),
        ("readme-gates", lambda: check_readme_ci_gates(root)),
        ("sabotage", lambda: check_sabotage_is_staged(root)),
    ]
    work = Workdir(root, bin_path)
    try:
        checks += [
            ("publish-guard", lambda: check_publish_guard(root, work)),
            ("gh-release", lambda: check_gh_release(root, work)),
            ("static", lambda: check_static(root, work)),
        ]
        unit_ran = [False]

        def unit():
            unit_ran[0] = check_unit_gate(root, work)
        checks.append(("unit", unit))
        for name, fn in checks:
            if only and name not in only:
                continue
            try:
                fn()
            except YamlError as e:
                fail(f"{name}: {e}")
        if not only or "unit" in only:
            if not unit_ran[0]:
                require = os.environ.get("PSGEN_REQUIRE_ALL", "") not in ("", "0")
                if require:
                    fail("PSGEN_REQUIRE_ALL is set but there is no binary for "
                         "the unit check")
                else:
                    print("SKIP: no built binary for the unit check",
                          file=sys.stderr)
                    print("WORKFLOW_UNIT_SKIPPED")
    finally:
        work.close()

    for line in NOTES:
        print(f"   {line}")
    if FAILURES:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
