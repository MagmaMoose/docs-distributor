"""Invariants the output must hold before it is proposed. No LLM, no judgement.

* **Line-count parity.** Substitution never adds or removes a line, and a repair is refused
  if it does, so every generated file has exactly its source's line count (the section index
  carries the generated-page note on top). A mismatch means something upstream is broken.
* **Links.** Every relative link in the generated pages resolves to a file in the docs repo.
  An anchor that no longer matches a heading is a warning.
* **``mkdocs build --strict``** on the docs repo with the new section in place, exactly as
  the docs repo's own CI will build it.
"""

from __future__ import annotations

import os
import posixpath
import re
import subprocess  # nosec B404 - fixed argv, no shell, see the call sites
import sys
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from docs_distributor.transform import (
    _LINK,
    GENERATED_NOTE_LINES,
    mask_code_spans,
    segments,
    slugify,
)


@dataclass
class VerifyResult:
    parity: list[str] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    anchors: list[str] = field(default_factory=list)
    mkdocs: str = "not run"  # passed | failed | not run
    mkdocs_log: str = ""

    @property
    def passed(self) -> bool:
        return not self.parity and not self.links and self.mkdocs != "failed"


def line_parity(
    sources: Mapping[str, bytes],
    outputs: Mapping[str, bytes],
    path_map: Mapping[str, str],
    target_dir: str,
    index: str | None = "index.md",
) -> list[str]:
    problems: list[str] = []
    for src, rel in sorted(path_map.items()):
        out_path = f"{target_dir}/{rel}"
        a, b = sources.get(src), outputs.get(out_path)
        if a is None or b is None or b"\0" in a:
            continue
        try:
            want = a.decode("utf-8").count("\n")
            got = b.decode("utf-8").count("\n")
        except UnicodeDecodeError:
            continue
        if src == index:
            want += GENERATED_NOTE_LINES
        if want != got:
            problems.append(f"{out_path}: {got} lines, source has {want}")
    return problems


_HEADING = re.compile(r"^#{1,6}\s+(.+?)\s*#*\s*$")
_ATTR_ID = re.compile(r"\{[^}]*#([\w-]+)[^}]*\}\s*$")


def anchors_of(text: str) -> set[str]:
    found: set[str] = set()
    for seg in segments(text):
        if seg.code:
            continue
        for line in seg.text.splitlines():
            m = _HEADING.match(line)
            if m:
                title = m.group(1)
                attr = _ATTR_ID.search(title)
                if attr:
                    found.add(attr.group(1))
                    title = title[: attr.start()]
                found.add(slugify(re.sub(r"[`*_]", "", title)))
    return found


def check_links(files: Mapping[str, str], known: set[str]) -> tuple[list[str], list[str]]:
    """Broken relative links (errors) and stale anchors (warnings) in generated pages.

    ``files`` are generated Markdown pages keyed by repo path; ``known`` is every path in the
    docs repo after this run.
    """
    errors: list[str] = []
    warnings: list[str] = []
    anchor_cache: dict[str, set[str]] = {}
    for path in sorted(files):
        for seg in segments(files[path]):
            if seg.code:
                continue
            masked = mask_code_spans(seg.text)
            for m in _LINK.finditer(masked):
                target = seg.text[m.start("target") : m.end("target")].strip("<>")
                if re.match(r"^[a-z][a-z0-9+.-]*:", target) or target.startswith("#"):
                    continue
                rel, _, anchor = target.partition("#")
                resolved = posixpath.normpath(posixpath.join(posixpath.dirname(path), rel))
                line = seg.first_line + seg.text[: m.start()].count("\n")
                if resolved not in known:
                    errors.append(f"{path}:{line}: link to {rel} does not resolve")
                    continue
                if anchor and resolved in files:
                    heads = anchor_cache.setdefault(resolved, anchors_of(files[resolved]))
                    if anchor not in heads:
                        warnings.append(f"{path}:{line}: anchor #{anchor} not found in {rel}")
    return errors, warnings


def mkdocs_build(repo: Path, timeout: int = 900) -> tuple[str, str]:
    """``mkdocs build --strict`` in ``repo``. Returns (passed|failed, the log's last lines)."""
    with tempfile.TemporaryDirectory() as site:
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": os.environ.get("HOME", site),
            "LANG": "C.UTF-8",
            "NO_COLOR": "1",
        }
        try:
            proc = subprocess.run(  # noqa: S603 # nosec B603 - fixed argv, no shell
                [sys.executable, "-m", "mkdocs", "build", "--strict", "--site-dir", site],
                cwd=repo,
                env=env,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return "failed", f"mkdocs build timed out after {timeout}s"
    log = "\n".join((proc.stdout + proc.stderr).strip().splitlines()[-40:])
    return ("passed" if proc.returncode == 0 else "failed"), log
