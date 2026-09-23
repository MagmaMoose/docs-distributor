"""Logs, the private run report, and the public texts.

Two audiences, kept apart by construction:

* **Private**: the run report on the cache volume. It holds every finding with the text that
  matched, every candidate term, every mapping proposal. It is written with owner-only
  permissions and never sent anywhere.
* **Public**: log lines, the pull-request body, the issue and the Slack message. These are
  built from counts, rule names, output paths and placeholders only, and the pipeline runs
  each one through the audit before it leaves the process.
"""

from __future__ import annotations

import json
import os
import sys
import time
import uuid
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import httpx
import yaml

from docs_distributor import audit


def log(event: str, **fields: Any) -> None:
    """One JSON object per line on stdout. Callers pass counts, ids and output paths only."""
    record = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": event, **fields}
    sys.stdout.write(json.dumps(record, sort_keys=True, default=str) + "\n")
    sys.stdout.flush()


@dataclass
class SourceReport:
    name: str
    title: str
    target: str
    revision: str = ""  # PRIVATE
    pages: int = 0
    dropped: int = 0
    replacements: int = 0
    private_links: int = 0
    images_omitted: int = 0
    repaired: int = 0
    unrepaired: list[str] = field(default_factory=list)  # "path:line kind" (public)
    candidates: int = 0
    admitted: list[str] = field(default_factory=list)  # judged public; they publish anyway
    sensitive: list[dict[str, str]] = field(default_factory=list)  # PRIVATE
    undecided: list[str] = field(default_factory=list)  # PRIVATE
    proposals: list[dict[str, str]] = field(default_factory=list)  # PRIVATE
    warnings: list[str] = field(default_factory=list)  # public


@dataclass
class RunReport:
    mode: str
    run_id: str = field(
        default_factory=lambda: (
            time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + uuid.uuid4().hex[:6]
        )
    )
    status: str = "running"
    exit_code: int | None = None
    sources: list[SourceReport] = field(default_factory=list)
    audit: dict[str, Any] = field(default_factory=dict)  # PRIVATE (matches)
    verify: dict[str, Any] = field(default_factory=dict)
    publish: dict[str, Any] = field(default_factory=dict)
    llm: dict[str, Any] = field(default_factory=dict)
    changes: dict[str, list[str]] = field(default_factory=dict)

    def write(self, root: Path) -> Path:
        path = root / self.run_id
        path.mkdir(parents=True, exist_ok=True)
        # Owner-only: the report can hold real values. 0700 is the tightest a directory can be
        # and still be entered.
        os.chmod(path, 0o700)  # nosemgrep
        target = path / "report.json"
        target.write_text(
            json.dumps(asdict(self), indent=1, sort_keys=True, default=str), encoding="utf-8"
        )
        os.chmod(target, 0o600)
        proposals = [p for s in self.sources for p in s.proposals]
        if proposals:
            proposal = path / "mapping-proposal.yml"
            proposal.write_text(mapping_proposal(proposals), encoding="utf-8")
            os.chmod(proposal, 0o600)
        return path


def findings_record(result: audit.AuditResult) -> dict[str, Any]:
    return {
        "layers": result.layers,
        "files": result.files,
        "findings": [asdict(f) for f in result.findings],
    }


def findings_summary(result: audit.AuditResult) -> list[str]:
    """Public lines: rule counts and where, never the matched text."""
    counts = Counter((f.layer, f.rule) for f in result.findings)
    lines = [f"layer {layer} {rule}: {n}" for (layer, rule), n in sorted(counts.items())]
    lines.extend(f.public() for f in result.findings[:50])
    return lines


def mapping_proposal(proposals: Sequence[Mapping[str, str]]) -> str:
    """The PRIVATE mapping diff a human reviews and merges into the mapping secret."""
    rules = [
        {"from": p["term"], "to": p["to"], "class": p["class"]}
        | ({} if p.get("to") else {"todo": "no acceptable stand-in was proposed"})
        for p in proposals
    ]
    header = (
        "# PRIVATE. Proposed additions to the docs-distributor mapping.\n"
        "# Review every entry, then add the ones you accept to the mapping secret.\n"
        "# Never commit this file or paste it anywhere public.\n"
    )
    return header + yaml.safe_dump({"rules": rules}, sort_keys=False, allow_unicode=True)


# --- public texts --------------------------------------------------------------------------


def pull_request_text(
    sources: Sequence[SourceReport], changes: Mapping[str, list[str]]
) -> tuple[str, str, str]:
    """(title, body, commit message). Deterministic: no run ids and no timestamps, so an
    unchanged run produces an unchanged pull request."""
    names = ", ".join(s.title for s in sources)
    title = f"docs: sync {names} from upstream"
    added, updated, removed = (len(changes.get(k, [])) for k in ("added", "updated", "removed"))
    bullets = [
        f"Regenerates {', '.join(f'`{s.target}/`' for s in sources)} from a private upstream: "
        f"{added} pages added, {updated} updated, {removed} removed.",
        "Passed the leak audit (literal, pattern-class and novelty layers) before this PR "
        "was opened. These pages are generated: edit them upstream, not here.",
    ]
    admitted = sorted({t for s in sources for t in s.admitted}, key=str.casefold)
    if admitted:
        shown = ", ".join(f"`{t}`" for t in admitted[:40])
        more = f" and {len(admitted) - 40} more" if len(admitted) > 40 else ""
        bullets.append(f"New terms the classifier judged public (worth a glance): {shown}{more}.")
    unrepaired = [u for s in sources for u in s.unrepaired]
    if unrepaired:
        bullets.append(
            f"{len(unrepaired)} substitution artefacts were left as they are: "
            + "; ".join(unrepaired[:10])
            + "."
        )
    warnings = [w for s in sources for w in s.warnings]
    if warnings:
        bullets.append(f"{len(warnings)} warnings: " + "; ".join(warnings[:10]) + ".")
    body = "\n".join(f"- {b}" for b in bullets) + "\n"
    commit = (
        f"{title}\n\nGenerated by docs-distributor. Edit upstream; this content is overwritten.\n"
    )
    return title, body, commit


NOVELTY_MARKER = "<!-- docs-distributor:novelty -->"


def novelty_issue(run_id: str, sources: Sequence[SourceReport]) -> tuple[str, str]:
    """A PUBLIC issue that says a sync is blocked and why, without naming a single term."""
    rows = []
    for s in sources:
        by_category = Counter(p["class"] for p in s.proposals)
        stand_ins: dict[str, list[str]] = {}
        for p in s.proposals:
            if p.get("to"):
                stand_ins.setdefault(p["class"], []).append(p["to"])
        for cls, n in sorted(by_category.items()):
            shown = ", ".join(f"`{v}`" for v in stand_ins.get(cls, [])) or "-"
            rows.append(f"| {s.name} | {cls} | {n} | {shown} |")
        if s.undecided:
            rows.append(f"| {s.name} | unclassified | {len(s.undecided)} | - |")
    title = "Sync blocked: terms with no mapping"
    body = "\n".join(
        [
            NOVELTY_MARKER,
            "The last sync published nothing: the novelty scan found terms that were classified "
            "sensitive, or could not be classified, and have no mapping.",
            "",
            "| Source | Class | Terms | Proposed stand-ins |",
            "|---|---|---|---|",
            *rows,
            "",
            "The terms are not listed here because this repository is public. The full proposal "
            f"is in the private run report `{run_id}/mapping-proposal.yml` on the cache volume; "
            "review it, add what you accept to the mapping secret, and the next run publishes.",
        ]
    )
    return title, body + "\n"


def slack(webhook: str | None, text: str, client: httpx.Client | None = None) -> bool:
    if not webhook:
        return False
    http = client or httpx.Client(timeout=15)
    try:
        return http.post(webhook, json={"text": text}).status_code < 300
    except httpx.HTTPError:
        return False
