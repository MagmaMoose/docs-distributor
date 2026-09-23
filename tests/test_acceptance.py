"""The brief's acceptance criteria, end to end, against the synthetic fixture corpus.

No network: the model is a deterministic fake and GitHub is an in-memory fake. Regenerate
the golden tree with ``UPDATE_GOLDEN=1 pytest tests/test_acceptance.py`` and review the diff
like any other change to expected output.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from pathlib import Path
from typing import Any

import pytest

from docs_distributor import audit, config, pipeline
from docs_distributor.github import blob_sha
from docs_distributor.llm import LLM, Cache, Template
from docs_distributor.novelty import load_tech_vocabulary
from docs_distributor.sources import load_local

FIXTURES = Path(__file__).parent / "fixtures"
GOLDEN = FIXTURES / "golden"
VOCAB = config.load_vocabulary()


class FakeModel:
    """Answers the four templates deterministically. ``sensitive`` terms are classified as
    customers; everything else is public."""

    model = "fake-model"

    def __init__(self, sensitive: frozenset[str] = frozenset()) -> None:
        self.sensitive = sensitive
        self.calls: list[str] = []

    def complete(self, template: Template, user: str) -> Any:
        self.calls.append(template.name)
        if template.name == "classify":
            terms = [t["term"] for t in json.loads(user[user.rindex("\n[") + 1 :])]
            return {
                "results": [
                    {
                        "term": t,
                        "sensitive": t.casefold() in self.sensitive,
                        "category": "customer"
                        if t.casefold() in self.sensitive
                        else "generic-word",
                        "reason": "fixture",
                    }
                    for t in terms
                ]
            }
        if template.name == "repair":
            text = user.split("Paragraph:\n\n", 1)[1]
            text = re.sub(r"(?i)\b(\w+)\s+\1\b", r"\1", text)
            text = re.sub(r"(?i)\b([\w][\w .-]{2,}?)\s*\(\s*\1\s*\)", r"\1", text)
            text = re.sub(r"\ba (?=[aeiouAEIOU])", "an ", text)
            return {"text": text}
        if template.name == "place":
            pages = json.loads(user[user.rindex("\n[") + 1 :])
            return {
                "placements": [
                    {"path": p["path"], "section": [], "title": p["heading"]} for p in pages
                ]
            }
        return {"proposals": []}


class FakeGitHub:
    """Just enough of the GitHub API for publish(): refs, trees, commits, pulls, issues."""

    def __init__(self, files: dict[str, bytes], base: str = "main") -> None:
        self.base = base
        self.blobs = {blob_sha(v): v for v in files.values()}
        self.trees: dict[str, dict[str, bytes]] = {}
        root = self._tree(files)
        self.commits: dict[str, tuple[str, str | None]] = {"c0": (root, None)}
        self.refs = {base: "c0"}
        self.pulls: list[dict[str, Any]] = []
        self.issues: list[dict[str, Any]] = []

    def _tree(self, files: dict[str, bytes]) -> str:
        sha = hashlib.sha1(
            json.dumps(sorted((p, blob_sha(b)) for p, b in files.items())).encode(),
            usedforsecurity=False,
        ).hexdigest()
        self.trees[sha] = dict(files)
        return sha

    def default_branch(self, repo: str) -> str:
        return self.base

    def branch_head(self, repo: str, branch: str) -> str | None:
        return self.refs.get(branch)

    def commit_tree(self, repo: str, commit: str) -> str:
        return self.commits[commit][0]

    def create_blob(self, repo: str, content: bytes) -> str:
        sha = blob_sha(content)
        self.blobs[sha] = content
        return sha

    def create_tree(self, repo: str, base_tree: str, entries: list[dict[str, Any]]) -> str:
        files = dict(self.trees[base_tree])
        for e in entries:
            if e["sha"] is None:
                files.pop(e["path"], None)
            else:
                files[e["path"]] = self.blobs[e["sha"]]
        return self._tree(files)

    def create_commit(self, repo: str, message: str, tree: str, parent: str) -> str:
        cid = f"c{len(self.commits)}"
        self.commits[cid] = (tree, parent)
        return cid

    def set_branch(self, repo: str, branch: str, sha: str, *, exists: bool) -> None:
        assert branch != self.base
        self.refs[branch] = sha

    def open_pull(self, repo: str, branch: str) -> dict[str, Any] | None:
        return next((p for p in self.pulls if p["head"] == branch and p["state"] == "open"), None)

    def create_pull(
        self, repo: str, *, title: str, body: str, head: str, base: str
    ) -> dict[str, Any]:
        n = len(self.pulls) + 1
        pr = {
            "number": n,
            "title": title,
            "body": body,
            "head": head,
            "base": base,
            "state": "open",
            "html_url": f"https://github.test/{repo}/pull/{n}",
        }
        self.pulls.append(pr)
        return pr

    def update_pull(self, repo: str, number: int, *, title: str, body: str) -> None:
        self.pulls[number - 1].update(title=title, body=body)

    def close_pull(self, repo: str, number: int, comment: str) -> None:
        self.pulls[number - 1]["state"] = "closed"

    def add_labels(self, repo: str, number: int, labels: list[str]) -> None:
        self.pulls[number - 1]["labels"] = labels

    def upsert_issue(self, repo: str, marker: str, title: str, body: str) -> str:
        self.issues = [i for i in self.issues if marker not in i["body"]]
        self.issues.append({"repo": repo, "title": title, "body": body})
        return f"https://github.test/{repo}/issues/1"


def repo_files(root: Path) -> dict[str, bytes]:
    return {
        p.relative_to(root).as_posix(): p.read_bytes()
        for p in sorted(root.rglob("*"))
        if p.is_file()
    }


def run(
    tmp_path: Path,
    *,
    mode: str = "plan",
    model: Any = None,
    github: FakeGitHub | None = None,
    source: Path = FIXTURES / "source",
    build: bool = False,
    cache: Path | None = None,
) -> tuple[int, Any, Path, Path]:
    cfg = config.load_config(FIXTURES / "config.yml")
    if github is not None:
        cfg = config.parse_config(
            config.load_yaml(FIXTURES / "config.yml")
            | {"report": {"issueRepo": "example-org/docs-distributor"}}
        )
    mapping = config.load_mapping(FIXTURES / "mapping.yml", VOCAB)
    llm = LLM(model or FakeModel(), Cache(cache or tmp_path / "cache"), sleep=lambda s: None)
    ctx = pipeline.Context(
        cfg,
        mapping,
        config.load_allow(),
        VOCAB,
        load_tech_vocabulary(),
        llm,
        {},
        tmp_path,
        github,  # type: ignore[arg-type]
    )
    fetched = [(cfg.sources[0], load_local(cfg.sources[0], source))]
    checkout = pipeline.copy_checkout(FIXTURES / "docs-repo", tmp_path / "checkout")
    out = tmp_path / "out"
    code, rep = pipeline.run(
        ctx, fetched, checkout, mode=mode, build=build, out_dir=out, report_dir=tmp_path / "reports"
    )
    return code, rep, out, checkout


# --- plan -> golden ----------------------------------------------------------------------


def test_plan_against_the_fixture_corpus_produces_the_golden_tree(tmp_path: Path) -> None:
    code, rep, out, checkout = run(tmp_path)
    assert code == pipeline.EXIT_OK, rep
    produced = repo_files(out) | {"mkdocs.yml": (checkout / "mkdocs.yml").read_bytes()}
    if os.environ.get("UPDATE_GOLDEN"):
        shutil.rmtree(GOLDEN, ignore_errors=True)
        for path, data in produced.items():
            (GOLDEN / path).parent.mkdir(parents=True, exist_ok=True)
            (GOLDEN / path).write_bytes(data)
    assert produced == repo_files(GOLDEN)


def test_golden_tree_passes_the_gate_and_carries_no_synthetic_real_value() -> None:
    mapping = config.load_mapping(FIXTURES / "mapping.yml", VOCAB)
    rules = config.build_rules(mapping, config.load_allow(), VOCAB)
    result = audit.audit_tree(GOLDEN, rules)
    assert result.findings == []


def test_plan_is_byte_identical_on_a_second_run(tmp_path: Path) -> None:
    cache = tmp_path / "shared-cache"
    _, _, first, _ = run(tmp_path / "one", cache=cache)
    model = FakeModel()
    _, _, second, _ = run(tmp_path / "two", cache=cache, model=model)
    assert repo_files(first) == repo_files(second)
    assert model.calls == []  # everything came from the cache


def test_strict_mkdocs_build_passes_on_the_generated_section(tmp_path: Path) -> None:
    pytest.importorskip("mkdocs")
    code, rep, _, _ = run(tmp_path, build=True)
    assert code == pipeline.EXIT_OK, rep.verify
    assert rep.verify["mkdocs"] == "passed"


# --- the gate catches every planted leak --------------------------------------------------

PLANTED = {
    "full-literal.md": "literal",
    "truncated-literal.md": "literal-truncated",
    "new-domain.md": "domain",
    "account-id.md": "account-12",
    "public-ip.md": "ipv4-public",
    "age-recipient.md": "age-recipient",
    "name-in-code-comment.md": "literal",
}


def test_audit_catches_every_planted_leak() -> None:
    mapping = config.load_mapping(FIXTURES / "mapping.yml", VOCAB)
    rules = config.build_rules(mapping, config.load_allow(), VOCAB)
    files = repo_files(FIXTURES / "planted")
    result = audit.audit_files(files, rules)
    caught = {f.path: f.rule for f in result.findings}
    assert set(caught) == set(PLANTED), caught
    for path, rule in PLANTED.items():
        assert rule in {f.rule for f in result.findings if f.path == path}, path


# --- sync is idempotent -------------------------------------------------------------------


def test_sync_twice_against_unchanged_sources_opens_one_pr_and_pushes_once(tmp_path: Path) -> None:
    gh = FakeGitHub(repo_files(FIXTURES / "docs-repo"))
    cache = tmp_path / "cache"
    code, rep, _, _ = run(tmp_path / "a", mode="sync", github=gh, cache=cache)
    assert code == pipeline.EXIT_OK, rep
    assert rep.publish["action"] == "created"
    head = gh.refs["docs/sync-upstream"]
    code, rep, _, _ = run(tmp_path / "b", mode="sync", github=gh, cache=cache)
    assert code == pipeline.EXIT_OK
    assert rep.publish["action"] == "up-to-date"
    assert gh.refs["docs/sync-upstream"] == head
    assert len(gh.pulls) == 1 and len(gh.commits) == 2
    assert gh.refs["main"] == "c0"  # the default branch is never written


def test_published_branch_carries_exactly_the_golden_tree(tmp_path: Path) -> None:
    gh = FakeGitHub(repo_files(FIXTURES / "docs-repo"))
    run(tmp_path, mode="sync", github=gh)
    files = gh.trees[gh.commits[gh.refs["docs/sync-upstream"]][0]]
    section = {p: b for p, b in files.items() if p.startswith("docs/hollow-cloud/")}
    assert section == {p: b for p, b in repo_files(GOLDEN).items() if p.startswith("docs/")}
    assert files["mkdocs.yml"] == (GOLDEN / "mkdocs.yml").read_bytes()


# --- a novel sensitive noun fails closed ------------------------------------------------


def test_novel_sensitive_noun_publishes_nothing_and_files_a_redacted_proposal(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    shutil.copytree(FIXTURES / "source", source)
    page = source / "docs" / "operations" / "runbook.md"
    page.write_text(page.read_text().replace("one context at a time", "for Zwartewater first"))
    gh = FakeGitHub(repo_files(FIXTURES / "docs-repo"))
    code, rep, out, _ = run(
        tmp_path, mode="sync", github=gh, source=source, model=FakeModel(frozenset({"zwartewater"}))
    )
    assert code == pipeline.EXIT_BLOCKED
    assert gh.pulls == [] and len(gh.commits) == 1 and not out.exists()
    (issue,) = gh.issues
    assert "Zwartewater" not in issue["body"] and "zwartewater" not in issue["body"].casefold()
    assert "`client-k`" in issue["body"]
    proposal = (tmp_path / "reports" / rep.run_id / "mapping-proposal.yml").read_text()
    assert "Zwartewater" in proposal and "client-k" in proposal
    assert (
        oct((tmp_path / "reports" / rep.run_id / "mapping-proposal.yml").stat().st_mode)[-3:]
        == "600"
    )


def test_terms_nobody_classified_block_the_run_too(tmp_path: Path) -> None:
    class Down(FakeModel):
        def complete(self, template: Template, user: str) -> Any:
            from docs_distributor.llm import LLMError

            raise LLMError("gateway down")

    code, rep, _, _ = run(tmp_path, model=Down())
    assert code == pipeline.EXIT_BLOCKED
    assert any(s.undecided for s in rep.sources)
