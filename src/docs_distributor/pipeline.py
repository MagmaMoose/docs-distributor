"""One run, in the order the README documents.

    fetch -> transform -> nav -> novelty (classify) -> [blocked: propose, issue, stop]
          -> repair -> audit -> verify -> audit the outbound text -> publish -> notify

Every stage that can fail the run fails it closed: nothing reaches the docs repo unless all
of them passed. Exit codes say which stage stopped it, so a CronJob's status is readable at a
glance:

    0  published, or nothing to publish
    2  blocked: sensitive or unclassified terms without a mapping (a proposal was filed)
    3  the leak audit failed
    4  verification failed (line parity, links, mkdocs build --strict)
    5  configuration or mapping error
    6  a fetch or an API call failed
"""

from __future__ import annotations

import os
import shutil
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from docs_distributor import audit, nav, report
from docs_distributor.config import (
    AllowRules,
    Config,
    PrivateMapping,
    SourceConfig,
    SourcePrivate,
    Vocabulary,
    build_rules,
)
from docs_distributor.github import GitHub, GitHubError, blob_sha, token_for
from docs_distributor.llm import LLM, Decision
from docs_distributor.novelty import Candidate, Lexicon, scan
from docs_distributor.publish import Outcome, changes_for, publish
from docs_distributor.sources import FetchedSource
from docs_distributor.transform import Damage, Substituter, TreeOut, transform_tree
from docs_distributor.verify import VerifyResult, check_links, line_parity, mkdocs_build

EXIT_OK, EXIT_BLOCKED, EXIT_AUDIT, EXIT_VERIFY, EXIT_CONFIG, EXIT_RUNTIME = 0, 2, 3, 4, 5, 6

PROSE_DAMAGE = {
    "doubled-word": "a word is doubled",
    "redundant-parenthetical": "a parenthetical repeats what precedes it",
    "article": '"a"/"an" no longer agrees with the next word',
}


@dataclass
class Context:
    cfg: Config
    mapping: PrivateMapping
    allow: AllowRules
    vocabulary: Vocabulary
    tech: frozenset[str]
    llm: LLM
    environ: Mapping[str, str]
    workdir: Path
    #: injected in tests; built from the target's auth otherwise
    github: GitHub | None = None

    def github_for(self, repo: str) -> GitHub:
        if self.github is not None:
            return self.github
        auth = self.cfg.target.auth
        return GitHub(auth.api_url, token_for(auth, self.environ, repo=repo))


@dataclass
class SourceOut:
    cfg: SourceConfig
    fetched: FetchedSource
    tree: TreeOut
    files: dict[str, bytes]
    nodes: list[nav.Node]
    report: report.SourceReport
    candidates: list[Candidate] = field(default_factory=list)


# --- stages ------------------------------------------------------------------------------


def transform_source(ctx: Context, src: SourceConfig, fetched: FetchedSource) -> SourceOut:
    sub = Substituter(ctx.mapping.rules)
    private = ctx.mapping.sources.get(src.name, SourcePrivate())
    tree = transform_tree(
        fetched.docs,
        target_dir=src.target,
        substituter=sub,
        include=src.include,
        exclude=src.exclude,
        drop=private.drop,
        rename=private.rename,
        private_hosts=ctx.mapping.private_hosts,
        # Short values would call half of all public URLs private; four characters is where
        # a value stops being a substring of ordinary words.
        real_values=[v for v in ctx.mapping.mapped_terms() if len(v) >= 4],
        cleared_binaries={b.path: b.sha256 for b in private.binaries},
    )
    files = {p: fo.content for p, fo in tree.files.items()}
    rep = report.SourceReport(
        name=src.name,
        title=src.title,
        target=src.target,
        revision=fetched.revision,
        pages=sum(1 for p in files if p.endswith(".md")),
        dropped=len(tree.dropped),
        replacements=sum(fo.replacements for fo in tree.files.values()),
        private_links=tree.links.private,
        images_omitted=tree.links.images_omitted,
        warnings=list(tree.warnings),
    )
    nodes = build_nav(ctx, src, fetched, tree, files, sub, rep)
    return SourceOut(src, fetched, tree, files, nodes, rep)


def _heading(text: str, fallback: str) -> str:
    for line in text.splitlines():
        if line.startswith("# "):
            return line[2:].strip()
    return fallback.replace("-", " ").capitalize()


def build_nav(
    ctx: Context,
    src: SourceConfig,
    fetched: FetchedSource,
    tree: TreeOut,
    files: Mapping[str, bytes],
    sub: Substituter,
    rep: report.SourceReport,
) -> list[nav.Node]:
    prefix = src.target.removeprefix("docs/")
    nodes, dropped = nav.rebuild(
        nav.parse(fetched.nav),
        path_map=tree.path_map,
        rename_title=lambda t: sub.apply(t).text,
        prefix=prefix,
    )
    if dropped:
        rep.warnings.append(f"{len(dropped)} nav entries point at pages that are not published")
    listed = set(nav.pages(nodes))
    index = f"{prefix}/index.md"
    unlisted = sorted(
        f"{prefix}/{rel}"
        for rel in tree.path_map.values()
        if rel.endswith(".md") and f"{prefix}/{rel}" not in listed and f"{prefix}/{rel}" != index
    )
    if unlisted:
        headings = [
            (p, _heading(files[f"docs/{p}"].decode("utf-8"), Path(p).stem)) for p in unlisted
        ]
        placed = ctx.llm.place(headings, nav.sections(nodes))
        for path, heading in headings:
            choice = placed.get(path)
            if choice is not None:
                nav.place(nodes, path, choice.title, choice.section)
            else:
                nav.place(
                    nodes,
                    path,
                    heading,
                    nav.fallback_section(nodes, path.removeprefix(prefix + "/")),
                )
    if f"docs/{index}" in files:
        nodes = nav.section_index_first(nodes, index)
    return nodes


def nav_text(out: SourceOut) -> str:
    return "\n".join(nav.render([nav.Node(out.cfg.title, None, out.nodes)], "")) + "\n"


def classify(ctx: Context, outs: Sequence[SourceOut]) -> dict[str, Decision]:
    lexicon = Lexicon.build(
        tech=ctx.tech,
        allow=ctx.allow.terms | ctx.mapping.allow.terms,
        placeholder_values=ctx.vocabulary.all_values() | {r.target for r in ctx.mapping.rules},
        languages=ctx.cfg.languages,
    )
    everyone: list[Candidate] = []
    for out in outs:
        md = {p: b.decode("utf-8") for p, b in out.files.items() if p.endswith(".md")}
        out.candidates = scan(md, lexicon, extra_texts={f"nav {out.cfg.name}": nav_text(out)})
        out.report.candidates = len(out.candidates)
        everyone.extend(out.candidates)
    decisions = ctx.llm.classify(everyone)
    for out in outs:
        for cand in out.candidates:
            d = decisions.get(cand.term.casefold())
            if d is None:
                out.report.undecided.append(cand.term)
            elif d.sensitive:
                out.report.sensitive.append(
                    {"term": cand.term, "category": d.category, "where": cand.where}
                )
            else:
                out.report.admitted.append(cand.term)
        out.report.admitted = sorted(set(out.report.admitted), key=str.casefold)
    return decisions


def propose(ctx: Context, outs: Sequence[SourceOut]) -> None:
    taken = [r.target for r in ctx.mapping.rules]
    for out in outs:
        terms = [(s["term"], s["category"]) for s in out.report.sensitive]
        terms += [(t, "other") for t in out.report.undecided]
        for p in ctx.llm.propose(terms, ctx.vocabulary, taken):
            out.report.proposals.append(
                {"term": p.term, "class": p.cls, "to": p.to, "origin": p.origin}
            )
            if p.to:
                taken.append(p.to)


def repair(ctx: Context, out: SourceOut) -> None:
    placeholders = sorted({r.target for r in ctx.mapping.rules if r.target}, key=len, reverse=True)
    for path, fo in sorted(out.tree.files.items()):
        prose = [d for d in fo.damage if d.kind in PROSE_DAMAGE]
        for d in fo.damage:
            if d.kind not in PROSE_DAMAGE:
                out.report.unrepaired.append(f"{d.path}:{d.line} {d.kind}")
        if not prose:
            continue
        lines = out.files[path].decode("utf-8").splitlines(keepends=True)
        groups: dict[tuple[int, int], list[Damage]] = {}
        for d in prose:
            groups.setdefault((d.block_start, d.block_end), []).append(d)
        for (start, end), items in sorted(groups.items(), reverse=True):
            para = "".join(lines[start - 1 : end - 1])
            issues = [f"line {d.line - start + 1}: {PROSE_DAMAGE[d.kind]}" for d in items]
            present = [p for p in placeholders if p in para]
            fixed = ctx.llm.repair(para, issues, present)
            if fixed is None:
                out.report.unrepaired.extend(f"{d.path}:{d.line} {d.kind}" for d in items)
                continue
            if para.endswith("\n") and not fixed.endswith("\n"):
                fixed += "\n"
            lines[start - 1 : end - 1] = fixed.splitlines(keepends=True)
            out.report.repaired += len(items)
        out.files[path] = "".join(lines).encode("utf-8")


def gate(
    ctx: Context,
    files: Mapping[str, bytes],
    outs: Sequence[SourceOut],
    decisions: Mapping[str, Decision] | None,
    extra: Mapping[str, str],
) -> audit.AuditResult:
    rules = build_rules(ctx.mapping, ctx.allow, ctx.vocabulary)
    novelty = None
    if decisions is not None:
        novelty = audit.Novelty(
            candidates=tuple(
                audit.NoveltyCandidate(c.term, c.where) for o in outs for c in o.candidates
            ),
            decisions={
                k: audit.NoveltyDecision(d.sensitive, d.origin) for k, d in decisions.items()
            },
        )
    return audit.audit_files(
        files,
        rules,
        cleared_binaries=ctx.mapping.cleared_binaries(),
        novelty=novelty,
        extra_texts=extra,
    )


# --- the docs repo -------------------------------------------------------------------------


@dataclass
class Staged:
    checkout: Path
    changes: dict[str, bytes | None]
    current_blobs: dict[str, str]
    summary: dict[str, list[str]]
    verify: VerifyResult


def stage(ctx: Context, outs: Sequence[SourceOut], checkout: Path, *, build: bool) -> Staged:
    """Apply the generated tree and nav to a docs-repo checkout, and verify it there."""
    cfg = ctx.cfg
    managed = [o.cfg.target for o in outs]
    mk_path = cfg.target.mkdocs
    mk_text = (checkout / mk_path).read_text(encoding="utf-8")
    for out in outs:
        mk_text = nav.splice(
            mk_text,
            out.cfg.name,
            lambda indent, out=out: nav.block(out.cfg.name, out.cfg.title, out.nodes, indent),  # type: ignore[misc]
            cfg.target.nav_after,
        )
    generated: dict[str, bytes] = {p: b for o in outs for p, b in o.files.items()}
    generated[mk_path] = mk_text.encode("utf-8")
    current: dict[str, bytes] = {}
    for d in [*managed, mk_path]:
        root = checkout / d
        if root.is_file():
            current[d] = root.read_bytes()
        elif root.is_dir():
            for p in root.rglob("*"):
                if p.is_file():
                    current[p.relative_to(checkout).as_posix()] = p.read_bytes()
    changes = changes_for(current, generated, managed)
    for path, data in changes.items():
        target = checkout / path
        if data is None:
            target.unlink(missing_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
    summary = {
        "added": sorted(p for p, d in changes.items() if d is not None and p not in current),
        "updated": sorted(p for p, d in changes.items() if d is not None and p in current),
        "removed": sorted(p for p, d in changes.items() if d is None),
    }
    result = VerifyResult()
    for out in outs:
        result.parity += line_parity(out.fetched.docs, out.files, out.tree.path_map, out.cfg.target)
    known = {p.relative_to(checkout).as_posix() for p in checkout.rglob("*") if p.is_file()}
    md = {p: b.decode("utf-8") for o in outs for p, b in o.files.items() if p.endswith(".md")}
    result.links, result.anchors = check_links(md, known)
    if build and not result.parity and not result.links:
        result.mkdocs, result.mkdocs_log = mkdocs_build(checkout)
    return Staged(checkout, changes, {p: blob_sha(b) for p, b in current.items()}, summary, result)


# --- the run -----------------------------------------------------------------------------


def run(
    ctx: Context,
    fetched: Sequence[tuple[SourceConfig, FetchedSource]],
    checkout: Path,
    *,
    mode: str,
    build: bool = True,
    out_dir: Path | None = None,
    report_dir: Path,
) -> tuple[int, report.RunReport]:
    rep = report.RunReport(mode=mode)
    report.log("run.start", run=rep.run_id, mode=mode, sources=[s.name for s, _ in fetched])

    def finish(code: int, status: str) -> tuple[int, report.RunReport]:
        rep.exit_code, rep.status = code, status
        rep.llm = {
            "calls": ctx.llm.stats.calls,
            "cache_hits": ctx.llm.stats.hits,
            "rejected": ctx.llm.stats.rejected,
            "failed": ctx.llm.stats.failed,
        }
        where = rep.write(report_dir)
        report.log("run.finish", run=rep.run_id, status=status, exit=code, report=str(where))
        return code, rep

    outs = [transform_source(ctx, src, f) for src, f in fetched]
    rep.sources = [o.report for o in outs]
    for o in outs:
        report.log(
            "transform",
            source=o.cfg.name,
            pages=o.report.pages,
            dropped=o.report.dropped,
            replacements=o.report.replacements,
            private_links=o.report.private_links,
        )

    decisions = classify(ctx, outs)
    blocked = sum(len(o.report.sensitive) + len(o.report.undecided) for o in outs)
    report.log("novelty", candidates=sum(o.report.candidates for o in outs), blocked=blocked)
    if blocked:
        propose(ctx, outs)
        code, rep = finish(EXIT_BLOCKED, "blocked")
        notify_blocked(ctx, rep, mode)
        return code, rep

    for o in outs:
        repair(ctx, o)

    files = {p: b for o in outs for p, b in o.files.items()}
    result = gate(ctx, files, outs, decisions, {f"nav {o.cfg.name}": nav_text(o) for o in outs})
    rep.audit = report.findings_record(result)
    report.log("audit", passed=result.passed(), layers=result.layers, findings=len(result.findings))
    if not result.passed():
        code, rep = finish(EXIT_AUDIT, "audit-failed")
        notify(
            ctx,
            f"docs-distributor: the leak audit stopped the sync ({len(result.findings)} "
            "findings). Nothing was published.",
        )
        return code, rep

    staged = stage(ctx, outs, checkout, build=build)
    rep.changes = staged.summary
    rep.verify = {
        "parity": staged.verify.parity,
        "links": staged.verify.links,
        "anchors": staged.verify.anchors,
        "mkdocs": staged.verify.mkdocs,
        "log": staged.verify.mkdocs_log,
    }
    for o in outs:
        o.report.warnings += [a for a in staged.verify.anchors if a.startswith(o.cfg.target)]
    report.log(
        "verify",
        passed=staged.verify.passed,
        mkdocs=staged.verify.mkdocs,
        parity=len(staged.verify.parity),
        links=len(staged.verify.links),
        **{k: len(v) for k, v in staged.summary.items()},
    )
    if not staged.verify.passed:
        code, rep = finish(EXIT_VERIFY, "verify-failed")
        notify(
            ctx,
            "docs-distributor: verification failed (parity, links or mkdocs --strict). "
            "Nothing was published.",
        )
        return code, rep

    if out_dir is not None:
        for path, data in files.items():
            (out_dir / path).parent.mkdir(parents=True, exist_ok=True)
            (out_dir / path).write_bytes(data)

    title, body, commit = report.pull_request_text(rep.sources, staged.summary)
    branch = ctx.cfg.target.branch_prefix + "upstream"
    outbound = gate(
        ctx,
        {},
        outs,
        None,
        {
            "pull request title": title,
            "pull request body": body,
            "commit message": commit,
            "branch": branch,
        },
    )
    if not outbound.passed(required=("literal", "patterns")):
        rep.audit["outbound"] = report.findings_record(outbound)
        return finish(EXIT_AUDIT, "audit-failed")

    if mode != "sync":
        return finish(EXIT_OK, "planned")

    try:
        outcome = publish_changes(ctx, staged, title=title, body=body, commit=commit, branch=branch)
    except GitHubError as exc:
        report.log("publish.error", error=str(exc))
        return finish(EXIT_RUNTIME, "publish-failed")
    rep.publish = {"action": outcome.action, "branch": outcome.branch, "pr": outcome.pr_url}
    code, rep = finish(EXIT_OK, outcome.action)
    if outcome.action in ("created", "updated", "closed"):
        notify(ctx, f"docs-distributor: {outcome.action} {outcome.pr_url}")
    return code, rep


def publish_changes(
    ctx: Context, staged: Staged, *, title: str, body: str, commit: str, branch: str
) -> Outcome:
    t = ctx.cfg.target
    gh = ctx.github_for(t.repo)
    base = t.base or gh.default_branch(t.repo)
    return publish(
        gh,
        t.repo,
        base=base,
        branch=branch,
        branch_prefix=t.branch_prefix,
        changes=staged.changes,
        current_blobs=staged.current_blobs,
        title=title,
        body=body,
        commit_message=commit,
        labels=t.labels,
    )


def notify(ctx: Context, text: str) -> None:
    env = ctx.cfg.report.slack_webhook_env
    if env:
        report.slack(ctx.environ.get(env), text)


def notify_blocked(ctx: Context, rep: report.RunReport, mode: str) -> None:
    title, body = report.novelty_issue(rep.run_id, rep.sources)
    # The issue goes to a public repository. It carries no term by construction; the gate
    # checks that anyway, against the full mapping and every sensitive term.
    rules = build_rules(ctx.mapping, ctx.allow, ctx.vocabulary)
    sensitive = [
        audit.Literal(s["term"], "sensitive term") for src in rep.sources for s in src.sensitive
    ]
    sensitive += [audit.Literal(t, "undecided term") for src in rep.sources for t in src.undecided]
    rules = audit.Rules(
        literals=(*rules.literals, *sensitive), allow=rules.allow, placeholders=rules.placeholders
    )
    if audit.audit_files({}, rules, extra_texts={"issue": title + "\n" + body}).findings:
        report.log("issue.withheld", reason="issue text failed the audit")
        return
    url = None
    repo = ctx.cfg.report.issue_repo
    if mode == "sync" and repo:
        try:
            url = ctx.github_for(repo).upsert_issue(repo, report.NOVELTY_MARKER, title, body)
        except GitHubError as exc:
            report.log("issue.error", error=str(exc))
    report.log("blocked", issue=url, proposals=sum(len(s.proposals) for s in rep.sources))
    notify(
        ctx,
        f"docs-distributor: sync blocked, new terms need a mapping. {url or 'See the run report.'}",
    )


def copy_checkout(src: Path, dest: Path) -> Path:
    """A throwaway copy of a local docs checkout: a plan never edits the user's working tree."""
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(
        src, dest, ignore=shutil.ignore_patterns(".git", "site", "node_modules", ".venv")
    )
    return dest


def default_local_dir(name: str) -> Path:
    base = (
        Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "docs-distributor" / name
    )
    base.mkdir(parents=True, exist_ok=True)
    return base
