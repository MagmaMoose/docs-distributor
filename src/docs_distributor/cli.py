"""docs-distributor command line.

plan     transform, classify, audit and verify; print what would change; publish nothing
sync     plan, then open or update the pull request (what the CronJob runs)
audit    the gate on its own, over any directory or file list (a pre-commit hook)
onboard  first port of a new source: a proposed mapping and nav for human review
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path

import yaml

from docs_distributor import __version__, audit, config, pipeline, report
from docs_distributor.config import ConfigError, SourceConfig, SourcePrivate
from docs_distributor.github import GitHub, GitHubError, token_for
from docs_distributor.llm import LLM, Cache, Decision, Proposal, ReplayBackend, make_backend
from docs_distributor.novelty import Candidate, Lexicon, load_tech_vocabulary, scan
from docs_distributor.sources import SourceError, fetch, load_local
from docs_distributor.transform import Substituter, transform_tree

DEFAULT_CONFIG = "/etc/docs-distributor/config.yml"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="docs-distributor", description=__doc__.split("\n\n")[0])
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    for name in ("plan", "sync"):
        p = sub.add_parser(name, help=f"{name} a run")
        p.add_argument(
            "--config", default=os.environ.get("DOCS_DISTRIBUTOR_CONFIG", DEFAULT_CONFIG)
        )
        p.add_argument("--mapping", help="mapping file or mapping.d directory (PRIVATE)")
        if name == "plan":
            p.add_argument(
                "--source",
                action="append",
                default=[],
                metavar="NAME=PATH",
                help="use a local checkout for a source",
            )
            p.add_argument(
                "--docs-repo",
                type=Path,
                help="a local docs-repo checkout to plan against (copied, never edited)",
            )
            p.add_argument(
                "--offline", action="store_true", help="answer LLM calls from the cache only"
            )
            p.add_argument("--no-build", action="store_true", help="skip mkdocs build --strict")
            p.add_argument("--out", type=Path, help="write the generated tree here for inspection")
        p.add_argument("--report-dir", type=Path, help="where the PRIVATE run report goes")

    a = sub.add_parser("audit", help="run the gate over files or directories")
    a.add_argument("paths", nargs="+", type=Path)
    a.add_argument("--mapping", help="add the literal layer from this mapping (PRIVATE)")
    a.add_argument(
        "--show-matches",
        action="store_true",
        help="print matched text (do not paste the output anywhere public)",
    )
    a.add_argument(
        "--allow",
        action="append",
        default=[],
        type=Path,
        help="extra allow file(s), same format as rules/allow.yml",
    )
    a.add_argument(
        "--only",
        choices=("literal", "patterns"),
        help="run one layer; `literal` without a mapping checks nothing and passes",
    )

    o = sub.add_parser("onboard", help="propose a mapping and nav for a new source")
    o.add_argument("source", type=Path, help="a local checkout of the source repository")
    o.add_argument("--name", required=True, help="the public alias, e.g. cloud-platform")
    o.add_argument("--docs-dir", default="docs")
    o.add_argument("--mapping", help="an existing mapping to extend (PRIVATE)")
    o.add_argument("--out", type=Path, required=True, help="where to write the PRIVATE proposal")
    o.add_argument(
        "--offline", action="store_true", help="no LLM: list candidates for a human to classify"
    )
    o.add_argument("--config", default=os.environ.get("DOCS_DISTRIBUTOR_CONFIG"))

    args = parser.parse_args(argv)
    try:
        if args.command == "audit":
            return cmd_audit(args)
        if args.command == "onboard":
            return cmd_onboard(args)
        return cmd_run(args)
    except ConfigError as exc:
        report.log("config.error", source=exc.source, problems=exc.problems)
        return pipeline.EXIT_CONFIG
    except (SourceError, GitHubError) as exc:
        report.log("runtime.error", error=str(exc))
        return pipeline.EXIT_RUNTIME


def _mapping(
    explicit: str | None, vocabulary: config.Vocabulary, required: bool
) -> config.PrivateMapping | None:
    path = config.resolve_mapping_path(explicit)
    if path is None:
        if required:
            raise ConfigError("mapping", ["no mapping found: pass --mapping or mount the secret"])
        return None
    return config.load_mapping(path, vocabulary)


def cmd_run(args: argparse.Namespace) -> int:
    cfg = config.load_config(Path(args.config))
    vocabulary = config.load_vocabulary()
    mapping = _mapping(args.mapping, vocabulary, required=True)
    assert mapping is not None  # noqa: S101 — required=True raised otherwise
    allow = config.load_allow()
    local = dict(s.split("=", 1) for s in getattr(args, "source", []))
    in_cluster = args.command == "sync"
    report_dir = args.report_dir or (
        Path(cfg.report.dir) if in_cluster else pipeline.default_local_dir("reports")
    )
    cache_dir = Path(cfg.cache_dir) if in_cluster else pipeline.default_local_dir("llm-cache")
    workdir = Path(
        tempfile.mkdtemp(
            prefix="docs-distributor-",
            dir=cfg.work_dir if in_cluster and Path(cfg.work_dir).exists() else None,
        )
    )

    backend = (
        ReplayBackend(cfg.llm.model)
        if getattr(args, "offline", False)
        else make_backend(cfg.llm, workdir)
    )
    llm = LLM(backend, Cache(cache_dir), batch_size=cfg.llm.batch_size)
    ctx = pipeline.Context(
        cfg, mapping, allow, vocabulary, load_tech_vocabulary(), llm, os.environ, workdir
    )

    fetched = []
    for src in cfg.sources:
        if src.name in local:
            fetched.append((src, load_local(src, Path(local[src.name]))))
            continue
        url = src.url or mapping.sources.get(src.name, SourcePrivate()).url
        if not url:
            raise ConfigError(
                "sources", [f"{src.name}: no url in values or in the private mapping"]
            )
        fetched.append((src, fetch(src, url, token_for(src.auth, os.environ, repo=None), workdir)))
        report.log("fetch", source=src.name)

    checkout = docs_checkout(cfg, getattr(args, "docs_repo", None), workdir)
    code, rep = pipeline.run(
        ctx,
        fetched,
        checkout,
        mode=args.command,
        build=not getattr(args, "no_build", False),
        out_dir=getattr(args, "out", None),
        report_dir=report_dir,
    )
    if args.command == "plan":
        print_plan(rep)
    return code


def docs_checkout(cfg: config.Config, local: Path | None, workdir: Path) -> Path:
    dest = workdir / "docs-repo"
    if local is not None:
        return pipeline.copy_checkout(local, dest)
    t = cfg.target
    gh = GitHub(
        t.auth.api_url,
        token_for(t.auth, os.environ, repo=t.repo) if t.auth.kind != "none" else None,
    )
    base = t.base or gh.default_branch(t.repo)
    head = gh.branch_head(t.repo, base)
    return gh.download(t.repo, head or base, dest)


def print_plan(rep: report.RunReport) -> None:
    out = sys.stderr
    out.write(f"\nrun {rep.run_id}: {rep.status}\n")
    for s in rep.sources:
        out.write(
            f"  {s.name}: {s.pages} pages, {s.replacements} substitutions, "
            f"{s.private_links} private links, {s.candidates} candidates "
            f"({len(s.admitted)} public, {len(s.sensitive)} sensitive, "
            f"{len(s.undecided)} undecided), {s.repaired} repaired, "
            f"{len(s.unrepaired)} left as is\n"
        )
    for kind, paths in rep.changes.items():
        out.write(f"  {kind}: {len(paths)}\n")
    if rep.audit.get("findings"):
        out.write("  audit:\n")
        for f in rep.audit["findings"][:40]:
            out.write(
                f"    {f['path']}:{f['line']} layer {f['layer']} {f['rule']}: {f['detail']}\n"
            )
    if rep.verify.get("parity") or rep.verify.get("links"):
        for line in rep.verify["parity"] + rep.verify["links"]:
            out.write(f"    {line}\n")
    if rep.verify.get("mkdocs") == "failed":
        out.write(rep.verify.get("log", "") + "\n")


def cmd_audit(args: argparse.Namespace) -> int:
    vocabulary = config.load_vocabulary()
    mapping = _mapping(args.mapping, vocabulary, required=False)
    allow = config.load_allow()
    for extra in args.allow:
        more = config.load_allow(extra)
        allow = config.AllowRules(
            audit.Allowlist(allow.allowlist.entries + more.allowlist.entries),
            allow.terms | more.terms,
        )
    rules = config.build_rules(mapping, allow, vocabulary)
    files: dict[str, bytes] = {}
    for p in args.paths:
        if p.is_dir():
            files |= {f"{p.as_posix().rstrip('/')}/{k}": v for k, v in audit.read_tree(p).items()}
        elif p.is_file():
            files[p.as_posix()] = p.read_bytes()
    if args.only == "literal":
        if mapping is None:
            sys.stdout.write("no mapping: the literal layer has nothing to check\n")
            return 0
        rules = audit.Rules(literals=rules.literals)
    result = audit.audit_files(
        files, rules, cleared_binaries=mapping.cleared_binaries() if mapping else frozenset()
    )
    if args.only == "literal":
        result.findings = [f for f in result.findings if f.layer == 1]
    elif args.only == "patterns":
        result.findings = [f for f in result.findings if f.layer == 2]
    required: tuple[str, ...] = ("literal", "patterns") if mapping else ("patterns",)
    if args.only:
        required = (args.only,)
    for f in result.findings:
        line = f.public()
        if args.show_matches:
            line += f"  [{f.match}]"
        elif f.layer == 2:
            line += f"  [{f.masked()}]"
        sys.stdout.write(line + "\n")
    sys.stdout.write(
        f"{result.files} files, {len(result.findings)} findings; "
        + ", ".join(f"{k}: {v}" for k, v in result.layers.items())
        + "\n"
    )
    return 0 if result.passed(required=required) else pipeline.EXIT_AUDIT


def cmd_onboard(args: argparse.Namespace) -> int:
    """First port of a source. Writes a PRIVATE proposal: every candidate with its decision
    and a proposed stand-in, for a human to review before it goes into the mapping secret."""
    vocabulary = config.load_vocabulary()
    mapping = _mapping(args.mapping, vocabulary, required=False) or config.PrivateMapping()
    allow = config.load_allow()
    src = SourceConfig(
        name=args.name, target=f"docs/{args.name}", title=args.name, docs_dir=args.docs_dir
    )
    fetched = load_local(src, args.source)
    sub = Substituter(mapping.rules)
    tree = transform_tree(
        fetched.docs, target_dir=src.target, substituter=sub, include=("**/*.md",)
    )
    md = {p: fo.content.decode("utf-8") for p, fo in tree.files.items() if p.endswith(".md")}
    lexicon = Lexicon.build(
        tech=load_tech_vocabulary(),
        allow=allow.terms | mapping.allow.terms,
        placeholder_values=vocabulary.all_values() | {r.target for r in mapping.rules},
    )
    candidates = scan(md, lexicon)
    decisions: dict[str, Decision] = {}
    proposals: dict[str, Proposal] = {}
    if not args.offline:
        cfg = (
            config.load_config(Path(args.config))
            if args.config
            else config.parse_config({"target": {"repo": "none/none"}, "sources": []})
        )
        workdir = Path(tempfile.mkdtemp(prefix="docs-distributor-onboard-"))
        llm = LLM(
            make_backend(cfg.llm, workdir),
            Cache(pipeline.default_local_dir("llm-cache")),
            batch_size=cfg.llm.batch_size,
        )
        decisions = dict(llm.classify(candidates))
        sensitive = [
            (c.term, decisions[c.term.casefold()].category)
            for c in candidates
            if c.term.casefold() in decisions and decisions[c.term.casefold()].sensitive
        ]
        proposals = {
            p.term: p for p in llm.propose(sensitive, vocabulary, [r.target for r in mapping.rules])
        }
    write_onboarding(args.out, candidates, decisions, proposals)
    report.log(
        "onboard",
        source=args.name,
        candidates=len(candidates),
        classified=len(decisions),
        proposals=len(proposals),
        out=str(args.out),
    )
    return 0


def write_onboarding(
    path: Path,
    candidates: Sequence[Candidate],
    decisions: Mapping[str, Decision],
    proposals: Mapping[str, Proposal],
) -> None:
    rules: list[dict[str, str]] = []
    public: list[dict[str, str]] = []
    review: list[dict[str, object]] = []
    for c in candidates:
        d = decisions.get(c.term.casefold())
        if d is None:
            review.append(
                {"term": c.term, "count": c.count, "where": c.where, "context": list(c.contexts)}
            )
        elif d.sensitive:
            p = proposals.get(c.term)
            rules.append(
                {
                    "from": c.term,
                    "to": (p.to if p else "") or "TODO",
                    "class": p.cls if p else "other",
                    "why": d.reason,
                }
            )
        else:
            public.append({"term": c.term, "category": d.category, "why": d.reason})
    doc = {"rules": rules, "judged_public": public, "needs_review": review}
    header = (
        "# PRIVATE: an onboarding proposal for docs-distributor. It names real terms.\n"
        "# Review it, move accepted `rules` into the mapping secret, add the public terms you\n"
        "# agree with to the mapping's `allow:` (class: term), and delete this file.\n"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        header + yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, width=100),
        encoding="utf-8",
    )
    os.chmod(path, 0o600)


if __name__ == "__main__":
    raise SystemExit(main())
