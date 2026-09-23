"""Load and validate the four inputs: the private mapping, the committed allow and vocabulary
rules, and the runtime config.

Nothing here decides what publishes. It turns YAML into the plain objects the transform and
the audit consume, and refuses anything ambiguous: a mapping whose placeholder would itself
fail the audit, a placeholder that contains the value it replaces, an allow entry without a
justification.

The mapping is the one PRIVATE input. It is read from a mounted Secret (or a local file for
``plan``) and never written anywhere by this tool.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from docs_distributor import audit

RULE_CLASSES = frozenset(
    [
        "org",
        "repo",
        "domain",
        "host",
        "url",
        "person",
        "handle",
        "email",
        "customer",
        "vendor",
        "product",
        "project",
        "account",
        "subscription",
        "tenant",
        "uuid",
        "ip",
        "cidr",
        "path",
        "cluster",
        "namespace",
        "secret",
        "location",
        "other",
    ]
)
CASE_MODES = ("insensitive", "exact", "preserve")
BOUNDARY_MODES = ("auto", "word", "none")

# In the pod, then on a maintainer's machine. Never a path inside a repository.
DEFAULT_MAPPING_PATHS = (
    Path("/etc/docs-distributor/private/mapping.d"),
    Path("/etc/docs-distributor/private/mapping.yml"),
    Path.home() / ".config" / "docs-distributor" / "mapping.d",
    Path.home() / ".config" / "docs-distributor" / "mapping.yml",
)


class ConfigError(ValueError):
    """One or more problems in an input file. ``problems`` lists every one found."""

    def __init__(self, source: str, problems: Sequence[str]) -> None:
        self.source = source
        self.problems = list(problems)
        super().__init__(f"{source}: " + "; ".join(self.problems))


# --- YAML --------------------------------------------------------------------------------


class _Loader(yaml.SafeLoader):
    """SafeLoader that tolerates the python/name tags MkDocs configs carry.

    ``!!python/name:material.extensions.emoji.twemoji`` becomes the string after the tag. The
    tag is never executed: this loader only ever reads, and only needs the nav.
    """


def _python_tag(loader: yaml.SafeLoader, suffix: str, node: yaml.Node) -> str:
    return suffix.split(":", 1)[-1]


_Loader.add_multi_constructor("tag:yaml.org,2002:python/", _python_tag)
_Loader.add_multi_constructor("!", lambda loader, suffix, node: None)


def load_yaml(path: Path) -> Any:
    with path.open(encoding="utf-8") as fh:
        loader = _Loader(fh)  # a SafeLoader subclass: it constructs data, never objects
        try:
            return loader.get_single_data()
        finally:
            loader.dispose()


def _rules_file(name: str) -> Path:
    return Path(str(resources.files("docs_distributor") / "rules" / name))


# --- allow.yml ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AllowRules:
    allowlist: audit.Allowlist
    #: casefolded public terms the novelty scan need not ask about
    terms: frozenset[str]


def parse_allow(data: Any, source: str) -> AllowRules:
    problems: list[str] = []
    entries: list[audit.AllowEntry] = []
    terms: set[str] = set()
    raw = (data or {}).get("entries") if isinstance(data, dict) else data
    for i, item in enumerate(raw or []):
        where = f"entry {i + 1}"
        if not isinstance(item, dict):
            problems.append(f"{where}: not a mapping")
            continue
        cls = str(item.get("class", "")).strip()
        why = str(item.get("why", "")).strip()
        if not why:
            problems.append(f"{where}: `why` is required and must name a public source")
            continue
        if cls == "term":
            if not item.get("value"):
                problems.append(f"{where}: a term entry needs `value`")
            else:
                terms.add(str(item["value"]).casefold())
            continue
        known = {pc.name for pc in audit.PATTERN_CLASSES}
        if cls not in known:
            problems.append(f"{where}: unknown class {cls!r}")
            continue
        for key in ("pattern", "context"):
            if item.get(key) is not None:
                try:
                    re.compile(str(item[key]))
                except re.error as exc:
                    problems.append(f"{where}: bad {key} regex: {exc}")
        try:
            entries.append(
                audit.AllowEntry(
                    cls=cls,
                    why=why,
                    value=None if item.get("value") is None else str(item["value"]),
                    pattern=None if item.get("pattern") is None else str(item["pattern"]),
                    context=None if item.get("context") is None else str(item["context"]),
                    paths=tuple(str(p) for p in item.get("paths") or ()),
                    subdomains=bool(item.get("subdomains", True)),
                )
            )
        except ValueError as exc:
            problems.append(f"{where}: {exc}")
    if problems:
        raise ConfigError(source, problems)
    return AllowRules(audit.Allowlist(tuple(entries)), frozenset(terms))


def load_allow(path: Path | None = None) -> AllowRules:
    path = path or _rules_file("allow.yml")
    return parse_allow(load_yaml(path), str(path))


# --- vocabulary.yml ----------------------------------------------------------------------


@dataclass(frozen=True)
class PlaceholderClass:
    name: str
    values: tuple[str, ...] = ()
    series: str | None = None
    shapes: tuple[str, ...] = ()
    audit_class: str | None = None
    ranges: tuple[str, ...] = ()


@dataclass(frozen=True)
class Vocabulary:
    classes: Mapping[str, PlaceholderClass]

    def placeholders(self, extra_values: Iterable[str] = ()) -> audit.Placeholders:
        values: list[str] = [*extra_values]
        patterns: dict[str, list[str]] = {}
        domains: list[str] = []
        for pc in self.classes.values():
            values.extend(pc.values)
            if pc.audit_class == "domain":
                domains.extend(pc.values)
            if pc.audit_class:
                patterns.setdefault(pc.audit_class, []).extend(pc.shapes)
        return audit.Placeholders.build(values=values, patterns=patterns, domains=domains)

    def all_values(self) -> frozenset[str]:
        return frozenset(v.casefold() for pc in self.classes.values() for v in pc.values)


def parse_vocabulary(data: Any, source: str) -> Vocabulary:
    problems: list[str] = []
    classes: dict[str, PlaceholderClass] = {}
    for name, spec in ((data or {}).get("classes") or {}).items():
        if not isinstance(spec, dict):
            problems.append(f"class {name}: not a mapping")
            continue
        shapes = tuple(str(s) for s in spec.get("shapes") or ())
        for s in shapes:
            try:
                re.compile(s)
            except re.error as exc:
                problems.append(f"class {name}: bad shape {s!r}: {exc}")
        classes[str(name)] = PlaceholderClass(
            name=str(name),
            values=tuple(str(v) for v in spec.get("values") or ()),
            series=None if spec.get("series") is None else str(spec["series"]),
            shapes=shapes,
            audit_class=None if spec.get("audit") is None else str(spec["audit"]),
            ranges=tuple(str(r) for r in spec.get("ranges") or ()),
        )
    if problems:
        raise ConfigError(source, problems)
    return Vocabulary(classes)


def load_vocabulary(path: Path | None = None) -> Vocabulary:
    path = path or _rules_file("vocabulary.yml")
    return parse_vocabulary(load_yaml(path), str(path))


# --- mapping.yml (PRIVATE) -----------------------------------------------------------------


@dataclass(frozen=True)
class MappingRule:
    index: int  # 1-based, in load order; the only thing about a rule that is safe to log
    source: str  # the real value. PRIVATE.
    target: str
    cls: str
    case: str = "insensitive"
    boundary: str = "auto"
    regex: bool = False
    variants: tuple[str, ...] = ()
    audit_only: bool = False

    @property
    def label(self) -> str:
        return f"mapping rule {self.index} ({self.cls})"

    def literals(self) -> list[audit.Literal]:
        """What layer 1 must never see in the output for this rule."""
        if self.regex:
            return []  # a regex has no single literal; its matches are replaced in transform
        values = [self.source, *self.variants]
        lits = [audit.Literal(v, self.label) for v in values]
        if self.cls == "person":
            lits.extend(
                audit.Literal(v, self.label, boundary=True)
                for v in audit.person_variants(self.source)
                if v.casefold() not in {x.casefold() for x in values}
            )
        return lits


@dataclass(frozen=True)
class BinaryClearance:
    path: str
    sha256: str
    why: str


@dataclass(frozen=True)
class SourcePrivate:
    """Per-source settings that would identify the source if published."""

    url: str | None = None
    drop: tuple[str, ...] = ()
    rename: Mapping[str, str] = field(default_factory=dict)
    binaries: tuple[BinaryClearance, ...] = ()


@dataclass(frozen=True)
class DenyValue:
    value: str
    why: str


@dataclass(frozen=True)
class PrivateMapping:
    rules: tuple[MappingRule, ...] = ()
    sources: Mapping[str, SourcePrivate] = field(default_factory=dict)
    private_hosts: tuple[str, ...] = ()
    allow: AllowRules = field(default_factory=lambda: AllowRules(audit.Allowlist(), frozenset()))
    deny: tuple[DenyValue, ...] = ()
    files: tuple[str, ...] = ()

    def literals(self) -> list[audit.Literal]:
        lits: list[audit.Literal] = []
        for rule in self.rules:
            lits.extend(rule.literals())
        lits.extend(audit.Literal(d.value, f"deny {i + 1}") for i, d in enumerate(self.deny))
        return lits

    def cleared_binaries(self) -> frozenset[str]:
        return frozenset(b.sha256.lower() for s in self.sources.values() for b in s.binaries)

    def mapped_terms(self) -> frozenset[str]:
        """Casefolded real values (and their variants) the mapping covers."""
        out: set[str] = set()
        for rule in self.rules:
            if not rule.regex:
                out.add(rule.source.casefold())
                out.update(v.casefold() for v in rule.variants)
        return frozenset(out)


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def parse_mapping(documents: Sequence[tuple[str, Any]], vocabulary: Vocabulary) -> PrivateMapping:
    """Merge mapping documents (in order) into one validated :class:`PrivateMapping`.

    Error messages name rules by index and class, never by value: a CronJob's logs are not
    the place for the real side of the mapping.
    """
    problems: list[str] = []
    rules: list[MappingRule] = []
    sources: dict[str, dict[str, Any]] = {}
    private_hosts: list[str] = []
    allow_items: list[Any] = []
    deny: list[DenyValue] = []

    for source_name, data in documents:
        if data is None:
            continue
        if not isinstance(data, dict):
            problems.append(f"{source_name}: top level must be a mapping")
            continue
        if data.get("version", 1) != 1:
            problems.append(f"{source_name}: unsupported version {data.get('version')!r}")
        for raw in _as_list(data.get("rules")):
            index = len(rules) + 1
            rule, errs = _parse_rule(index, raw)
            problems.extend(f"{source_name}: {e}" for e in errs)
            if rule is not None:
                rules.append(rule)
        for name, spec in (data.get("sources") or {}).items():
            sources.setdefault(str(name), {}).update(spec or {})
        private_hosts.extend(
            str(h).lower() for h in _as_list((data.get("links") or {}).get("private_hosts"))
        )
        allow_items.extend(_as_list(data.get("allow")))
        # The compact form for a reviewed list: one justification for many terms, so an
        # onboarding review fits in a secret store's size limit.
        terms = data.get("allow_terms")
        if terms is not None:
            if not isinstance(terms, dict) or not str(terms.get("why", "")).strip():
                problems.append(f"{source_name}: allow_terms needs `why` and `values`")
            else:
                allow_items.extend(
                    {"class": "term", "value": str(v), "why": str(terms["why"])}
                    for v in _as_list(terms.get("values"))
                )
        for i, item in enumerate(_as_list(data.get("deny"))):
            if not isinstance(item, dict) or not item.get("value") or not item.get("why"):
                problems.append(f"{source_name}: deny {i + 1}: needs `value` and `why`")
            else:
                deny.append(DenyValue(str(item["value"]), str(item["why"])))

    problems.extend(_check_rules(rules, vocabulary))

    parsed_sources: dict[str, SourcePrivate] = {}
    for name, spec in sources.items():
        binaries = []
        for i, b in enumerate(_as_list(spec.get("binaries"))):
            if not isinstance(b, dict) or not all(b.get(k) for k in ("path", "sha256", "why")):
                problems.append(f"source {name}: binary {i + 1} needs path, sha256 and why")
                continue
            if not re.fullmatch(r"[0-9a-fA-F]{64}", str(b["sha256"])):
                problems.append(f"source {name}: binary {i + 1}: sha256 is not 64 hex characters")
                continue
            binaries.append(
                BinaryClearance(str(b["path"]), str(b["sha256"]).lower(), str(b["why"]))
            )
        parsed_sources[name] = SourcePrivate(
            url=None if spec.get("url") is None else str(spec["url"]),
            drop=tuple(str(g) for g in _as_list(spec.get("drop"))),
            rename={str(k): str(v) for k, v in (spec.get("rename") or {}).items()},
            binaries=tuple(binaries),
        )

    try:
        allow = parse_allow({"entries": allow_items}, "mapping allow")
    except ConfigError as exc:
        problems.extend(exc.problems)
        allow = AllowRules(audit.Allowlist(), frozenset())

    if problems:
        raise ConfigError("mapping", problems)
    return PrivateMapping(
        rules=tuple(rules),
        sources=parsed_sources,
        private_hosts=tuple(dict.fromkeys(private_hosts)),
        allow=allow,
        deny=tuple(deny),
        files=tuple(name for name, _ in documents),
    )


def _parse_rule(index: int, raw: Any) -> tuple[MappingRule | None, list[str]]:
    where = f"rule {index}"
    if not isinstance(raw, dict):
        return None, [f"{where}: not a mapping"]
    errs: list[str] = []
    src = raw.get("from")
    dst = raw.get("to")
    cls = str(raw.get("class", "other"))
    if not isinstance(src, str) or not src.strip():
        errs.append(f"{where}: `from` must be a non-empty string")
    if not isinstance(dst, str):
        errs.append(f"{where}: `to` must be a string (it may be empty to delete)")
    elif "\n" in dst:
        errs.append(f"{where}: `to` may not contain a newline (line counts must not move)")
    if cls not in RULE_CLASSES:
        errs.append(f"{where}: unknown class {cls!r}")
    case = str(raw.get("case", "insensitive"))
    if case not in CASE_MODES:
        errs.append(f"{where}: case must be one of {', '.join(CASE_MODES)}")
    boundary = str(raw.get("boundary", "auto"))
    if boundary not in BOUNDARY_MODES:
        errs.append(f"{where}: boundary must be one of {', '.join(BOUNDARY_MODES)}")
    is_regex = bool(raw.get("regex", False))
    if is_regex and isinstance(src, str):
        try:
            re.compile(src)
        except re.error as exc:
            errs.append(f"{where}: bad regex: {exc}")
        if isinstance(dst, str) and re.search(r"\\\d|\\g<", dst):
            errs.append(f"{where}: a regex `to` may not reference groups; it would copy real text")
    variants = tuple(str(v) for v in _as_list(raw.get("variants")))
    if errs:
        return None, errs
    return (
        MappingRule(
            index=index,
            source=str(src),
            target=str(dst),
            cls=cls,
            case=case,
            boundary=boundary,
            regex=is_regex,
            variants=variants,
            audit_only=bool(raw.get("audit_only", False)),
        ),
        [],
    )


def _check_rules(rules: Sequence[MappingRule], vocabulary: Vocabulary) -> list[str]:
    """Cross-rule checks. Each is a mapping that could never pass the audit, or would pass it
    by accident."""
    problems: list[str] = []
    seen: dict[str, MappingRule] = {}
    for rule in rules:
        if rule.regex:
            continue
        for value in (rule.source, *rule.variants):
            key = value.casefold()
            other = seen.get(key)
            # Case-exact rules may split one spelling into several ("CSAM3" and "csam3"); any
            # other overlap is two rules claiming the same text.
            if (
                other is not None
                and other.index != rule.index
                and not (
                    rule.case == "exact" and other.case == "exact" and value not in _values(other)
                )
            ):
                problems.append(f"{rule.label}: duplicates the value of rule {other.index}")
            seen.setdefault(key, rule)

    literals = [lit for rule in rules for lit in rule.literals()]
    # Vocabulary only. Counting the mapping's own targets as placeholders here would exempt
    # every target from the very check that is meant to vet it.
    vocab_only = audit.Rules(
        literals=(), allow=audit.Allowlist(), placeholders=vocabulary.placeholders()
    )
    for rule in rules:
        # The same literal matcher the gate uses: a placeholder that contains a real value,
        # as the gate would see it, can never pass.
        hits = audit.audit_files(
            {}, audit.Rules(literals=tuple(literals)), extra_texts={"placeholder": rule.target}
        ).findings
        owners = sorted({h.detail for h in hits if h.layer == 1})
        if owners:
            problems.append(
                f"{rule.label}: its placeholder contains a real value ({', '.join(owners)})"
            )
        # A placeholder is text we are about to publish, so it has to pass the gate on its
        # own. This is what stops a real-looking domain, address or account being used as a
        # stand-in: a stand-in under a real TLD is somebody's domain; under .example it is
        # nobody's.
        hits = audit.audit_files({}, vocab_only, extra_texts={"placeholder": rule.target}).findings
        if hits:
            problems.append(
                f"{rule.label}: its placeholder would fail the audit "
                f"({', '.join(sorted({h.rule for h in hits}))})"
            )
    return problems


def _values(rule: MappingRule) -> tuple[str, ...]:
    return (rule.source, *rule.variants)


def mapping_documents(path: Path) -> list[tuple[str, Any]]:
    """One file, or every ``*.yml``/``*.yaml`` in a directory in lexical order."""
    if path.is_dir():
        files = sorted(p for p in path.iterdir() if p.suffix in (".yml", ".yaml") and p.is_file())
    else:
        files = [path]
    return [(f.name, load_yaml(f)) for f in files]


def resolve_mapping_path(explicit: str | Path | None) -> Path | None:
    candidates = [Path(explicit)] if explicit else []
    env = os.environ.get("DOCS_DISTRIBUTOR_MAPPING")
    if env:
        candidates.append(Path(env))
    if not explicit:
        candidates.extend(DEFAULT_MAPPING_PATHS)
    for c in candidates:
        if c.exists():
            return c
    return None


def load_mapping(path: Path, vocabulary: Vocabulary) -> PrivateMapping:
    return parse_mapping(mapping_documents(path), vocabulary)


def build_rules(
    mapping: PrivateMapping | None, allow: AllowRules, vocabulary: Vocabulary
) -> audit.Rules:
    """The audit's view of all inputs: literals from the mapping, the merged allowlist, and
    the vocabulary's placeholders."""
    if mapping is None:
        return audit.Rules(
            literals=(), allow=allow.allowlist, placeholders=vocabulary.placeholders()
        )
    return audit.Rules(
        literals=tuple(mapping.literals()),
        allow=audit.Allowlist(allow.allowlist.entries + mapping.allow.allowlist.entries),
        # Vocabulary only: every mapping target was already vetted against it on load.
        placeholders=vocabulary.placeholders(),
    )


# --- runtime config (config.yml) -----------------------------------------------------------


@dataclass(frozen=True)
class Auth:
    """How to authenticate to one GitHub host. Secrets come from the environment."""

    kind: str = "token"  # token | github-app | none
    token_env: str | None = None
    app_id_env: str = "DD_GITHUB_APP_ID"
    installation_id_env: str = "DD_GITHUB_APP_INSTALLATION_ID"
    private_key_env: str = "DD_GITHUB_APP_PRIVATE_KEY"
    api_url: str = "https://api.github.com"


@dataclass(frozen=True)
class SourceConfig:
    name: str
    target: str  # directory in the docs repo, e.g. docs/cloud-platform
    title: str  # nav section title
    url: str | None = None  # None: read it from the private mapping
    ref: str = "main"
    docs_dir: str = "docs"
    nav_file: str | None = "mkdocs.yml"
    include: tuple[str, ...] = ("**/*.md",)
    exclude: tuple[str, ...] = ()
    auth: Auth = field(default_factory=Auth)


@dataclass(frozen=True)
class TargetConfig:
    repo: str  # owner/name
    base: str | None = None  # default branch; None = ask the API
    branch_prefix: str = "docs/sync-"
    mkdocs: str = "mkdocs.yml"
    nav_after: str | None = None  # insert new sections after this top-level nav title
    auth: Auth = field(default_factory=lambda: Auth(kind="github-app"))
    labels: tuple[str, ...] = ("documentation",)


@dataclass(frozen=True)
class LLMConfig:
    backend: str = "claude-code"  # claude-code | anthropic | replay
    model: str = "claude-sonnet-4-6-max"
    base_url: str | None = None
    effort: str = "low"
    thinking_tokens: int | None = 2048
    timeout_seconds: int = 300
    batch_size: int = 40
    claude_bin: str = "claude"


@dataclass(frozen=True)
class ReportConfig:
    dir: str = "/var/lib/docs-distributor/reports"
    slack_webhook_env: str | None = "SLACK_WEBHOOK_URL"
    issue_repo: str | None = None


@dataclass(frozen=True)
class Config:
    target: TargetConfig
    sources: tuple[SourceConfig, ...]
    llm: LLMConfig = field(default_factory=LLMConfig)
    cache_dir: str = "/var/lib/docs-distributor/cache"
    work_dir: str = ""  # empty: the system temp dir; the chart sets /work (an emptyDir)
    report: ReportConfig = field(default_factory=ReportConfig)
    languages: tuple[str, ...] = ("en",)


def _auth(raw: Any, default_kind: str, problems: list[str], where: str) -> Auth:
    raw = raw or {}
    kind = str(raw.get("type", default_kind))
    if kind not in ("token", "github-app", "none"):
        problems.append(f"{where}: auth.type must be token, github-app or none")
    return Auth(
        kind=kind,
        token_env=raw.get("tokenEnv"),
        app_id_env=str(raw.get("appIdEnv", "DD_GITHUB_APP_ID")),
        installation_id_env=str(raw.get("installationIdEnv", "DD_GITHUB_APP_INSTALLATION_ID")),
        private_key_env=str(raw.get("privateKeyEnv", "DD_GITHUB_APP_PRIVATE_KEY")),
        api_url=str(raw.get("apiUrl", "https://api.github.com")).rstrip("/"),
    )


_SOURCE_NAME = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")


def parse_config(data: Any, source: str = "config") -> Config:
    problems: list[str] = []
    if not isinstance(data, dict):
        raise ConfigError(source, ["top level must be a mapping"])
    t = data.get("target") or {}
    if not t.get("repo") or "/" not in str(t.get("repo")):
        problems.append("target.repo must be owner/name")
    target = TargetConfig(
        repo=str(t.get("repo", "")),
        base=t.get("base"),
        branch_prefix=str(t.get("branchPrefix", "docs/sync-")),
        mkdocs=str(t.get("mkdocs", "mkdocs.yml")),
        nav_after=t.get("navAfter"),
        auth=_auth(t.get("auth"), "github-app", problems, "target"),
        labels=tuple(str(x) for x in t.get("labels", ["documentation"])),
    )
    sources: list[SourceConfig] = []
    seen: set[str] = set()
    for i, s in enumerate(data.get("sources") or []):
        where = f"sources[{i}]"
        name = str(s.get("name", ""))
        if not _SOURCE_NAME.fullmatch(name):
            problems.append(f"{where}: name must be lower-case kebab (it appears in branch names)")
        if name in seen:
            problems.append(f"{where}: duplicate source name {name!r}")
        seen.add(name)
        tgt = str(s.get("target", ""))
        if not tgt.startswith("docs/") or ".." in tgt.split("/"):
            problems.append(f"{where}: target must be a directory under docs/")
        sources.append(
            SourceConfig(
                name=name,
                target=tgt.rstrip("/"),
                title=str(s.get("title") or name),
                url=s.get("url") or None,
                ref=str(s.get("ref", "main")),
                docs_dir=str(s.get("docsDir", "docs")).strip("/"),
                nav_file=s.get("nav", "mkdocs.yml"),
                include=tuple(s.get("include") or ("**/*.md",)),
                exclude=tuple(s.get("exclude") or ()),
                auth=_auth(s.get("auth"), "token", problems, where),
            )
        )
    targets = [s.target for s in sources]
    for a in targets:
        for b in targets:
            if a != b and (b + "/").startswith(a + "/"):
                problems.append(f"source targets overlap: {a} contains {b}")
    llm_raw = data.get("llm") or {}
    backend = str(llm_raw.get("backend", "claude-code"))
    if backend not in ("claude-code", "anthropic", "replay"):
        problems.append("llm.backend must be claude-code, anthropic or replay")
    llm = LLMConfig(
        backend=backend,
        model=str(llm_raw.get("model", LLMConfig.model)),
        base_url=llm_raw.get("baseUrl"),
        effort=str(llm_raw.get("effort", "low")),
        thinking_tokens=llm_raw.get("thinkingTokens", 2048),
        timeout_seconds=int(llm_raw.get("timeoutSeconds", 300)),
        batch_size=int(llm_raw.get("batchSize", 40)),
        claude_bin=str(llm_raw.get("claudeBin", "claude")),
    )
    rep = data.get("report") or {}
    report = ReportConfig(
        dir=str(rep.get("dir", ReportConfig.dir)),
        slack_webhook_env=rep.get("slackWebhookEnv", "SLACK_WEBHOOK_URL"),
        issue_repo=rep.get("issueRepo"),
    )
    if problems:
        raise ConfigError(source, problems)
    return Config(
        target=target,
        sources=tuple(sources),
        llm=llm,
        cache_dir=str(data.get("cacheDir", Config.cache_dir)),
        work_dir=str(data.get("workDir", Config.work_dir)),
        report=report,
        languages=tuple(data.get("languages") or ("en",)),
    )


def load_config(path: Path) -> Config:
    return parse_config(load_yaml(path), str(path))
