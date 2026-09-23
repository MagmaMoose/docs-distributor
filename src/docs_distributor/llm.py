"""The four LLM calls, each cached and each checked by Python before its answer is used.

The model is consulted only where code cannot decide (see the README's table):

* :meth:`LLM.classify`: is an unmapped term sensitive?
* :meth:`LLM.propose`: what stand-in fits the scheme for a sensitive term?
* :meth:`LLM.repair`: make a paragraph grammatical again after substitution;
* :meth:`LLM.place`: where does a page the source nav does not list belong?

It never decides whether anything publishes. That is :mod:`docs_distributor.audit`, which
runs after every one of these and does not call a model.

**Determinism.** An uncached model rewords the same paragraph differently every week and
floods the diff. Every answer is therefore cached on disk, keyed by
``sha256(content + template name@version + model id)``, and a run with the same inputs gets
the same bytes back. Bump a template's ``version`` to invalidate its answers on purpose.

**Privacy.** Only :meth:`classify` and :meth:`propose` send a real term, with context that
is already anonymised around it. :meth:`repair` and :meth:`place` see anonymised text only.
Answers can contain real terms, so the cache lives on a private volume and is never
published.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
import string
import subprocess
import tempfile
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any, Protocol

import httpx
import yaml

from docs_distributor import audit
from docs_distributor.config import RULE_CLASSES, LLMConfig, Vocabulary
from docs_distributor.novelty import Candidate

# --- templates ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Template:
    name: str
    version: int
    system: str
    user: string.Template
    schema: dict[str, Any]

    @property
    def tag(self) -> str:
        return f"{self.name}@{self.version}"


def prompts_dir() -> Path:
    packaged = Path(str(resources.files("docs_distributor") / "prompts"))
    if packaged.is_dir():
        return packaged
    return Path(__file__).resolve().parents[2] / "prompts"  # a source checkout


def load_template(name: str, directory: Path | None = None) -> Template:
    text = ((directory or prompts_dir()) / f"{name}.md").read_text(encoding="utf-8")
    _, front, body = text.split("---\n", 2)
    meta = yaml.safe_load(front)
    system, _, user = body.partition("=== user ===\n")
    return Template(
        name=str(meta["name"]),
        version=int(meta["version"]),
        system=system.strip(),
        user=string.Template(user.strip()),
        schema=dict(meta["schema"]),
    )


# --- errors, cache, backends -------------------------------------------------------------


class LLMError(RuntimeError):
    """The model could not be reached or did not answer."""


class ResponseRejected(LLMError):
    """The model answered, and Python's checks refused the answer."""


class CacheMiss(LLMError):
    """A replay-only run needed an answer nobody has cached."""


class Cache:
    """Content-addressed answers on disk: ``<root>/<key[:2]>/<key>.json``."""

    def __init__(self, root: Path) -> None:
        self.root = root

    @staticmethod
    def key(content: str, tag: str, model: str) -> str:
        return hashlib.sha256(f"{content}\x00{tag}\x00{model}".encode()).hexdigest()

    def _path(self, key: str) -> Path:
        return self.root / key[:2] / f"{key}.json"

    def get(self, key: str) -> Any | None:
        path = self._path(key)
        if not path.is_file():
            return None
        return json.loads(path.read_text(encoding="utf-8"))["response"]

    def put(self, key: str, tag: str, model: str, content: str, response: Any) -> None:
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        record = {"template": tag, "model": model, "request": content, "response": response}
        # Write-then-rename, so a pod killed mid-write never leaves a half answer behind.
        fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(record, fh, ensure_ascii=False, sort_keys=True, indent=1)
        os.replace(tmp, path)


class Backend(Protocol):
    model: str

    def complete(self, template: Template, user: str) -> Any: ...


class ClaudeCodeBackend:
    """Headless Claude Code (``claude -p``), optionally routed through a LiteLLM gateway.

    This is the supported way to spend a Claude subscription from automation: the CLI is
    Claude Code, so no client has to present itself as one. Routing follows the gateway's
    house rule: the subscription's OAuth token is the upstream bearer
    (``ANTHROPIC_AUTH_TOKEN``), and the gateway's own virtual key rides
    ``x-litellm-api-key`` with its ``Bearer`` prefix, on the raw listener.

    The run is hermetic: no tools, no MCP servers, no user or project settings or hooks, an
    empty working directory, and, when a token is supplied, its own HOME. Without a token it
    inherits the local login, which is how ``plan`` runs on a laptop.

    The CLI answers errors with ``is_error: true`` while still saying ``subtype: success``,
    so ``is_error`` is what is checked.
    """

    def __init__(
        self, cfg: LLMConfig, workdir: Path, environ: Mapping[str, str] | None = None
    ) -> None:
        self.cfg = cfg
        self.model = cfg.model
        self.workdir = workdir
        self.environ = dict(os.environ if environ is None else environ)

    def command(self, template: Template) -> list[str]:
        return [
            self.cfg.claude_bin,
            "-p",
            "--output-format", "json",
            "--json-schema", json.dumps(template.schema, separators=(",", ":")),
            "--model", self.model,
            "--tools", "",
            "--permission-mode", "dontAsk",
            "--no-session-persistence",
            "--setting-sources", "project",
            "--strict-mcp-config",
            "--effort", self.cfg.effort,
            "--append-system-prompt", template.system,
        ]  # fmt: skip

    def env(self) -> dict[str, str]:
        src = self.environ
        env = {
            "PATH": src.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "LANG": "C.UTF-8",
            "DISABLE_TELEMETRY": "1",
            "DISABLE_AUTOUPDATER": "1",
            "DISABLE_ERROR_REPORTING": "1",
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        }
        oauth = src.get("CLAUDE_OAUTH_TOKEN")
        gateway_key = src.get("LITELLM_API_KEY")
        if self.cfg.base_url:
            env["ANTHROPIC_BASE_URL"] = self.cfg.base_url
        if oauth:
            env["ANTHROPIC_AUTH_TOKEN"] = oauth
            home = self.workdir / "home"
            home.mkdir(parents=True, exist_ok=True)
            env["HOME"] = str(home)
            env["CLAUDE_CONFIG_DIR"] = str(home / ".claude")
        else:
            for name in ("HOME", "USER", "LOGNAME", "TMPDIR"):
                if name in src:
                    env[name] = src[name]
        if gateway_key:
            env["ANTHROPIC_CUSTOM_HEADERS"] = f"x-litellm-api-key: Bearer {gateway_key}"
        if self.cfg.thinking_tokens is not None:
            env["MAX_THINKING_TOKENS"] = str(self.cfg.thinking_tokens)
        return env

    def complete(self, template: Template, user: str) -> Any:
        cwd = self.workdir / "empty"
        cwd.mkdir(parents=True, exist_ok=True)
        try:
            proc = subprocess.run(  # noqa: S603 — fixed argv, no shell
                self.command(template),
                input=user,
                capture_output=True,
                text=True,
                timeout=self.cfg.timeout_seconds,
                cwd=cwd,
                env=self.env(),
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise LLMError(f"claude timed out after {self.cfg.timeout_seconds}s") from exc
        except OSError as exc:
            raise LLMError(f"claude could not start: {exc.strerror}") from exc
        try:
            envelope = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise LLMError(f"claude exited {proc.returncode} without a JSON result") from exc
        if envelope.get("is_error"):
            # An error's `result` is the CLI's message, not model output, so it is safe to
            # log; truncated anyway.
            status = envelope.get("api_error_status") or envelope.get("terminal_reason") or "error"
            raise LLMError(f"claude: {status}: {str(envelope.get('result', ''))[:160]}")
        if "structured_output" not in envelope:
            raise LLMError("claude answered without structured output")
        return envelope["structured_output"]


class AnthropicBackend:
    """The Messages API with an API key, for deployments without a subscription. The answer is
    forced through a single tool whose input schema is the template's schema."""

    def __init__(
        self,
        cfg: LLMConfig,
        environ: Mapping[str, str] | None = None,
        client: httpx.Client | None = None,
    ) -> None:
        env = os.environ if environ is None else environ
        self.cfg = cfg
        self.model = cfg.model
        self.key = env.get("ANTHROPIC_API_KEY") or env.get("LITELLM_API_KEY") or ""
        self.client = client or httpx.Client(timeout=cfg.timeout_seconds)

    def complete(self, template: Template, user: str) -> Any:
        base = (self.cfg.base_url or "https://api.anthropic.com").rstrip("/")
        headers = {"anthropic-version": "2023-06-01", "content-type": "application/json"}
        if base.endswith("anthropic.com"):
            headers["x-api-key"] = self.key
        else:
            headers["authorization"] = f"Bearer {self.key}"
        body = {
            "model": self.model,
            "max_tokens": 8192,
            "system": template.system,
            "messages": [{"role": "user", "content": user}],
            "tools": [
                {
                    "name": "answer",
                    "description": "Return the answer.",
                    "input_schema": template.schema,
                }
            ],
            "tool_choice": {"type": "tool", "name": "answer"},
        }
        try:
            resp = self.client.post(f"{base}/v1/messages", headers=headers, json=body)
        except httpx.HTTPError as exc:
            raise LLMError(f"messages API unreachable: {type(exc).__name__}") from exc
        if resp.status_code >= 400:
            raise LLMError(f"messages API answered {resp.status_code}")
        for block in resp.json().get("content", []):
            if block.get("type") == "tool_use":
                return block.get("input")
        raise LLMError("messages API answered without the forced tool call")


class ReplayBackend:
    """Answers only from the cache. For CI, tests and ``plan --offline``."""

    def __init__(self, model: str) -> None:
        self.model = model

    def complete(self, template: Template, user: str) -> Any:
        raise CacheMiss(f"{template.tag}: no cached answer and this run is replay-only")


def make_backend(cfg: LLMConfig, workdir: Path) -> Backend:
    if cfg.backend == "claude-code":
        return ClaudeCodeBackend(cfg, workdir)
    if cfg.backend == "anthropic":
        return AnthropicBackend(cfg)
    return ReplayBackend(cfg.model)


# --- results -----------------------------------------------------------------------------


@dataclass(frozen=True)
class Decision:
    term: str
    sensitive: bool
    category: str
    reason: str
    origin: str  # "llm:<model>" or "cache:<model>"


@dataclass(frozen=True)
class Proposal:
    term: str  # PRIVATE
    cls: str
    to: str
    reason: str
    origin: str  # "llm", "series" (assigned by Python) or "unresolved"


@dataclass(frozen=True)
class Placement:
    path: str
    section: tuple[str, ...]
    title: str
    origin: str


@dataclass
class Stats:
    calls: int = 0
    hits: int = 0
    rejected: int = 0
    failed: int = 0
    by_template: dict[str, int] = field(default_factory=dict)


def _canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _batches(items: Sequence[Any], size: int) -> Iterable[Sequence[Any]]:
    for i in range(0, len(items), max(1, size)):
        yield items[i : i + size]


# --- series (Python assigns these; the model is not needed for a next letter) -------------


def _letters(upper: bool) -> Iterable[str]:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if upper else "abcdefghijklmnopqrstuvwxyz"
    yield from alphabet
    for a in alphabet:
        for b in alphabet:
            yield a + b


def next_in_series(series: str, taken: Iterable[str]) -> str:
    """The first value of ``series`` ("client-{letter}", "vendor-{LETTER}") not taken."""
    used = {t.casefold() for t in taken}
    upper = "{LETTER}" in series
    for letters in _letters(upper):
        value = series.replace("{LETTER}", letters).replace("{letter}", letters)
        if value.casefold() not in used:
            return value
    raise ValueError(f"series {series!r} is exhausted")


_CLASS_TO_VOCAB = {
    "customer": "customer",
    "vendor": "vendor",
    "handle": "handle",
    "person": "handle",
    "org": "org",
    "product": "product",
}


# --- the four calls ----------------------------------------------------------------------


class LLM:
    def __init__(
        self,
        backend: Backend,
        cache: Cache,
        *,
        batch_size: int = 40,
        templates: Mapping[str, Template] | None = None,
        retries: int = 2,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.backend = backend
        self.cache = cache
        self.batch_size = batch_size
        self.templates = dict(
            templates or {n: load_template(n) for n in ("classify", "propose", "repair", "place")}
        )
        self.retries = retries
        self.sleep = sleep
        self.stats = Stats()

    def _ask(self, name: str, user: str) -> Any:
        template = self.templates[name]
        last: LLMError | None = None
        for attempt in range(self.retries + 1):
            try:
                self.stats.calls += 1
                self.stats.by_template[name] = self.stats.by_template.get(name, 0) + 1
                return self.backend.complete(template, user)
            except CacheMiss:
                raise
            except LLMError as exc:
                last = exc
                self.stats.failed += 1
                if attempt < self.retries:
                    self.sleep(5.0 * (attempt + 1))
        raise last if last is not None else LLMError(f"{name}: no attempt was made")

    def _key(self, name: str, content: str) -> str:
        return Cache.key(content, self.templates[name].tag, self.backend.model)

    def _store(self, name: str, content: str, response: Any) -> None:
        self.cache.put(
            self._key(name, content),
            self.templates[name].tag,
            self.backend.model,
            content,
            response,
        )

    # classify ------------------------------------------------------------------------

    def classify(self, candidates: Sequence[Candidate]) -> dict[str, Decision]:
        """A decision per candidate, keyed by ``term.casefold()``.

        Cached per term: the contexts inform the first answer and are not part of the key,
        so an edit elsewhere on a page does not re-open a settled question. A candidate the
        model will not answer for stays undecided, and the audit fails closed on it.
        """
        decisions: dict[str, Decision] = {}
        todo: list[Candidate] = []
        for cand in sorted(candidates, key=lambda c: c.term.casefold()):
            hit = self.cache.get(self._key("classify", cand.term.casefold()))
            if hit is not None:
                self.stats.hits += 1
                decisions[cand.term.casefold()] = Decision(
                    cand.term, **hit, origin=f"cache:{self.backend.model}"
                )
            else:
                todo.append(cand)
        for batch in _batches(todo, self.batch_size):
            payload = [
                {"term": c.term, "contexts": list(c.contexts), "why_flagged": list(c.reasons)}
                for c in batch
            ]
            user = self.templates["classify"].user.substitute(
                terms=json.dumps(payload, ensure_ascii=False, indent=1)
            )
            try:
                answer = self._ask("classify", user)
            except CacheMiss:
                continue
            except LLMError:
                continue  # these stay undecided; layer 3 fails the run on them
            wanted = {c.term: c for c in batch}
            for item in _results(answer, "results"):
                term = item.get("term")
                if term not in wanted or not isinstance(item.get("sensitive"), bool):
                    self.stats.rejected += 1
                    continue
                record = {
                    "sensitive": item["sensitive"],
                    "category": str(item.get("category", "other")),
                    "reason": str(item.get("reason", ""))[:200],
                }
                self._store("classify", term.casefold(), record)
                decisions[term.casefold()] = Decision(
                    term, **record, origin=f"llm:{self.backend.model}"
                )
                del wanted[term]
        return decisions

    # propose -------------------------------------------------------------------------

    def propose(
        self,
        terms: Sequence[tuple[str, str]],
        vocabulary: Vocabulary,
        taken: Iterable[str],
    ) -> list[Proposal]:
        """A stand-in per ``(term, category)``. Series classes are assigned by Python; the
        model is asked only for the rest, and every answer must pass the gate on its own."""
        taken_set = {t.casefold() for t in taken} | vocabulary.all_values()
        out: list[Proposal] = []
        ask: list[tuple[str, str]] = []
        for term, category in sorted(terms, key=lambda t: t[0].casefold()):
            cls = _category_class(category)
            vocab_cls = vocabulary.classes.get(_CLASS_TO_VOCAB.get(cls, ""))
            if vocab_cls is not None and vocab_cls.series:
                value = next_in_series(vocab_cls.series, taken_set)
                taken_set.add(value.casefold())
                out.append(
                    Proposal(term, cls, value, f"next {vocab_cls.name} in the series", "series")
                )
            else:
                ask.append((term, category))
        placeholders = vocabulary.placeholders()
        for batch in _batches(ask, self.batch_size):
            pending: dict[str, str] = {}
            for term, category in batch:
                content = _canon({"term": term.casefold(), "category": category})
                hit = self.cache.get(self._key("propose", content))
                if hit is not None and _placeholder_ok(term, hit["to"], placeholders, taken_set):
                    self.stats.hits += 1
                    taken_set.add(hit["to"].casefold())
                    out.append(Proposal(term, hit["class"], hit["to"], hit["reason"], "cache"))
                else:
                    pending[term] = category
            if not pending:
                continue
            user = self.templates["propose"].user.substitute(
                vocabulary=_describe_vocabulary(vocabulary),
                taken=", ".join(sorted(taken_set)) or "(nothing yet)",
                terms=json.dumps(
                    [{"term": t, "category": c} for t, c in pending.items()],
                    ensure_ascii=False,
                    indent=1,
                ),
            )
            try:
                answer = self._ask("propose", user)
            except LLMError:
                answer = {}
            for item in _results(answer, "proposals"):
                term = item.get("term")
                to = str(item.get("to", "")).strip()
                cls = str(item.get("class", "other"))
                if (
                    term not in pending
                    or cls not in RULE_CLASSES
                    or not _placeholder_ok(term, to, placeholders, taken_set)
                ):
                    self.stats.rejected += 1
                    continue
                record = {"class": cls, "to": to, "reason": str(item.get("reason", ""))[:200]}
                self._store(
                    "propose", _canon({"term": term.casefold(), "category": pending[term]}), record
                )
                taken_set.add(to.casefold())
                out.append(Proposal(term, cls, to, record["reason"], "llm"))
                del pending[term]
            for term, category in pending.items():
                out.append(
                    Proposal(
                        term, _category_class(category), "", "no acceptable proposal", "unresolved"
                    )
                )
        return sorted(out, key=lambda p: p.term.casefold())

    # repair --------------------------------------------------------------------------

    def repair(self, text: str, issues: Sequence[str], placeholders: Sequence[str]) -> str | None:
        """The repaired paragraph, or None when no answer passes the checks."""
        content = _canon(
            {"text": text, "issues": list(issues), "placeholders": sorted(placeholders)}
        )
        hit = self.cache.get(self._key("repair", content))
        if hit is not None:
            self.stats.hits += 1
            return str(hit["text"])
        user = self.templates["repair"].user.substitute(
            issues="\n".join(f"- {i}" for i in issues),
            placeholders=", ".join(sorted(placeholders)) or "(none)",
            text=text,
        )
        try:
            answer = self._ask("repair", user)
        except LLMError:
            return None
        repaired = answer.get("text") if isinstance(answer, dict) else None
        if not isinstance(repaired, str) or not repair_acceptable(text, repaired, placeholders):
            self.stats.rejected += 1
            return None
        self._store("repair", content, {"text": repaired})
        return repaired

    # place ---------------------------------------------------------------------------

    def place(
        self, pages: Sequence[tuple[str, str]], tree: Sequence[tuple[str, ...]]
    ) -> dict[str, Placement]:
        """Placement per page path, for ``pages`` of ``(path, heading)``. Pages the model
        cannot place are left out; the caller falls back to a deterministic spot."""
        sections = {tuple(s) for s in tree} | {()}
        out: dict[str, Placement] = {}
        pending: dict[str, str] = {}
        tree_key = _canon(sorted(list(s) for s in sections))
        for path, heading in sorted(pages):
            hit = self.cache.get(
                self._key("place", _canon({"path": path, "heading": heading, "tree": tree_key}))
            )
            if hit is not None and tuple(hit["section"]) in sections:
                self.stats.hits += 1
                out[path] = Placement(path, tuple(hit["section"]), hit["title"], "cache")
            else:
                pending[path] = heading
        if not pending:
            return out
        user = self.templates["place"].user.substitute(
            tree="\n".join("  " * (len(s) - 1) + s[-1] for s in sorted(sections) if s) or "(empty)",
            pages=json.dumps(
                [{"path": p, "heading": h} for p, h in pending.items()],
                ensure_ascii=False,
                indent=1,
            ),
        )
        try:
            answer = self._ask("place", user)
        except LLMError:
            return out
        for item in _results(answer, "placements"):
            path = item.get("path")
            section = tuple(str(s) for s in item.get("section") or ())
            title = str(item.get("title", "")).strip()
            if path not in pending or section not in sections or not (0 < len(title) <= 60):
                self.stats.rejected += 1
                continue
            record = {"section": list(section), "title": title}
            self._store(
                "place", _canon({"path": path, "heading": pending[path], "tree": tree_key}), record
            )
            out[path] = Placement(path, section, title, "llm")
        return out


def _results(answer: Any, key: str) -> list[dict[str, Any]]:
    items = answer.get(key) if isinstance(answer, dict) else None
    return [i for i in items if isinstance(i, dict)] if isinstance(items, list) else []


def _category_class(category: str) -> str:
    return {
        "organisation": "org",
        "customer": "customer",
        "person": "person",
        "internal-system": "product",
        "vendor": "vendor",
        "location": "location",
        "resource-name": "other",
    }.get(category, "other")


def _describe_vocabulary(vocabulary: Vocabulary) -> str:
    lines = []
    for pc in vocabulary.classes.values():
        parts = []
        if pc.values:
            parts.append("in use: " + ", ".join(pc.values))
        if pc.series:
            parts.append(f"series: {pc.series}")
        if pc.ranges:
            parts.append("ranges: " + ", ".join(pc.ranges))
        if parts:
            lines.append(f"- {pc.name}: " + "; ".join(parts))
    return "\n".join(lines)


def _placeholder_ok(term: str, to: str, placeholders: audit.Placeholders, taken: set[str]) -> bool:
    """A stand-in must be new, must not echo the term, and must pass the gate on its own."""
    if not to or len(to) > 80 or "\n" in to or to.casefold() in taken:
        return False
    low_term, low_to = term.casefold(), to.casefold()
    if low_term in low_to:
        return False
    term_parts = {p for p in re.split(r"[^a-z0-9]+", low_term) if len(p) >= 4}
    to_parts = set(re.split(r"[^a-z0-9]+", low_to))
    if term_parts & to_parts:
        return False
    rules = audit.Rules(literals=(audit.Literal(term, "proposal"),), placeholders=placeholders)
    return not audit.audit_files({}, rules, extra_texts={"placeholder": to}).findings


_FUNCTION_WORDS = frozenset(
    "a an the and or of to in on for with is are be by as at it its this that".split()
)
_LINE_PREFIX = re.compile(r"^\s*(?:[-*+]\s+|\d+[.)]\s+|>\s*|#{1,6}\s+)?")


def repair_acceptable(before: str, after: str, placeholders: Sequence[str]) -> bool:
    """Python's check on a repaired paragraph. Any failure keeps the unrepaired text."""
    a_lines, b_lines = before.splitlines(), after.splitlines()
    if len(a_lines) != len(b_lines):
        return False
    for x, y in zip(a_lines, b_lines, strict=True):
        if _LINE_PREFIX.match(x).group(0) != _LINE_PREFIX.match(y).group(0):  # type: ignore[union-attr]
            return False
    for p in placeholders:
        if before.count(p) and not after.count(p):
            return False
    tokens_before = {t.casefold() for t in re.findall(r"[\w'-]+", before)}
    added = {t.casefold() for t in re.findall(r"[\w'-]+", after)} - tokens_before - _FUNCTION_WORDS
    if added:
        return False
    return difflib.SequenceMatcher(a=before, b=after, autojunk=False).ratio() >= 0.85
