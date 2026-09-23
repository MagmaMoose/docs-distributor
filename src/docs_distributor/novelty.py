"""Candidate unmapped-noun detection. Deterministic, and it decides nothing.

The scan runs over the TRANSFORMED output. By then every mapped value is gone, so what is
left that looks like a name is exactly what nobody has decided about yet, and every location
reported is an output path, which is safe to publish.

A token's parts (split on ``-``, ``_``, ``.``, and camel case) are *known* when they are
short, numeric, hex, a placeholder, allowlisted, in the tech vocabulary, or a common word in
one of the configured languages. A part becomes a candidate when:

* **unknown-word**: it is none of those (``hollowbrook``, ``jdoe42``, ``iLedgerSuite``);
* **proper-noun**: it is written capitalised mid-sentence in prose, where English does not
  force a capital, and is not known vocabulary. A frequency list happily calls
  ``Lisbon`` an English word; the capital in "hosted in Lisbon" says it is a name.

Candidates go to the classifier (:mod:`docs_distributor.llm`), and the audit's layer 3
refuses to pass a run in which any candidate lacks a decision.

What this cannot see: a name that is also a common word and only ever appears where
capitals are forced (a table cell, a heading, the start of a sentence). The literal layer
is what covers those, once the mapping names them; the novelty scan is a net, not a wall.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources
from pathlib import Path

from docs_distributor.transform import segments

_TOKEN = re.compile(r"[A-Za-z0-9]+(?:[-_.][A-Za-z0-9]+)*")
_PART_SPLIT = re.compile(r"[-_.]")
_CAMEL = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+")
_HEXISH = re.compile(r"[0-9a-f]{6,}")
_CALENDAR = frozenset(
    "january february march april may june july august september october november december "
    "monday tuesday wednesday thursday friday saturday sunday".split()
)
_CONTEXT_CHARS = 90
_MAX_CONTEXTS = 3


@dataclass(frozen=True)
class Candidate:
    term: str  # PRIVATE: an unmapped token from the source
    where: str  # first OUTPUT location, "path:line" (safe)
    count: int
    contexts: tuple[str, ...]  # output snippets around the term (anonymised apart from it)
    reasons: tuple[str, ...]


def load_tech_vocabulary(path: Path | None = None) -> frozenset[str]:
    path = path or Path(str(resources.files("docs_distributor") / "rules" / "tech-vocabulary.txt"))
    words = (line.strip().casefold() for line in path.read_text(encoding="utf-8").splitlines())
    return frozenset(w for w in words if w and not w.startswith("#"))


@lru_cache(maxsize=200_000)
def _zipf(word: str, lang: str) -> float:
    from wordfreq import zipf_frequency

    return float(zipf_frequency(word, lang))


@dataclass
class Lexicon:
    """What the scan counts as already known."""

    tech: frozenset[str]
    allow: frozenset[str] = frozenset()
    placeholders: frozenset[str] = frozenset()
    languages: tuple[str, ...] = ("en",)
    min_zipf: float = 3.0
    _known: dict[str, bool] = field(default_factory=dict)

    @classmethod
    def build(
        cls,
        *,
        tech: Iterable[str],
        allow: Iterable[str] = (),
        placeholder_values: Iterable[str] = (),
        languages: Iterable[str] = ("en",),
    ) -> Lexicon:
        parts: set[str] = set()
        for value in placeholder_values:
            parts.update(p.casefold() for p in _TOKEN.findall(value))
            for tok in _TOKEN.findall(value):
                parts.update(p.casefold() for p in _PART_SPLIT.split(tok))
        return cls(
            tech=frozenset(t.casefold() for t in tech),
            allow=frozenset(a.casefold() for a in allow),
            placeholders=frozenset(parts),
            languages=tuple(languages),
        )

    def listed(self, word: str) -> bool:
        w = word.casefold()
        return w in self.tech or w in self.allow or w in self.placeholders

    def word_known(self, word: str) -> bool:
        w = word.casefold()
        cached = self._known.get(w)
        if cached is not None:
            return cached
        base = w.rstrip("0123456789")
        known = (
            len(base) <= 2
            or w.isdigit()
            or (_HEXISH.fullmatch(w) is not None and any(c.isdigit() for c in w))
            or any(self._stem_known(s) for s in (w, base, *_stems(base)))
        )
        self._known[w] = known
        return known

    def _stem_known(self, stem: str) -> bool:
        return len(stem) >= 3 and (
            self.listed(stem) or any(_zipf(stem, lang) >= self.min_zipf for lang in self.languages)
        )

    def part_known(self, part: str) -> bool:
        if self.word_known(part):
            return True
        subparts = _CAMEL.findall(part)
        return len(subparts) > 1 and all(self.word_known(s) for s in subparts)


_SUFFIXES = (
    ("ies", ("y",)),
    ("ing", ("", "e")),
    ("ied", ("y",)),
    ("ed", ("", "e")),
    ("es", ("", "e")),
    ("ers", ("", "e")),
    ("er", ("", "e")),
    ("able", ("", "e")),
    ("ments", ("",)),
    ("ment", ("",)),
    ("ly", ("",)),
    ("s", ("",)),
)


def _stems(word: str) -> list[str]:
    """Plausible stems of an inflected English word: synced -> sync, reconciles ->
    reconcile, repositories -> repository, mapper -> map. Crude on purpose; a wrong stem
    only means one more question to the classifier, never one fewer check."""
    out: list[str] = []
    for suffix, endings in _SUFFIXES:
        if word.endswith(suffix) and len(word) - len(suffix) >= 3:
            root = word[: -len(suffix)]
            out.extend(root + e for e in endings)
            if len(root) >= 4 and root[-1] == root[-2]:
                out.append(root[:-1])  # mapp -> map, logg -> log
    return out


@dataclass
class _Seen:
    term: str
    where: str
    count: int = 0
    contexts: list[str] = field(default_factory=list)
    reasons: set[str] = field(default_factory=set)


def _snippet(line: str, start: int, end: int) -> str:
    lo = max(0, start - _CONTEXT_CHARS)
    hi = min(len(line), end + _CONTEXT_CHARS)
    return ("…" if lo else "") + line[lo:hi].strip() + ("…" if hi < len(line) else "")


def _mid_sentence(line: str, start: int) -> bool:
    """True when a capital at ``start`` is not forced by position: the previous word on the
    line is lower-case and only spaces separate the two."""
    before = line[:start]
    gap = len(before) - len(before.rstrip(" "))
    if gap == 0:
        return False
    prev = before.rstrip(" ")
    m = re.search(r"([A-Za-z][A-Za-z0-9'-]*)$", prev)
    return m is not None and m.group(1)[0].islower()


def scan(
    files: Mapping[str, str],
    lexicon: Lexicon,
    extra_texts: Mapping[str, str] | None = None,
) -> list[Candidate]:
    """Candidates in the transformed Markdown ``files`` (output path -> text)."""
    seen: dict[str, _Seen] = {}

    def note(term: str, where: str, reason: str, context: str) -> None:
        key = term.casefold()
        entry = seen.get(key)
        if entry is None:
            entry = seen[key] = _Seen(term, where)
        entry.count += 1
        entry.reasons.add(reason)
        if len(entry.contexts) < _MAX_CONTEXTS and context not in entry.contexts:
            entry.contexts.append(context)

    texts = dict(files)
    for name, text in (extra_texts or {}).items():
        texts[f"<{name}>"] = text

    # A word the corpus also writes in lower case is being used as a word, not a name
    # ("the Secret" vs "a secret"); only never-lowercased words can be proper nouns.
    lowercase_seen: set[str] = set()
    for text in texts.values():
        lowercase_seen.update(t for t in re.findall(r"(?<![A-Za-z])[a-z][a-z]+", text))

    for path in sorted(texts):
        text = texts[path]
        for seg in segments(text) if path.endswith(".md") else [_whole(text)]:
            for offset, line in enumerate(seg.text.splitlines()):
                line_no = seg.first_line + offset
                for m in _TOKEN.finditer(line):
                    for part_m in _parts(m):
                        part, p_start, p_end = part_m
                        if len(part.rstrip("0123456789")) < 3:
                            continue
                        where = f"{path}:{line_no}"
                        context = _snippet(line, p_start, p_end)
                        if not lexicon.part_known(part):
                            note(part, where, "unknown-word", context)
                        elif (
                            not seg.code
                            and part[0].isupper()
                            and any(c.islower() for c in part)
                            and not lexicon.listed(part)
                            and part.casefold() not in _CALENDAR
                            and part.casefold() not in lowercase_seen
                            and _mid_sentence(line, p_start)
                        ):
                            note(part, where, "proper-noun", context)
    return [
        Candidate(e.term, e.where, e.count, tuple(e.contexts), tuple(sorted(e.reasons)))
        for e in sorted(seen.values(), key=lambda e: e.term.casefold())
    ]


class _whole:
    """A non-Markdown file scanned as a single code segment."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.code = True
        self.first_line = 1


def _parts(m: re.Match[str]) -> list[tuple[str, int, int]]:
    token, base = m.group(0), m.start()
    out: list[tuple[str, int, int]] = []
    pos = 0
    for piece in _PART_SPLIT.split(token):
        start = token.index(piece, pos)
        out.append((piece, base + start, base + start + len(piece)))
        pos = start + len(piece)
    return out
