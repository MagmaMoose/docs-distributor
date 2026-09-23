"""Deterministic transformation of a source docs tree into its anonymised form.

Everything here is mechanical and repeatable: the same source, mapping and version produce
byte-identical output. No LLM is called from this module; it only records where prose may
have been damaged so the pipeline can ask for a repair (see :mod:`docs_distributor.llm`).

Per Markdown file, in order:

1. **Links** are classified on the SOURCE text, before anything is renamed:

   * a relative link to a page that is published is re-pointed at that page's new path;
   * a link into a private host, or whose URL contains any real value from the mapping,
     becomes a code span of its text (a dead link helps nobody, and the URL would leak);
   * a relative link to something that is not published becomes a code span too.

2. **The mapping** is applied in one pass: regex rules first, in order, then every literal
   at once, longest first, so a placeholder is never substituted again. Inside fenced code
   blocks the padding after a replacement is adjusted so aligned columns (tree diagrams,
   box borders, trailing comments) stay aligned. A match that spans a line break keeps its
   line breaks, so line counts never move.

3. **Damage** the substitution may have caused ("the the platform", "Security Gate
   (security gate)", an article that no longer agrees) is recorded, not fixed.
"""

from __future__ import annotations

import hashlib
import posixpath
import re
import unicodedata
from collections import Counter
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from urllib.parse import urlsplit

from docs_distributor.config import MappingRule

# --- substitution ------------------------------------------------------------------------


@dataclass(frozen=True)
class Replacement:
    rule_index: int
    start: int  # in the output text
    end: int
    original: str  # PRIVATE: the real text that was replaced


@dataclass
class Substituted:
    text: str
    replacements: list[Replacement]
    misaligned: list[int]  # output offsets where padding could not absorb a longer value


_BORDER = "│┃║|"


def _case_like(template: str, target: str) -> str:
    """Give ``target`` the letter case of ``template`` (used by ``case: preserve``)."""
    letters = [c for c in template if c.isalpha()]
    if not letters:
        return target
    if all(c.isupper() for c in letters) and len(letters) > 1:
        return target.upper()
    if all(c.islower() for c in letters):
        return target.lower()
    if letters[0].isupper():
        return target[:1].upper() + target[1:]
    return target


class Substituter:
    """Applies the mapping. Built once per run; :meth:`apply` is pure."""

    def __init__(self, rules: Sequence[MappingRule]) -> None:
        active = [r for r in rules if not r.audit_only]
        self._regex = [(re.compile(r.source), r) for r in active if r.regex]
        literals: list[tuple[str, MappingRule]] = []
        for r in active:
            if r.regex:
                continue
            literals.extend((v, r) for v in (r.source, *r.variants))
        literals.sort(key=lambda item: (-len(item[0]), item[0].casefold()))
        self._by_key: dict[str, MappingRule] = {}
        self._exact: dict[str, MappingRule] = {}
        alternatives: list[str] = []
        for value, rule in literals:
            body = r"\s+".join(re.escape(w) for w in value.split())
            if rule.boundary == "word" or (rule.boundary == "auto" and value[:1].isalnum()):
                body = r"(?<![A-Za-z0-9])" + body
            if rule.boundary == "word" or (rule.boundary == "auto" and value[-1:].isalnum()):
                body = body + r"(?![A-Za-z0-9])"
            if rule.case == "exact":
                self._exact[" ".join(value.split())] = rule
                alternatives.append(f"(?:{body})")
            else:
                self._by_key.setdefault(" ".join(value.split()).casefold(), rule)
                alternatives.append(f"(?i:{body})")
        self._literal = re.compile("|".join(alternatives)) if alternatives else None

    def _rule_for(self, matched: str) -> MappingRule | None:
        key = " ".join(matched.split())
        return self._exact.get(key) or self._by_key.get(key.casefold())

    def apply(self, text: str, *, code: bool = False) -> Substituted:
        """Substitute ``text``. With ``code`` set, keep columns after each replacement."""
        replacements: list[Replacement] = []
        misaligned: list[int] = []
        for rx, rule in self._regex:
            text = self._sub(rx, text, lambda m, rule=rule: rule, code, replacements, misaligned)
        if self._literal is not None:
            text = self._sub(
                self._literal,
                text,
                lambda m: self._rule_for(m.group(0)),
                code,
                replacements,
                misaligned,
            )
        return Substituted(text, replacements, misaligned)

    @staticmethod
    def _sub(
        rx: re.Pattern[str],
        text: str,
        pick: object,
        code: bool,
        replacements: list[Replacement],
        misaligned: list[int],
    ) -> str:
        out: list[str] = []
        pos = 0
        shift = 0  # len(output so far) - len(input consumed so far)
        # Replacements already recorded point into the text we are about to rewrite; move
        # them as this pass shifts text around them.
        earlier = list(replacements)
        replacements.clear()
        moved: list[tuple[int, int]] = []  # (input offset, delta) checkpoints
        for m in rx.finditer(text):
            rule = pick(m)  # type: ignore[operator]
            if rule is None or m.start() < pos:
                continue
            original = m.group(0)
            target = _case_like(original, rule.target) if rule.case == "preserve" else rule.target
            # A match across a line break keeps its breaks (and the indentation after them),
            # so the line count, and a list item's continuation, survive.
            target += "".join(re.findall(r"\n[ \t]*", original))
            out.append(text[pos : m.start()])
            end = m.end()
            if code and "\n" not in original:
                target, end, bad = _keep_columns(text, m.start(), m.end(), target)
                if bad:
                    misaligned.append(m.start() + shift)
            start_out = m.start() + shift
            out.append(target)
            replacements.append(
                Replacement(rule.index, start_out, start_out + len(target), original)
            )
            shift += len(target) - (end - m.start())
            moved.append((end, shift))
            pos = end
        out.append(text[pos:])
        for r in earlier:
            delta = 0
            for offset, d in moved:
                if offset <= r.start:
                    delta = d
            replacements.append(
                Replacement(r.rule_index, r.start + delta, r.end + delta, r.original)
            )
        replacements.sort(key=lambda r: r.start)
        return "".join(out)


def _keep_columns(text: str, start: int, end: int, target: str) -> tuple[str, int, bool]:
    """Absorb a length change into the padding that follows, when there is padding.

    Returns the (possibly padded) target, the input offset the replacement now extends to,
    and whether a longer value could not be absorbed.
    """
    delta = len(target) - (end - start)
    if delta == 0:
        return target, end, False
    line_end = text.find("\n", end)
    line_end = len(text) if line_end == -1 else line_end
    spaces = len(text[end:line_end]) - len(text[end:line_end].lstrip(" "))
    after = text[end + spaces : end + spaces + 1]
    aligned = spaces >= 2 or (spaces >= 1 and after and after in _BORDER)
    if not aligned:
        return target, end, False
    new_spaces = spaces - delta
    if new_spaces < 1:
        return target + " ", end + spaces, True
    return target + " " * new_spaces, end + spaces, False


# --- Markdown structure ------------------------------------------------------------------


@dataclass(frozen=True)
class Segment:
    text: str
    code: bool
    first_line: int  # 1-based


_FENCE = re.compile(r"^(?P<indent>[ \t]*)(?P<fence>`{3,}|~{3,})")


def segments(text: str) -> list[Segment]:
    """Split Markdown into prose and fenced-code segments, keeping every character.

    Fences may be indented (inside lists and admonitions). A fence closes on a line of the
    same character at least as long, and nothing else.
    """
    out: list[Segment] = []
    buf: list[str] = []
    in_code = False
    fence = ""
    start_line = 1
    line_no = 0
    for line in text.splitlines(keepends=True):
        line_no += 1
        m = _FENCE.match(line)
        if not in_code and m:
            if buf:
                out.append(Segment("".join(buf), False, start_line))
            buf, start_line = [line], line_no
            in_code, fence = True, m.group("fence")
            continue
        buf.append(line)
        stripped = line.strip()
        if in_code and stripped and set(stripped) == {fence[0]} and len(stripped) >= len(fence):
            out.append(Segment("".join(buf), True, start_line))
            buf, start_line, in_code = [], line_no + 1, False
    if buf:
        out.append(Segment("".join(buf), in_code, start_line))
    return out


_CODE_SPAN = re.compile(r"(`+)(?:(?!\1).)+?\1", re.DOTALL)


def _outside_code_spans(text: str) -> Iterator[tuple[int, int]]:
    """(start, end) ranges of ``text`` that are not inside inline code spans."""
    pos = 0
    for m in _CODE_SPAN.finditer(text):
        yield pos, m.start()
        pos = m.end()
    yield pos, len(text)


# --- links -------------------------------------------------------------------------------

_LINK = re.compile(
    r"(?P<bang>!?)\[(?P<text>(?:[^\[\]\n]|\[[^\[\]\n]*\])*)\]"
    r"\((?P<target><[^>\n]*>|[^\s)]+)(?P<title>\s+(?:\"[^\"\n]*\"|'[^'\n]*'))?\s*\)"
)
_AUTOLINK = re.compile(r"<(?P<url>https?://[^>\s]+)>")
_BARE_URL = re.compile(r"(?<![(<`\w])(?P<url>https?://[^\s)<>`\]]+[^\s)<>`\].,;:!?'\"])")


@dataclass
class LinkStats:
    internal: int = 0
    private: int = 0
    unpublished: int = 0
    images_omitted: int = 0


@dataclass(frozen=True)
class LinkContext:
    source_path: str  # of the page being rewritten, relative to the source docs dir
    path_map: Mapping[str, str]  # source rel path -> output rel path (both under their roots)
    private_hosts: frozenset[str]
    real_values: tuple[str, ...]  # casefolded; a URL containing one is private
    published_binaries: frozenset[str]  # source rel paths of cleared binaries
    substituter: Substituter | None = None  # re-slugs anchors whose heading was renamed


def _is_private_url(url: str, ctx: LinkContext) -> bool:
    host = (urlsplit(url).hostname or "").lower()
    if host and any(host == h or host.endswith("." + h) for h in ctx.private_hosts):
        return True
    low = url.casefold()
    return any(v in low for v in ctx.real_values)


def _as_code(text: str) -> str:
    inner = text.strip()
    if not inner:
        return ""
    if inner.startswith("`") and inner.endswith("`"):
        return inner
    if "`" in inner:
        return inner
    return f"`{inner}`"


def slugify(value: str, separator: str = "-") -> str:
    """Python-Markdown's toc slugify, so rewritten anchors match what MkDocs generates."""
    value = unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode("ascii")
    value = re.sub(r"[^\w\s-]", "", value).strip().lower()
    return re.sub(rf"[{separator}\s]+", separator, value)


def rewrite_links(text: str, ctx: LinkContext, stats: LinkStats) -> str:
    """Rewrite the links in one prose segment. Code spans are left alone."""
    parts: list[str] = []
    last = 0
    for lo, hi in _outside_code_spans(text):
        parts.append(text[last:lo])
        parts.append(_rewrite_region(text[lo:hi], ctx, stats))
        last = hi
    parts.append(text[last:])
    return "".join(parts)


def _rewrite_region(region: str, ctx: LinkContext, stats: LinkStats) -> str:
    def link(m: re.Match[str]) -> str:
        bang, label, target = m.group("bang"), m.group("text"), m.group("target").strip("<>")
        title = m.group("title") or ""
        if target.startswith("#"):
            return m.group(0)
        scheme = urlsplit(target).scheme
        if scheme:
            if _is_private_url(target, ctx):
                stats.private += 1
                return f"*{label or 'image'}*" if bang else _as_code(label or target)
            return m.group(0)
        path, _, anchor = target.partition("#")
        resolved = posixpath.normpath(posixpath.join(posixpath.dirname(ctx.source_path), path))
        if bang:
            if resolved in ctx.published_binaries and resolved in ctx.path_map:
                return f"{bang}[{label}]({_relative(ctx, resolved)}{title})"
            stats.images_omitted += 1
            return f"*{label or 'image'}*"
        if resolved in ctx.path_map and not resolved.startswith("../"):
            stats.internal += 1
            new = _relative(ctx, resolved)
            if anchor and ctx.substituter is not None:
                # The heading this points at is renamed by the same mapping, so its slug
                # moves with it. A placeholder with a space would otherwise break the link.
                anchor = slugify(ctx.substituter.apply(anchor).text)
            return f"[{label}]({new}{'#' + anchor if anchor else ''}{title})"
        stats.unpublished += 1
        return _as_code(label or path)

    region = _LINK.sub(link, region)

    def auto(m: re.Match[str]) -> str:
        if _is_private_url(m.group("url"), ctx):
            stats.private += 1
            return f"`{m.group('url')}`"
        return m.group(0)

    region = _AUTOLINK.sub(auto, region)

    def bare(m: re.Match[str]) -> str:
        if _is_private_url(m.group("url"), ctx):
            stats.private += 1
            return f"`{m.group('url')}`"
        return m.group(0)

    return _BARE_URL.sub(bare, region)


def _relative(ctx: LinkContext, resolved: str) -> str:
    here = posixpath.dirname(ctx.path_map[ctx.source_path])
    return posixpath.relpath(ctx.path_map[resolved], here or ".")


# --- damage ------------------------------------------------------------------------------


@dataclass(frozen=True)
class Damage:
    kind: str  # doubled-word | redundant-parenthetical | article | misaligned | code-punctuation
    path: str  # OUTPUT path
    line: int  # 1-based, in the output file
    #: the paragraph (prose) or line (code) to repair, as it stands in the output
    block_start: int
    block_end: int  # exclusive line numbers


_DOUBLED = re.compile(r"(?i)(?<![\w-])(\w+)\s+\1(?![\w-])")
_REDUNDANT = re.compile(r"(?i)(?<![\w-])([\w][\w .-]{2,}?)\s*\(\s*\1\s*\)")
_ARTICLE = re.compile(r"(?i)(?<![\w-])(a|an)\s+$")
_STRUCTURAL = set(",;:{}[]()\"'=")


def _starts_with_vowel_sound(word: str) -> bool:
    return word[:1].lower() in "aeiou"


def find_damage(
    output_path: str,
    before: str,
    after: str,
    replacements: Sequence[Replacement],
    code: bool,
    first_line: int,
) -> list[Damage]:
    """Damage the replacements in one segment may have caused.

    Only damage that touches a replacement and was not already in the source is reported:
    "that that" in the source was the author's, not ours.
    """
    found: list[Damage] = []
    lines = after.splitlines(keepends=True)
    starts = [0]
    for ln in lines:
        starts.append(starts[-1] + len(ln))

    def line_of(offset: int) -> int:
        lo, hi = 0, len(starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if starts[mid] <= offset:
                lo = mid
            else:
                hi = mid - 1
        return lo

    def paragraph(idx: int) -> tuple[int, int]:
        a = idx
        while a > 0 and lines[a - 1].strip():
            a -= 1
        b = idx
        while b + 1 < len(lines) and lines[b + 1].strip():
            b += 1
        return first_line + a, first_line + b + 1

    def touches(start: int, end: int) -> bool:
        return any(r.start <= end and start <= r.end for r in replacements)

    def record(kind: str, offset: int) -> None:
        idx = line_of(offset)
        a, b = (first_line + idx, first_line + idx + 1) if code else paragraph(idx)
        found.append(Damage(kind, output_path, first_line + idx, a, b))

    if code:
        for r in replacements:
            gone = Counter(c for c in r.original if c in _STRUCTURAL)
            came = Counter(c for c in after[r.start : r.end] if c in _STRUCTURAL)
            if gone != came:
                record("code-punctuation", r.start)
        return found

    source_doubles = Counter(m.group(0).casefold() for m in _DOUBLED.finditer(before))
    for m in _DOUBLED.finditer(after):
        if touches(m.start(), m.end()) and source_doubles[m.group(0).casefold()] == 0:
            record("doubled-word", m.start())
    for m in _REDUNDANT.finditer(after):
        if touches(m.start(), m.end()):
            record("redundant-parenthetical", m.start())
    for r in replacements:
        new = after[r.start : r.end].lstrip()
        am = _ARTICLE.search(after[max(0, r.start - 4) : r.start])
        if am and new:
            wants_an = _starts_with_vowel_sound(new)
            if (am.group(1).lower() == "an") != wants_an and (
                (am.group(1).lower() == "an") == _starts_with_vowel_sound(r.original)
            ):
                record("article", r.start)
    return found


# --- files and trees ---------------------------------------------------------------------


GENERATED_NOTE = (
    '!!! note "Generated section"\n'
    "    These pages are generated from a private upstream by docs-distributor and replaced\n"
    "    on every sync. Edit them upstream; changes made here are overwritten.\n"
)
GENERATED_NOTE_LINES = GENERATED_NOTE.count("\n") + 1  # the note plus a blank line after it


def add_generated_note(text: str) -> str:
    """Put the note after the page's first H1 (or at the top when there is none)."""
    lines = text.splitlines(keepends=True)
    for i, line in enumerate(lines):
        if line.startswith("# "):
            head = "".join(lines[: i + 1])
            if not head.endswith("\n"):
                head += "\n"
            return head + "\n" + GENERATED_NOTE + "".join(lines[i + 1 :])
    return GENERATED_NOTE + "\n" + text


@dataclass
class FileOut:
    output_path: str
    content: bytes
    replacements: int = 0
    damage: list[Damage] = field(default_factory=list)
    misaligned: int = 0


@dataclass
class TreeOut:
    files: dict[str, FileOut]  # keyed by output path relative to the docs repo root
    path_map: dict[str, str]  # source rel path -> output rel path under the target dir (PRIVATE)
    dropped: list[str]  # source rel paths not published (PRIVATE)
    links: LinkStats
    rule_hits: Counter[int]
    warnings: list[str]


def _slug_segment(segment: str) -> str:
    stem, dot, ext = segment.rpartition(".") if "." in segment else (segment, "", "")
    stem = unicodedata.normalize("NFKD", stem).encode("ascii", "ignore").decode("ascii").lower()
    stem = re.sub(r"[^a-z0-9._-]+", "-", stem)
    stem = re.sub(r"-{2,}", "-", stem).strip("-") or "page"
    return f"{stem}{dot}{ext.lower()}"


def plan_paths(
    sources: Iterable[str], substituter: Substituter, rename: Mapping[str, str]
) -> tuple[dict[str, str], list[str]]:
    """Output path (under the target dir) for every published source path.

    An explicit rename wins. Otherwise the mapping is applied to the path and each segment is
    slugged, so a real name in a file or directory name is replaced like anywhere else.
    Returns the map and a list of problems (collisions).
    """
    out: dict[str, str] = {}
    problems: list[str] = []
    taken: dict[str, str] = {}
    for src in sorted(sources):
        if src in rename:
            new = rename[src]
        else:
            anon = substituter.apply(src).text
            new = "/".join(_slug_segment(s) for s in anon.split("/"))
        if new in taken:
            problems.append(f"two source files would publish to the same path ({new})")
            continue
        taken[new] = src
        out[src] = new
    return out, problems


def selected(
    path: str, include: Sequence[str], exclude: Sequence[str], drop: Sequence[str]
) -> bool:
    def match(globs: Sequence[str]) -> bool:
        return any(
            fnmatchcase(path, g) or (g.startswith("**/") and fnmatchcase(path, g[3:]))
            for g in globs
        )

    return match(include) and not match(exclude) and not match(drop)


def transform_markdown(
    source_rel: str,
    text: str,
    output_path: str,
    substituter: Substituter,
    ctx: LinkContext,
    stats: LinkStats,
    rule_hits: Counter[int],
) -> FileOut:
    out_parts: list[str] = []
    damage: list[Damage] = []
    count = 0
    misaligned = 0
    line = 1
    for seg in segments(text):
        body = seg.text if seg.code else rewrite_links(seg.text, ctx, stats)
        result = substituter.apply(body, code=seg.code)
        count += len(result.replacements)
        misaligned += len(result.misaligned)
        for r in result.replacements:
            rule_hits[r.rule_index] += 1
        damage.extend(
            find_damage(output_path, body, result.text, result.replacements, seg.code, line)
        )
        for offset in result.misaligned:
            idx = result.text.count("\n", 0, offset)
            damage.append(Damage("misaligned", output_path, line + idx, line + idx, line + idx + 1))
        out_parts.append(result.text)
        line += seg.text.count("\n")
    return FileOut(output_path, "".join(out_parts).encode("utf-8"), count, damage, misaligned)


def is_text(data: bytes) -> bool:
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return b"\x00" not in data


def transform_tree(
    files: Mapping[str, bytes],
    *,
    target_dir: str,
    substituter: Substituter,
    include: Sequence[str],
    exclude: Sequence[str] = (),
    drop: Sequence[str] = (),
    rename: Mapping[str, str] | None = None,
    private_hosts: Iterable[str] = (),
    real_values: Iterable[str] = (),
    cleared_binaries: Mapping[str, str] | None = None,
    index_note: bool = True,
) -> TreeOut:
    """Transform one source's docs directory (``files`` keyed by path relative to it).

    ``cleared_binaries`` maps source-relative path -> sha256 for binaries a human cleared;
    every other binary is left out and any image pointing at it is replaced by its alt text.
    """
    cleared = dict(cleared_binaries or {})
    chosen = [p for p in sorted(files) if selected(p, include, exclude, drop)]
    dropped = [p for p in sorted(files) if p not in chosen]
    publish: list[str] = []
    for p in chosen:
        data = files[p]
        if is_text(data) or cleared.get(p) == hashlib.sha256(data).hexdigest():
            publish.append(p)
        else:
            dropped.append(p)
    path_map, problems = plan_paths(publish, substituter, rename or {})
    ctx = LinkContext(
        source_path="",
        path_map=path_map,
        private_hosts=frozenset(h.lower() for h in private_hosts),
        real_values=tuple(sorted({v.casefold() for v in real_values if v}, key=len, reverse=True)),
        published_binaries=frozenset(p for p in publish if not is_text(files[p])),
        substituter=substituter,
    )
    stats = LinkStats()
    hits: Counter[int] = Counter()
    out: dict[str, FileOut] = {}
    for src in sorted(path_map):
        output_path = f"{target_dir}/{path_map[src]}"
        data = files[src]
        if not is_text(data):
            out[output_path] = FileOut(output_path, data)
            continue
        text = data.decode("utf-8")
        if src.endswith(".md"):
            page_ctx = LinkContext(
                src,
                ctx.path_map,
                ctx.private_hosts,
                ctx.real_values,
                ctx.published_binaries,
                substituter,
            )
            if index_note and src == "index.md":
                # Before the transform, so damage is reported at the lines it will occupy.
                text = add_generated_note(text)
            out[output_path] = transform_markdown(
                src, text, output_path, substituter, page_ctx, stats, hits
            )
        else:
            result = substituter.apply(text, code=True)
            for r in result.replacements:
                hits[r.rule_index] += 1
            out[output_path] = FileOut(
                output_path, result.text.encode("utf-8"), len(result.replacements)
            )
    return TreeOut(out, path_map, sorted(dropped), stats, hits, problems)
