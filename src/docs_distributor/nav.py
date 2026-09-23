"""Nav generation: Python only.

The source's own MkDocs nav is the layout. Titles go through the same mapping as the pages,
paths follow the pages to their published locations, and the result is rendered as one
block of YAML that replaces the block between this source's markers in the docs repo's
``mkdocs.yml``:

    # >>> docs-distributor: cloud-platform
    - Cloud Platform:
      - cloud-platform/index.md
      ...
    # <<< docs-distributor: cloud-platform

Everything outside the markers is left byte-for-byte alone. A page the source nav does not
list is placed by :meth:`docs_distributor.llm.LLM.place` when that is available and by a
fixed rule when it is not (a section named after its directory, else the end of the set);
either way the YAML itself is written here.
"""

from __future__ import annotations

import json
import posixpath
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

NavItem = Any  # str | dict[str, str | list[NavItem]]


@dataclass
class Node:
    """One entry of the generated nav: a section (children) or a page (path)."""

    title: str | None
    path: str | None = None
    children: list[Node] = field(default_factory=list)

    @property
    def is_section(self) -> bool:
        return self.path is None


def parse(nav: Sequence[NavItem] | None) -> list[Node]:
    out: list[Node] = []
    for item in nav or []:
        if isinstance(item, str):
            out.append(Node(None, item))
        elif isinstance(item, dict):
            for title, value in item.items():
                if isinstance(value, str):
                    out.append(Node(str(title), value))
                elif isinstance(value, list):
                    out.append(Node(str(title), None, parse(value)))
    return out


def pages(nodes: Sequence[Node]) -> list[str]:
    found: list[str] = []
    for n in nodes:
        if n.is_section:
            found.extend(pages(n.children))
        elif n.path:
            found.append(n.path)
    return found


def sections(nodes: Sequence[Node], prefix: tuple[str, ...] = ()) -> list[tuple[str, ...]]:
    out: list[tuple[str, ...]] = []
    for n in nodes:
        if n.is_section and n.title:
            here = (*prefix, n.title)
            out.append(here)
            out.extend(sections(n.children, here))
    return out


def rebuild(
    nodes: Sequence[Node],
    *,
    path_map: Mapping[str, str],
    rename_title: Callable[[str], str],
    prefix: str,
) -> tuple[list[Node], list[str]]:
    """The source nav with every page moved to its published path and every title passed
    through the mapping. Pages that are not published are dropped (and reported)."""
    dropped: list[str] = []

    def walk(items: Sequence[Node]) -> list[Node]:
        out: list[Node] = []
        for n in items:
            if n.is_section:
                kids = walk(n.children)
                if kids:
                    out.append(Node(rename_title(n.title or ""), None, kids))
                continue
            src = posixpath.normpath(n.path or "")
            if src not in path_map:
                dropped.append(src)
                continue
            out.append(
                Node(rename_title(n.title) if n.title else None, f"{prefix}/{path_map[src]}")
            )
        return out

    return walk(nodes), dropped


def place(
    nodes: list[Node],
    page_path: str,
    title: str,
    section: Sequence[str],
) -> None:
    """Append a page at the end of ``section`` (a path of section titles; empty = top)."""
    target = nodes
    for name in section:
        match = next((n for n in target if n.is_section and n.title == name), None)
        if match is None:
            break
        target = match.children
    target.append(Node(title, page_path))


def fallback_section(nodes: Sequence[Node], output_rel: str) -> tuple[str, ...]:
    """Where a page goes when nobody chose: the first section named like its directory."""
    parent = posixpath.dirname(output_rel).split("/")[-1].replace("-", " ").casefold()
    for s in sections(nodes):
        if s[-1].casefold() == parent:
            return s
    return ()


def section_index_first(nodes: list[Node], index_path: str) -> list[Node]:
    """Put the section's index page first and untitled, which is how Material's
    navigation.indexes makes it the section's landing page."""
    rest = [n for n in nodes if n.path != index_path]
    return [Node(None, index_path), *rest] if len(rest) != len(nodes) else nodes


# --- rendering and splicing --------------------------------------------------------------

_PLAIN = re.compile(r"[A-Za-z0-9(][^:#\n]*")
_YAML_WORDS = frozenset("true false yes no on off null ~".split())


def _scalar(value: str) -> str:
    if (
        _PLAIN.fullmatch(value)
        and not value.endswith(" ")
        and value.casefold() not in _YAML_WORDS
        and not re.search(r"[\[\]{},&*!|>'\"%@`]", value[:1])
    ):
        return value
    return json.dumps(value, ensure_ascii=False)


def render(nodes: Sequence[Node], indent: str, step: str = "  ") -> list[str]:
    lines: list[str] = []
    for n in nodes:
        if n.is_section:
            lines.append(f"{indent}- {_scalar(n.title or '')}:")
            lines.extend(render(n.children, indent + step, step))
        elif n.title:
            lines.append(f"{indent}- {_scalar(n.title)}: {n.path}")
        else:
            lines.append(f"{indent}- {n.path}")
    return lines


def markers(name: str) -> tuple[str, str]:
    return f"# >>> docs-distributor: {name}", f"# <<< docs-distributor: {name}"


def block(name: str, title: str, nodes: Sequence[Node], indent: str) -> str:
    begin, end = markers(name)
    body = render([Node(title, None, list(nodes))], indent)
    return (
        "\n".join([f"{indent}{begin} (generated; edit upstream)", *body, f"{indent}{end}"]) + "\n"
    )


class SpliceError(ValueError):
    pass


def splice(
    mkdocs_text: str, name: str, new_block_for: Callable[[str], str], nav_after: str | None
) -> str:
    """Replace this source's block in ``mkdocs_text``, or insert it after the top-level nav
    entry titled ``nav_after`` (else at the end of the nav). ``new_block_for(indent)``
    renders the block at the indent the file uses for its top-level nav items."""
    lines = mkdocs_text.splitlines(keepends=True)
    begin, end = markers(name)
    starts = [i for i, ln in enumerate(lines) if ln.strip().startswith(begin)]
    ends = [i for i, ln in enumerate(lines) if ln.strip() == end]
    if starts or ends:
        if len(starts) != 1 or len(ends) != 1 or ends[0] < starts[0]:
            raise SpliceError(f"mkdocs.yml has broken docs-distributor markers for {name}")
        indent = lines[starts[0]][: len(lines[starts[0]]) - len(lines[starts[0]].lstrip())]
        return "".join(lines[: starts[0]]) + new_block_for(indent) + "".join(lines[ends[0] + 1 :])

    nav_at = next((i for i, ln in enumerate(lines) if re.match(r"^nav:\s*$", ln)), None)
    if nav_at is None:
        raise SpliceError("mkdocs.yml has no top-level nav: to add the section to")
    first_item = next(
        (i for i in range(nav_at + 1, len(lines)) if lines[i].lstrip().startswith("- ")), None
    )
    if first_item is None:
        raise SpliceError("mkdocs.yml has an empty nav")
    indent = lines[first_item][: len(lines[first_item]) - len(lines[first_item].lstrip())]

    def nav_end() -> int:
        for i in range(first_item, len(lines)):
            ln = lines[i]
            if ln.strip() and not ln.startswith(indent) and not ln.lstrip().startswith("#"):
                return i
        return len(lines)

    stop = nav_end()
    insert_at = stop
    if nav_after:
        head = re.compile(rf"^{re.escape(indent)}- {re.escape(nav_after)}:\s*$")
        at = next((i for i in range(first_item, stop) if head.match(lines[i])), None)
        if at is not None:
            insert_at = next(
                (i for i in range(at + 1, stop) if lines[i].startswith(indent + "- ")),
                stop,
            )
    return "".join(lines[:insert_at]) + new_block_for(indent) + "".join(lines[insert_at:])
