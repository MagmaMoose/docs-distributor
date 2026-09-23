"""Nav generation and splicing. Synthetic names only."""

from __future__ import annotations

import pytest
import yaml

from docs_distributor import nav

SOURCE_NAV = [
    {"Home": "index.md"},
    {
        "Networking": [
            {"Hollowbrook Network": "networking/hollowbrook.md"},
            {"Peering": "networking/peering.md"},
        ]
    },
    {"Operations": [{"Scratch": "scratch/todo.md"}]},
]
PATH_MAP = {
    "index.md": "index.md",
    "networking/hollowbrook.md": "networking/example-org.md",
    "networking/peering.md": "networking/peering.md",
}

DOCS_MKDOCS = """site_name: Docs
nav:
  - Home: index.md
  - Platform:
    - platform/index.md
    - Setup: platform/setup.md
  - Programming:
    - Bash: programming/bash.md
markdown_extensions:
  - admonition
"""


def build() -> list[nav.Node]:
    nodes, dropped = nav.rebuild(
        nav.parse(SOURCE_NAV),
        path_map=PATH_MAP,
        rename_title=lambda t: t.replace("Hollowbrook", "example-org"),
        prefix="cloud",
    )
    assert dropped == ["scratch/todo.md"]
    return nav.section_index_first(nodes, "cloud/index.md")


def test_rebuild_moves_pages_renames_titles_and_drops_empty_sections() -> None:
    lines = nav.render(build(), "")
    assert lines == [
        "- cloud/index.md",
        "- Networking:",
        "  - example-org Network: cloud/networking/example-org.md",
        "  - Peering: cloud/networking/peering.md",
    ]


def test_splice_inserts_after_the_named_entry_and_is_valid_yaml() -> None:
    nodes = build()
    out = nav.splice(
        DOCS_MKDOCS,
        "cloud",
        lambda ind: nav.block("cloud", "Cloud Platform", nodes, ind),
        "Platform",
    )
    parsed = yaml.safe_load(out)
    titles = [next(iter(i)) if isinstance(i, dict) else i for i in parsed["nav"]]
    assert titles == ["Home", "Platform", "Cloud Platform", "Programming"]
    assert parsed["nav"][2]["Cloud Platform"][0] == "cloud/index.md"
    assert out.startswith("site_name: Docs\nnav:\n  - Home: index.md\n")
    assert out.endswith("markdown_extensions:\n  - admonition\n")


def test_splice_replaces_its_own_block_and_nothing_else() -> None:
    nodes = build()
    once = nav.splice(
        DOCS_MKDOCS,
        "cloud",
        lambda ind: nav.block("cloud", "Cloud Platform", nodes, ind),
        "Platform",
    )
    twice = nav.splice(
        once, "cloud", lambda ind: nav.block("cloud", "Cloud Platform", nodes, ind), "Platform"
    )
    assert once == twice
    renamed = nav.splice(
        once, "cloud", lambda ind: nav.block("cloud", "Hybrid Cloud", nodes, ind), None
    )
    assert "Hybrid Cloud" in renamed and "Cloud Platform" not in renamed
    assert renamed.replace("Hybrid Cloud", "Cloud Platform") == once


def test_splice_appends_when_the_anchor_entry_is_missing() -> None:
    out = nav.splice(
        DOCS_MKDOCS, "cloud", lambda ind: nav.block("cloud", "Cloud", build(), ind), "Nope"
    )
    titles = [next(iter(i)) if isinstance(i, dict) else i for i in yaml.safe_load(out)["nav"]]
    assert titles[-1] == "Cloud"


def test_broken_markers_are_refused() -> None:
    begin, _ = nav.markers("cloud")
    with pytest.raises(nav.SpliceError):
        nav.splice(
            DOCS_MKDOCS.replace("  - Home", f"  {begin}\n  - Home"), "cloud", lambda i: "", None
        )


def test_titles_that_need_quoting_are_quoted() -> None:
    lines = nav.render(
        [
            nav.Node("Keys: rotation #2", "a.md"),
            nav.Node("yes", "b.md"),
            nav.Node("Onboarding & Access", "c.md"),
        ],
        "",
    )
    assert yaml.safe_load("\n".join(lines)) == [
        {"Keys: rotation #2": "a.md"},
        {"yes": "b.md"},
        {"Onboarding & Access": "c.md"},
    ]


def test_unlisted_page_falls_back_to_a_section_named_like_its_directory() -> None:
    nodes = build()
    assert nav.fallback_section(nodes, "networking/new-page.md") == ("Networking",)
    assert nav.fallback_section(nodes, "elsewhere/new-page.md") == ()
    nav.place(nodes, "cloud/networking/new-page.md", "New Page", ("Networking",))
    assert nav.render(nodes, "")[-1] == "  - New Page: cloud/networking/new-page.md"
