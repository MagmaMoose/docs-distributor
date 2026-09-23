"""The deterministic transform. Every value here is synthetic."""

from __future__ import annotations

from collections import Counter

from docs_distributor import config
from docs_distributor.transform import (
    GENERATED_NOTE,
    LinkContext,
    LinkStats,
    Substituter,
    find_damage,
    plan_paths,
    rewrite_links,
    segments,
    slugify,
    transform_tree,
)

VOCAB = config.load_vocabulary()


def subst(*rules: dict[str, object]) -> Substituter:
    m = config.parse_mapping([("m", {"rules": list(rules)})], VOCAB)
    return Substituter(m.rules)


HB = subst(
    {"from": "Hollowbrook Logistics", "to": "the platform owner", "class": "org"},
    {"from": "Hollowbrook", "to": "example-org", "class": "org"},
    {"from": "hollowbrook.nl", "to": "example.com", "class": "domain"},
    {"from": "git.hollowbrook.internal", "to": "git.example.com", "class": "host"},
    {"from": "Brackenfold", "to": "vendor-C", "class": "vendor", "case": "preserve"},
    {"from": "Jan de Vries", "to": "engineer-e", "class": "person"},
    {"from": "hb-prd-west", "to": "cluster-prd", "class": "cluster"},
)


# --- substitution ------------------------------------------------------------------------


def test_longest_value_wins_and_placeholders_are_not_substituted_again() -> None:
    out = HB.apply("Hollowbrook Logistics runs Hollowbrook on hollowbrook.nl").text
    assert out == "the platform owner runs example-org on example.com"


def test_word_boundaries_protect_longer_words() -> None:
    assert HB.apply("HollowbrookX and xHollowbrook").text == "HollowbrookX and xHollowbrook"
    assert HB.apply("pr-Hollowbrook-prd").text == "pr-example-org-prd"


def test_case_preserve() -> None:
    assert HB.apply("BRACKENFOLD brackenfold Brackenfold").text == "VENDOR-C vendor-c Vendor-C"


def test_match_across_a_line_break_keeps_the_line_count() -> None:
    src = "- Ask Jan de\n  Vries about it\n"
    out = HB.apply(src).text
    assert out.count("\n") == src.count("\n")
    assert out == "- Ask engineer-e\n   about it\n"


def test_replacements_are_recorded_with_output_offsets() -> None:
    res = HB.apply("x Hollowbrook y hollowbrook.nl")
    spans = [res.text[r.start : r.end] for r in res.replacements]
    assert spans == ["example-org", "example.com"]
    assert [r.original for r in res.replacements] == ["Hollowbrook", "hollowbrook.nl"]


def test_code_padding_absorbs_shorter_values_so_columns_hold() -> None:
    block = (
        "├── hb-prd-west/          # the production cluster\n"
        "├── staging/              # the staging cluster\n"
    )
    out = HB.apply(block, code=True).text
    first, second = out.splitlines()
    assert first.index("#") == second.index("#")
    assert "cluster-prd/" in first


def test_box_border_stays_aligned() -> None:
    block = "│ Hollowbrook Logistics │\n│ ingest                │\n"
    out = HB.apply(block, code=True).text
    a, b = out.splitlines()
    assert len(a) == len(b)


def test_value_too_long_for_its_padding_is_reported() -> None:
    s = subst({"from": "hb", "to": "a-much-longer-name", "class": "org"})
    res = s.apply("│ hb │\n", code=True)
    assert res.misaligned


# --- markdown structure ------------------------------------------------------------------


def test_segments_split_prose_and_indented_fences_and_keep_every_character() -> None:
    text = "intro\n\n!!! note\n    ```bash\n    echo Hollowbrook\n    ```\n\nafter\n"
    segs = segments(text)
    assert "".join(s.text for s in segs) == text
    assert [s.code for s in segs] == [False, True, False]
    assert segs[1].first_line == 4


# --- links -------------------------------------------------------------------------------


def ctx(source: str = "guide/setup.md") -> LinkContext:
    return LinkContext(
        source_path=source,
        path_map={
            "guide/setup.md": "guide/setup.md",
            "hollowbrook-notes.md": "example-org-notes.md",
            "index.md": "index.md",
        },
        private_hosts=frozenset({"git.hollowbrook.internal"}),
        real_values=("hollowbrook",),
        published_binaries=frozenset(),
        substituter=HB,
    )


def test_internal_link_follows_a_renamed_page() -> None:
    stats = LinkStats()
    out = rewrite_links("see [notes](../hollowbrook-notes.md#hollowbrook-setup)", ctx(), stats)
    assert out == "see [notes](../example-org-notes.md#example-org-setup)"
    assert stats.internal == 1


def test_link_into_a_private_host_becomes_a_code_span() -> None:
    stats = LinkStats()
    out = rewrite_links("[infra repo](https://git.hollowbrook.internal/ops/infra)", ctx(), stats)
    assert out == "`infra repo`"
    assert stats.private == 1


def test_link_whose_url_carries_a_real_value_becomes_a_code_span() -> None:
    out = rewrite_links("[the PR](https://github.com/hollowbrook/infra/pull/7)", ctx(), LinkStats())
    assert out == "`the PR`"


def test_public_links_are_untouched() -> None:
    text = "[k8s](https://kubernetes.io/docs/) and <https://github.com/fluxcd/flux2>"
    assert rewrite_links(text, ctx(), LinkStats()) == text


def test_link_outside_the_published_tree_becomes_a_code_span() -> None:
    stats = LinkStats()
    assert rewrite_links("[readme](../../README.md)", ctx(), stats) == "`readme`"
    assert stats.unpublished == 1


def test_links_inside_code_spans_are_left_alone() -> None:
    text = "use `[x](https://git.hollowbrook.internal/y)` literally"
    assert rewrite_links(text, ctx(), LinkStats()) == text


def test_private_bare_and_auto_links_become_code() -> None:
    out = rewrite_links(
        "clone https://git.hollowbrook.internal/ops/infra or <https://git.hollowbrook.internal/x>",
        ctx(),
        LinkStats(),
    )
    assert (
        out
        == "clone `https://git.hollowbrook.internal/ops/infra` or `https://git.hollowbrook.internal/x`"
    )


def test_uncleared_image_is_replaced_by_its_alt_text() -> None:
    stats = LinkStats()
    assert rewrite_links("![topology](img/net.png)", ctx(), stats) == "*topology*"
    assert stats.images_omitted == 1


def test_slugify_matches_python_markdown() -> None:
    assert slugify("Example-org Setup & Access!") == "example-org-setup-access"


# --- paths -------------------------------------------------------------------------------


def test_paths_are_anonymised_and_slugged() -> None:
    mapping, problems = plan_paths(
        ["deployment/hollowbrook-acc.md", "Jan de Vries/notes.md"], HB, rename={}
    )
    assert mapping["deployment/hollowbrook-acc.md"] == "deployment/example-org-acc.md"
    assert mapping["Jan de Vries/notes.md"] == "engineer-e/notes.md"
    assert problems == []


def test_explicit_rename_wins_and_collisions_are_reported() -> None:
    mapping, problems = plan_paths(
        ["a.md", "b.md"], HB, rename={"a.md": "same.md", "b.md": "same.md"}
    )
    assert problems
    mapping, problems = plan_paths(["a.md"], HB, rename={"a.md": "renamed/page.md"})
    assert mapping == {"a.md": "renamed/page.md"}


# --- damage ------------------------------------------------------------------------------


def damage_kinds(s: Substituter, text: str) -> list[str]:
    res = s.apply(text)
    return [d.kind for d in find_damage("p.md", text, res.text, res.replacements, False, 1)]


def test_doubled_word_introduced_by_substitution_is_reported() -> None:
    s = subst({"from": "Hollowbrook platform", "to": "the platform", "class": "org"})
    assert damage_kinds(s, "Deploy to the Hollowbrook platform today.\n") == ["doubled-word"]


def test_doubled_word_already_in_the_source_is_not_ours() -> None:
    s = subst({"from": "Hollowbrook", "to": "example-org", "class": "org"})
    assert damage_kinds(s, "the the Hollowbrook cluster\n") == []


def test_redundant_parenthetical_is_reported() -> None:
    s = subst({"from": "Chargewall", "to": "Security Gate", "class": "product"})
    assert damage_kinds(s, "Security Gate (Chargewall) runs on every PR.\n") == [
        "redundant-parenthetical"
    ]


def test_article_that_no_longer_agrees_is_reported() -> None:
    s = subst({"from": "Hollowbrook", "to": "example-org", "class": "org"})
    assert damage_kinds(s, "It is a Hollowbrook cluster.\n") == ["article"]
    assert (
        damage_kinds(s, "It is an Hollowbrook cluster.\n") == []
    )  # the author's mistake, not ours


def test_code_substitution_that_changes_punctuation_is_reported() -> None:
    s = subst({"from": r"hb-west,", "to": "cluster-a", "class": "cluster", "regex": True})
    res = s.apply('clusters = ["hb-west", "hb-east"]\nlist = [hb-west, x]\n', code=True)
    kinds = [d.kind for d in find_damage("p.md", "", res.text, res.replacements, True, 1)]
    assert kinds == ["code-punctuation"]


# --- trees -------------------------------------------------------------------------------


def test_tree_transform_end_to_end() -> None:
    files = {
        "index.md": b"# Hollowbrook docs\n\nSee [setup](guide/setup.md).\n",
        "guide/setup.md": b"# Setup\n\nClone [infra](https://git.hollowbrook.internal/ops/infra).\n",
        "hollowbrook-notes.md": b"notes\n",
        "scratch/todo.md": b"private\n",
        "img/diagram.png": b"\x89PNG\r\n\x1a\n\x00",
    }
    out = transform_tree(
        files,
        target_dir="docs/cloud",
        substituter=HB,
        include=("**/*.md", "**/*.png"),
        drop=("scratch/**",),
        private_hosts=("git.hollowbrook.internal",),
        real_values=("hollowbrook",),
    )
    assert sorted(out.files) == [
        "docs/cloud/example-org-notes.md",
        "docs/cloud/guide/setup.md",
        "docs/cloud/index.md",
    ]
    index = out.files["docs/cloud/index.md"].content.decode()
    assert index.startswith("# example-org docs\n\n" + GENERATED_NOTE)
    assert "[setup](guide/setup.md)" in index
    assert out.files["docs/cloud/guide/setup.md"].content.decode().endswith("Clone `infra`.\n")
    assert out.dropped == ["img/diagram.png", "scratch/todo.md"]
    assert out.links.private == 1


def test_tree_transform_is_deterministic() -> None:
    files = {"index.md": b"# Hollowbrook\n", "a.md": b"Jan de Vries at hollowbrook.nl\n"}
    kw = {"target_dir": "docs/x", "substituter": HB, "include": ("**/*.md",)}
    one = {k: v.content for k, v in transform_tree(files, **kw).files.items()}  # type: ignore[arg-type]
    two = {k: v.content for k, v in transform_tree(files, **kw).files.items()}  # type: ignore[arg-type]
    assert one == two
    assert Counter(transform_tree(files, **kw).rule_hits)  # type: ignore[arg-type]


def test_padding_after_the_rest_of_the_token_is_used_and_punctuation_is_not_misread() -> None:
    s = subst({"from": "hb-acc", "to": "cluster-acceptance", "class": "cluster"})
    block = "├── hb-acc/                 # acceptance\n├── shared/                 # dns\n"
    res = s.apply(block, code=True)
    a, b = res.text.splitlines()
    assert a.index("#") == b.index("#")
    yaml_line = "hb-acc:                value\nother:                 value\n"
    res = s.apply(yaml_line, code=True)
    assert [
        d.kind for d in find_damage("p.md", yaml_line, res.text, res.replacements, True, 1)
    ] == []
    a, b = res.text.splitlines()
    assert a.index("value") == b.index("value")
