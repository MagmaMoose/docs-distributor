"""Candidate detection. Synthetic names only."""

from __future__ import annotations

from docs_distributor.novelty import Lexicon, load_tech_vocabulary, scan

LEX = Lexicon.build(
    tech=load_tech_vocabulary(),
    allow=("Brackenfold",),
    placeholder_values=("example-org", "client-a", "vendor-C", "engineer-e"),
)


def terms(text: str, path: str = "docs/x/page.md") -> dict[str, tuple[str, ...]]:
    return {c.term: c.reasons for c in scan({path: text}, LEX)}


def test_unknown_word_is_a_candidate_and_english_is_not() -> None:
    found = terms("The Hollowbrook cluster runs the ingress controller.\n")
    assert found == {"Hollowbrook": ("unknown-word",)}


def test_compound_identifiers_report_the_unknown_part() -> None:
    found = terms("```\nkubectl --context pr-prd-hollowbrook get pods\n```\n")
    assert set(found) == {"hollowbrook"}


def test_camel_case_is_known_when_every_piece_is() -> None:
    assert terms("Apply the ExternalSecret and the CloudNativePG cluster.\n") == {}
    assert "iHollowbrook" in terms("The iHollowbrook suite.\n")


def test_trailing_digits_are_stripped_before_the_lookup() -> None:
    assert "jdoe42" in terms("committed by jdoe42\n")
    assert terms("flux2 and k3s and ipv4\n") == {}


def test_proper_noun_mid_sentence_is_a_candidate_even_when_it_is_a_word() -> None:
    assert terms("The cluster is hosted in Lisbon today.\n") == {"Lisbon": ("proper-noun",)}


def test_forced_capitals_are_not_proper_nouns() -> None:
    text = "# Lisbon Rollout\n\nLisbon is where it runs.\n\n| Lisbon | 10.0.0.0/8 |\n"
    assert terms(text) == {}


def test_known_products_capitalised_mid_sentence_are_not_asked_about() -> None:
    assert terms("We deploy with Helm and store secrets in Vault via Kubernetes.\n") == {}


def test_allowlisted_and_placeholder_terms_are_known() -> None:
    assert terms("Brackenfold hosts example-org for client-a and vendor-C.\n") == {}


def test_code_blocks_only_report_unknown_words() -> None:
    text = "```\nresource Lisbon hollowbrookvault\n```\n"
    assert terms(text) == {"hollowbrookvault": ("unknown-word",)}


def test_hex_ids_and_short_tokens_are_left_to_the_pattern_layer() -> None:
    assert terms("digest 3d3c42e5aac5 and id ab and x1\n") == {}


def test_first_location_contexts_and_counts_are_recorded() -> None:
    files = {
        "docs/x/b.md": "Hollowbrook again\n",
        "docs/x/a.md": "one Hollowbrook\ntwo Hollowbrook\nthree Hollowbrook\nfour Hollowbrook\n",
    }
    (cand,) = scan(files, LEX)
    assert cand.where == "docs/x/a.md:1"
    assert cand.count == 5
    assert len(cand.contexts) == 3


def test_extra_texts_are_scanned() -> None:
    (cand,) = scan({}, LEX, extra_texts={"nav": "- Hollowbrook Overview: x.md\n"})
    assert cand.where == "<nav>:1"


def test_scan_is_deterministic() -> None:
    files = {"docs/x/a.md": "Hollowbrook and Brackenfeld and Zwartewater\n"}
    assert scan(files, LEX) == scan(files, LEX)
