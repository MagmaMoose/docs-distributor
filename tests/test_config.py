"""Mapping, allow and vocabulary validation. Each refusal here is a mapping that would either
never pass the gate, or would pass it by accident."""

from __future__ import annotations

from pathlib import Path

import pytest

from docs_distributor import audit, config

VOCAB = config.load_vocabulary()


def mapping(*rules: dict[str, object], **extra: object) -> config.PrivateMapping:
    return config.parse_mapping([("m.yml", {"version": 1, "rules": list(rules), **extra})], VOCAB)


def problems(*rules: dict[str, object]) -> list[str]:
    with pytest.raises(config.ConfigError) as exc:
        mapping(*rules)
    return exc.value.problems


def test_committed_rules_load() -> None:
    allow = config.load_allow()
    assert allow.allowlist.entries
    assert "uuid" in {e.cls for e in allow.allowlist.entries}
    assert "customer" in VOCAB.classes


def test_a_valid_mapping_loads_and_yields_literals() -> None:
    m = mapping(
        {"from": "Hollowbrook", "to": "example-org", "class": "org"},
        {"from": "Jan de Vries", "to": "engineer-e", "class": "person"},
    )
    values = {lit.value.casefold() for lit in m.literals()}
    assert {"hollowbrook", "jan de vries", "jan.devries", "vries"} <= values
    derived = [lit for lit in m.literals() if lit.value.casefold() == "jan.devries"]
    assert derived[0].whole_word


def test_placeholder_that_is_a_real_domain_is_refused() -> None:
    errs = problems({"from": "hollowbrook.nl", "to": "client-a.nl", "class": "domain"})
    assert any("would fail the audit (domain)" in e for e in errs)


def test_placeholder_on_a_reserved_domain_is_accepted() -> None:
    mapping({"from": "hollowbrook.nl", "to": "client-a.example.com", "class": "domain"})


def test_placeholder_containing_the_real_value_is_refused() -> None:
    errs = problems({"from": "Acme", "to": "Acme Placeholder Ltd", "class": "org"})
    assert any("contains the real value" in e for e in errs)


def test_public_address_placeholder_is_refused_and_documentation_range_accepted() -> None:
    assert problems({"from": "93.184.216.34", "to": "93.184.216.1", "class": "ip"})
    mapping({"from": "93.184.216.34", "to": "203.0.113.10", "class": "ip"})


def test_duplicate_real_values_are_refused() -> None:
    errs = problems(
        {"from": "Hollowbrook", "to": "example-org", "class": "org"},
        {"from": "hollowbrook", "to": "the owner", "class": "org"},
    )
    assert any("duplicates" in e for e in errs)


def test_regex_placeholder_may_not_copy_groups() -> None:
    errs = problems({"from": r"hb-(\w+)-prd", "to": r"app-\1-prd", "class": "other", "regex": True})
    assert any("reference groups" in e for e in errs)


def test_problems_never_quote_the_real_value() -> None:
    errs = problems({"from": "Hollowbrook", "to": "Hollowbrook Two", "class": "org"})
    assert not any("Hollowbrook" in e for e in errs)


def test_newline_in_placeholder_is_refused() -> None:
    assert problems({"from": "Hollowbrook", "to": "a\nb", "class": "org"})


def test_mapping_directory_merges_in_lexical_order(tmp_path: Path) -> None:
    (tmp_path / "20-people.yml").write_text(
        "rules:\n  - {from: Jan de Vries, to: engineer-e, class: person}\n"
    )
    (tmp_path / "10-org.yml").write_text(
        "rules:\n  - {from: Hollowbrook, to: example-org, class: org}\n"
        "sources:\n  cloud:\n    url: https://git.example.com/x.git\n    drop: ['scratch/**']\n"
    )
    m = config.load_mapping(tmp_path, VOCAB)
    assert [r.index for r in m.rules] == [1, 2]
    assert m.rules[0].source == "Hollowbrook"
    assert m.sources["cloud"].drop == ("scratch/**",)


def test_binary_clearance_needs_a_real_digest_and_a_reason() -> None:
    with pytest.raises(config.ConfigError):
        mapping(sources={"s": {"binaries": [{"path": "a.png", "sha256": "abc", "why": "x"}]}})
    ok = mapping(sources={"s": {"binaries": [{"path": "a.png", "sha256": "a" * 64, "why": "reviewed"}]}})
    assert ok.cleared_binaries() == {"a" * 64}


def test_allow_entry_without_justification_is_refused() -> None:
    with pytest.raises(config.ConfigError):
        config.parse_allow({"entries": [{"class": "domain", "value": "x.com"}]}, "t")


def test_allow_entry_for_unknown_class_is_refused() -> None:
    with pytest.raises(config.ConfigError):
        config.parse_allow({"entries": [{"class": "nope", "value": "x", "why": "y"}]}, "t")


def test_build_rules_merges_private_allow_entries() -> None:
    m = mapping(allow=[{"class": "domain", "value": "brackenfold.nl", "why": "public service"}])
    rules = config.build_rules(m, config.load_allow(), VOCAB)
    result = audit.audit_files({"a.md": b"see brackenfold.nl\n"}, rules)
    assert result.findings == []


def test_runtime_config_parses_and_rejects_bad_sources() -> None:
    cfg = config.parse_config(
        {
            "target": {"repo": "owner/docs", "navAfter": "Platform"},
            "sources": [{"name": "cloud-platform", "target": "docs/cloud-platform", "title": "Cloud"}],
        }
    )
    assert cfg.sources[0].url is None
    assert cfg.target.auth.kind == "github-app"
    with pytest.raises(config.ConfigError):
        config.parse_config({"target": {"repo": "x"}, "sources": [{"name": "Bad Name", "target": "/etc"}]})


def test_overlapping_targets_are_refused() -> None:
    with pytest.raises(config.ConfigError):
        config.parse_config(
            {
                "target": {"repo": "o/d"},
                "sources": [
                    {"name": "a", "target": "docs/a"},
                    {"name": "b", "target": "docs/a/b"},
                ],
            }
        )


def test_mkdocs_python_tags_load_without_executing(tmp_path: Path) -> None:
    f = tmp_path / "mkdocs.yml"
    f.write_text("x: !!python/name:os.system\nnav:\n  - Home: index.md\n")
    data = config.load_yaml(f)
    assert data["x"] == "os.system"
    assert data["nav"] == [{"Home": "index.md"}]
