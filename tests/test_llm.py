"""The LLM layer: caching, Python's checks on every answer, and the headless CLI plumbing.
No test here reaches a model."""

from __future__ import annotations

import json
import stat
from pathlib import Path
from typing import Any

import pytest

from docs_distributor import config
from docs_distributor.config import LLMConfig
from docs_distributor.llm import (
    LLM,
    Cache,
    ClaudeCodeBackend,
    LLMError,
    ReplayBackend,
    Template,
    load_template,
    next_in_series,
    repair_acceptable,
)
from docs_distributor.novelty import Candidate

VOCAB = config.load_vocabulary()


class Fake:
    """A backend that answers from a function and counts calls."""

    model = "fake-model"

    def __init__(self, answer: Any) -> None:
        self.answer = answer
        self.calls: list[tuple[str, str]] = []

    def complete(self, template: Template, user: str) -> Any:
        self.calls.append((template.name, user))
        return self.answer(template, user) if callable(self.answer) else self.answer


def cand(term: str) -> Candidate:
    return Candidate(term, "docs/x/a.md:1", 1, (f"runs on {term} today",), ("unknown-word",))


def classify_all(template: Template, user: str) -> dict[str, Any]:
    terms = [t["term"] for t in json.loads(user.split("\n\n", 1)[1])]
    return {
        "results": [
            {"term": t, "sensitive": t.startswith("Hollow"), "category": "customer", "reason": "r"}
            for t in terms
        ]
    }


def test_templates_load_and_carry_a_version() -> None:
    for name in ("classify", "propose", "repair", "place"):
        t = load_template(name)
        assert t.tag == f"{name}@1"
        assert t.schema["type"] == "object"
        assert "$" in t.user.template


def test_cache_key_moves_with_content_template_and_model() -> None:
    base = Cache.key("x", "classify@1", "m")
    assert base == Cache.key("x", "classify@1", "m")
    assert (
        len(
            {
                base,
                Cache.key("y", "classify@1", "m"),
                Cache.key("x", "classify@2", "m"),
                Cache.key("x", "classify@1", "n"),
            }
        )
        == 4
    )


def test_classify_caches_per_term_and_asks_only_for_new_terms(tmp_path: Path) -> None:
    fake = Fake(classify_all)
    llm = LLM(fake, Cache(tmp_path))
    first = llm.classify([cand("Hollowbrook"), cand("Traefik")])
    assert first["hollowbrook"].sensitive and not first["traefik"].sensitive
    assert len(fake.calls) == 1
    again = LLM(fake, Cache(tmp_path)).classify(
        [cand("Hollowbrook"), cand("Traefik"), cand("Brackenfold")]
    )
    assert len(fake.calls) == 2
    assert "Brackenfold" in fake.calls[1][1] and "Traefik" not in fake.calls[1][1]
    assert again["hollowbrook"].origin.startswith("cache:")


def test_classify_ignores_answers_for_terms_it_did_not_ask_about(tmp_path: Path) -> None:
    fake = Fake(
        {"results": [{"term": "Other", "sensitive": False, "category": "other", "reason": "r"}]}
    )
    llm = LLM(fake, Cache(tmp_path))
    assert llm.classify([cand("Hollowbrook")]) == {}
    assert llm.stats.rejected == 1


def test_classify_failure_leaves_terms_undecided_so_the_gate_fails_closed(tmp_path: Path) -> None:
    class Broken(Fake):
        def complete(self, template: Template, user: str) -> Any:
            raise LLMError("gateway down")

    llm = LLM(Broken(None), Cache(tmp_path), sleep=lambda s: None)
    assert llm.classify([cand("Hollowbrook")]) == {}
    assert llm.stats.failed == 3  # first try plus two retries


def test_replay_backend_answers_only_from_cache(tmp_path: Path) -> None:
    LLM(Fake(classify_all), Cache(tmp_path)).classify([cand("Hollowbrook")])
    replay = LLM(ReplayBackend("fake-model"), Cache(tmp_path))
    assert set(replay.classify([cand("Hollowbrook"), cand("Unseen")])) == {"hollowbrook"}


def test_series_values_are_assigned_by_python_not_the_model(tmp_path: Path) -> None:
    fake = Fake({"proposals": []})
    llm = LLM(fake, Cache(tmp_path))
    out = llm.propose(
        [("Hollowbrook", "customer"), ("Brackenfold", "vendor")], VOCAB, taken=["client-j"]
    )
    assert [(p.term, p.to, p.origin) for p in out] == [
        ("Brackenfold", "vendor-C", "series"),
        ("Hollowbrook", "client-k", "series"),
    ]
    assert fake.calls == []


def test_next_in_series_rolls_over_to_two_letters() -> None:
    taken = [f"client-{c}" for c in "abcdefghijklmnopqrstuvwxyz"]
    assert next_in_series("client-{letter}", taken) == "client-aa"


def test_model_proposals_must_pass_the_gate_and_not_echo_the_term(tmp_path: Path) -> None:
    answers = {
        "proposals": [
            {"term": "hbticketsync", "class": "product", "to": "ticket-bridge", "reason": "r"},
            {"term": "hbvault", "class": "host", "to": "vault.hbvault.nl", "reason": "echo"},
            {"term": "zwartmeer", "class": "domain", "to": "zwart.nl", "reason": "real tld"},
        ]
    }
    llm = LLM(Fake(answers), Cache(tmp_path))
    out = {
        p.term: p
        for p in llm.propose(
            [
                ("hbticketsync", "resource-name"),
                ("hbvault", "resource-name"),
                ("zwartmeer", "resource-name"),
            ],
            VOCAB,
            taken=[],
        )
    }
    assert out["hbticketsync"].to == "ticket-bridge"
    assert out["hbvault"].origin == "unresolved"
    assert out["zwartmeer"].origin == "unresolved"


def test_repair_is_accepted_only_when_it_changes_nothing_but_grammar() -> None:
    before = "Deploy to the the platform before\nthe release window.\n"
    assert repair_acceptable(
        before, "Deploy to the platform before\nthe release window.\n", ["platform"]
    )
    # a new name
    assert not repair_acceptable(
        before, "Deploy to the Hollowbrook platform before\nthe release window.\n", []
    )
    # a lost line
    assert not repair_acceptable(before, "Deploy to the platform before the release window.\n", [])
    # a lost placeholder
    assert not repair_acceptable("Ask engineer-e (engineer-e).\n", "Ask them.\n", ["engineer-e"])


def test_repair_answers_are_cached(tmp_path: Path) -> None:
    fake = Fake({"text": "Deploy to the platform.\n"})
    llm = LLM(fake, Cache(tmp_path))
    assert (
        llm.repair("Deploy to the the platform.\n", ["doubled word"], [])
        == "Deploy to the platform.\n"
    )
    assert (
        llm.repair("Deploy to the the platform.\n", ["doubled word"], [])
        == "Deploy to the platform.\n"
    )
    assert len(fake.calls) == 1


def test_rejected_repair_is_not_cached_and_returns_none(tmp_path: Path) -> None:
    fake = Fake({"text": "Something else entirely.\n"})
    llm = LLM(fake, Cache(tmp_path))
    assert llm.repair("Deploy to the the platform.\n", ["doubled word"], []) is None
    assert llm.repair("Deploy to the the platform.\n", ["doubled word"], []) is None
    assert len(fake.calls) == 2


def test_placement_must_name_an_existing_section(tmp_path: Path) -> None:
    answer = {
        "placements": [
            {"path": "a.md", "section": ["Operations"], "title": "Break-glass"},
            {"path": "b.md", "section": ["Nowhere"], "title": "Lost"},
        ]
    }
    out = LLM(Fake(answer), Cache(tmp_path)).place(
        [("a.md", "Break-glass access"), ("b.md", "B")], [("Operations",)]
    )
    assert set(out) == {"a.md"}
    assert out["a.md"].section == ("Operations",)


# --- the headless CLI --------------------------------------------------------------------


def fake_claude(tmp_path: Path, envelope: dict[str, Any]) -> Path:
    script = tmp_path / "claude"
    script.write_text(
        "#!/bin/sh\n"
        f'printf "%s\\n" "$@" > "{tmp_path}/argv"\n'
        f'env > "{tmp_path}/env"\n'
        f'cat > "{tmp_path}/stdin"\n'
        f"cat <<'EOF'\n{json.dumps(envelope)}\nEOF\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return script


def test_claude_code_backend_routes_through_the_gateway_and_stays_hermetic(tmp_path: Path) -> None:
    script = fake_claude(
        tmp_path, {"type": "result", "is_error": False, "structured_output": {"text": "ok"}}
    )
    cfg = LLMConfig(
        model="claude-sonnet-4-6-max", base_url="http://litellm.test:4000", claude_bin=str(script)
    )
    env = {
        "PATH": "/usr/bin:/bin",
        "CLAUDE_OAUTH_TOKEN": "sk-ant-oat01-test",
        "LITELLM_API_KEY": "sk-gw",
        "HOME": "/root",
    }
    backend = ClaudeCodeBackend(cfg, tmp_path / "work", environ=env)
    assert backend.complete(load_template("repair"), "fix this") == {"text": "ok"}
    argv = (tmp_path / "argv").read_text().splitlines()
    assert argv[argv.index("--tools") + 1] == ""
    assert argv[argv.index("--model") + 1] == "claude-sonnet-4-6-max"
    assert "--json-schema" in argv and "--no-session-persistence" in argv
    seen = dict(
        line.split("=", 1) for line in (tmp_path / "env").read_text().splitlines() if "=" in line
    )
    assert seen["ANTHROPIC_BASE_URL"] == "http://litellm.test:4000"
    assert seen["ANTHROPIC_AUTH_TOKEN"] == "sk-ant-oat01-test"
    assert seen["ANTHROPIC_CUSTOM_HEADERS"] == "x-litellm-api-key: Bearer sk-gw"
    assert seen["HOME"].startswith(str(tmp_path))  # not the caller's home
    assert "CLAUDE_OAUTH_TOKEN" not in seen and "LITELLM_API_KEY" not in seen
    assert (tmp_path / "stdin").read_text() == "fix this"


def test_claude_code_error_envelope_is_an_error_even_when_subtype_says_success(
    tmp_path: Path,
) -> None:
    script = fake_claude(
        tmp_path,
        {
            "type": "result",
            "subtype": "success",
            "is_error": True,
            "result": "Failed to authenticate",
        },
    )
    backend = ClaudeCodeBackend(
        LLMConfig(claude_bin=str(script)), tmp_path / "w", environ={"PATH": "/bin"}
    )
    with pytest.raises(LLMError, match="Failed to authenticate"):
        backend.complete(load_template("repair"), "x")
