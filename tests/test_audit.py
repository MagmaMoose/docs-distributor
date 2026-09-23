"""The gate's own tests. These are the ones that matter: every rule the audit enforces has a
test that plants a violation and asserts it is caught, and a test that a legitimate
look-alike is not.

Every "real" value below is synthetic. Values that exist only to trip a pattern class are
chosen from ranges nobody uses for anything private (a Dutch-sounding placeholder company,
random UUIDs, an IANA example address block that is NOT one of the documentation ranges).
"""

from __future__ import annotations

import ast
import hashlib
import sys
from pathlib import Path

import pytest

from docs_distributor import audit
from docs_distributor.audit import (
    AllowEntry,
    Allowlist,
    Literal,
    Novelty,
    NoveltyCandidate,
    NoveltyDecision,
    Placeholders,
    Rules,
    audit_files,
    audit_tree,
    person_variants,
)

SUB_ID = "7c1e4b9a-3f2d-4e8b-9a6c-5d2f1e0b8a47"
AGE_KEY = "age1" + "qy9ps8xz3wl5tdkfk7nu2ay6jrjnvcpx0hx9wltrv3s9dq8e5m2sgk4tlr"

LITERALS = (
    Literal("Hollowbrook", "rule 1 (org)"),
    Literal("hollowbrook.nl", "rule 2 (domain)"),
    Literal(SUB_ID, "rule 3 (subscription)"),
    *(Literal(v, "rule 4 (person)") for v in person_variants("Jan de Vries")),
    Literal("HB", "rule 5 (org abbreviation)"),
)

ALLOW = Allowlist(
    (
        AllowEntry("domain", "public code host", value="github.com"),
        AllowEntry("domain", "Kubernetes API groups and docs", value="kubernetes.io"),
        AllowEntry("private-host", "Kubernetes in-cluster DNS suffix", value="cluster.local"),
        AllowEntry("ipv4-public", "Cloudflare public resolver", value="1.1.1.1"),
        AllowEntry("account-12", "AWS-owned EKS image registry, af-south-1", value="877085696533"),
        AllowEntry("email", "GitHub SSH remote user", value="git@github.com"),
        AllowEntry(
            "truncated-id",
            "public GitHub Action commit pins",
            context=r"@[0-9a-f]{7,40}(?:…|\.\.\.)",
        ),
        AllowEntry(
            "uuid",
            "KICS query ids are public rule identifiers",
            context=r"kics-scan (?:disable|ignore)",
        ),
    )
)

PLACEHOLDERS = Placeholders.build(
    values=("111122223333", "example-org", "engineer-e", "client-a"),
    patterns={"uuid": (r"[0-9a-f]{8}-1111-2222-3333-[0-9a-f]{12}",)},
)

RULES = Rules(literals=LITERALS, allow=ALLOW, placeholders=PLACEHOLDERS)


def run(text: str, path: str = "page.md", **kw: object) -> list[audit.Finding]:
    result = audit_files({path: text.encode()}, RULES, **kw)  # type: ignore[arg-type]
    return result.findings


def rules_hit(text: str, **kw: object) -> set[str]:
    return {f.rule for f in run(text, **kw)}


# --- the gate is itself trustworthy ------------------------------------------------------


def test_audit_imports_only_the_standard_library() -> None:
    """A reviewer who does not trust this tool must be able to read the gate in isolation."""
    tree = ast.parse(Path(audit.__file__).read_text())
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module.split(".")[0])
    assert imported - {"__future__"} <= set(sys.stdlib_module_names), imported


def test_clean_text_passes_every_layer() -> None:
    result = audit_files(
        {"page.md": b"The example-org platform runs in eu-west-1 on 10.0.0.0/16.\n"},
        RULES,
        novelty=Novelty(candidates=(), decisions={}),
    )
    assert result.findings == []
    assert result.passed()


# --- layer 1: literal --------------------------------------------------------------------


def test_full_literal_is_caught_in_any_case() -> None:
    assert rules_hit("Owned by HOLLOWBROOK since 2019.") == {"literal"}
    assert rules_hit("mail ops at hollowbrook.nl") >= {"literal"}


def test_literal_split_across_a_line_break_is_caught() -> None:
    assert "literal" in rules_hit("Ask Jan de\nVries about the VPN.")


def test_literal_in_a_file_name_is_caught() -> None:
    result = audit_files({"hollowbrook/setup.md": b"clean\n"}, RULES)
    assert [f.rule for f in result.findings] == ["literal"]
    assert result.findings[0].path == "hollowbrook/setup.md"
    assert result.findings[0].line == 0  # the path itself, not a line of it


def test_short_literal_only_matches_as_a_whole_word() -> None:
    assert rules_hit("the HB team") == {"literal"}
    assert rules_hit("an HBase cluster and a thumb drive") == set()


@pytest.mark.parametrize(
    "text",
    [
        "subscription 7c1e4b9a-…",
        "subscription 7c1e4b9a…",
        "subscription 7c1e4b9a-...",
        "subscription 7c1e4b9a...",
        "/subscriptions/7c1e4b9a-3f2d-…/resourceGroups",
        "domain hollowb…",
    ],
)
def test_truncated_literal_is_caught(text: str) -> None:
    assert "literal-truncated" in rules_hit(text)


def test_truncation_shorter_than_six_characters_is_not_a_finding() -> None:
    assert rules_hit("id 7c1e4…") == set()


def test_personal_name_in_a_code_comment_is_caught() -> None:
    text = '```hcl\nresource "x" "y" {\n  # TODO(jan.devries): rotate this\n}\n```\n'
    findings = run(text)
    assert [f.rule for f in findings] == ["literal"]
    assert findings[0].line == 3


def test_person_variants_cover_the_forms_a_name_takes_in_code() -> None:
    variants = {v.casefold() for v in person_variants("Jan de Vries")}
    assert {"jan de vries", "jan.devries", "jdevries", "j.devries", "devries", "vries"} <= variants
    assert "jan" not in variants  # a first name alone is not evidence of anything


def test_surname_shorter_than_five_characters_is_not_audited_alone() -> None:
    assert "bos" not in {v.casefold() for v in person_variants("Piet Bos")}


# --- layer 2: pattern classes ------------------------------------------------------------


def test_new_real_domain_is_caught() -> None:
    assert "domain" in rules_hit("Status page at https://status.brackenfold.nl/incidents")


@pytest.mark.parametrize(
    "text",
    [
        "see https://github.com/example-org/platform-infra",
        "label app.kubernetes.io/name: web",
        "resolve api.example.com and ops.example.net",
        "edit main.tf and README.md then values.yaml",
        "set var.org and inputs.domain in the workflow",
        "uses System.IO and ASP.NET Core",
    ],
)
def test_public_or_code_shaped_domains_are_not_findings(text: str) -> None:
    assert "domain" not in rules_hit(text)


def test_allowlisted_domain_does_not_cover_a_lookalike() -> None:
    assert "domain" in rules_hit("clone from notgithub.com instead")


def test_twelve_digit_account_is_caught() -> None:
    assert rules_hit("assume role in 482913576021") == {"account-12"}
    assert rules_hit("console shows 4829-1357-6021") == {"account-12"}


def test_placeholder_and_allowlisted_accounts_pass() -> None:
    assert rules_hit("dev is 111122223333; ECR 877085696533.dkr.ecr.af-south-1") == set()


def test_longer_digit_runs_and_hex_are_not_accounts() -> None:
    assert rules_hit("build 4829135760219 at sha 3d3c42e5aac5ba805825da76410c181273ba90b1") == set()


def test_public_ipv4_outside_the_documentation_ranges_is_caught() -> None:
    assert rules_hit("the edge gateway is 93.184.216.34") == {"ipv4-public"}
    assert rules_hit("split tunnel 172.168.16.0/20") == {"ipv4-public"}


@pytest.mark.parametrize(
    "text",
    [
        "gateway 203.0.113.10 and 198.51.100.0/24 and 192.0.2.1",
        "private 10.150.100.0/22, 172.16.0.1, 192.168.19.69",
        "loopback 127.0.0.1, link-local 169.254.169.254, CGNAT 100.64.0.1",
        "resolver 1.1.1.1",
        "chart v1.2.3.4 and 0.0.0.0/0",
    ],
)
def test_non_public_or_allowlisted_ipv4_passes(text: str) -> None:
    assert "ipv4-public" not in rules_hit(text)


def test_public_ipv6_is_caught_and_documentation_ipv6_passes() -> None:
    assert "ipv6-public" in rules_hit("peer 2a01:4f8:c0c:1234::1")
    assert "ipv6-public" not in rules_hit("peer 2001:db8::1 and fe80::1 at 12:34:56")


def test_age_recipient_is_caught_and_placeholder_is_not() -> None:
    assert rules_hit(f"recipient: {AGE_KEY}") == {"age-recipient"}
    assert rules_hit("recipient: age1example…") == set()


def test_aws_access_key_is_caught() -> None:
    assert "aws-access-key-id" in rules_hit("AKIA" + "Q3VZ7XKM2PLR8WTN")


def test_slack_token_is_caught_and_placeholders_are_not() -> None:
    assert "slack-token" in rules_hit("xoxb-" + "7719203348-5510293847-QmZr8tXvLp")
    assert rules_hit("token xoxb-your-token or xoxb-... or xoxb-<token>") == set()


def test_private_key_block_is_caught() -> None:
    assert "private-key" in rules_hit("-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blbn\n")


def test_email_rules() -> None:
    assert rules_hit("mail j.smit@brackenfold.nl") >= {"email"}
    assert rules_hit("mail platform-lead@example.com or git@github.com") == set()


def test_uuid_rules() -> None:
    assert rules_hit("tenant 2f9d6c1a-8b7e-4c3d-a5f4-1e2d3c4b5a69") == {"uuid"}
    assert rules_hit("tenant aaaaaaaa-1111-2222-3333-aaaaaaaaaaaa") == set()
    assert rules_hit("# kics-scan disable=2f9d6c1a-8b7e-4c3d-a5f4-1e2d3c4b5a69") == set()


def test_truncated_opaque_id_is_caught_unless_allowlisted() -> None:
    assert rules_hit("cache policy 5b3e9f1c…") == {"truncated-id"}
    assert rules_hit("uses: actions/checkout@9c091bb… # v7") == set()
    assert rules_hit("zeros 00000000-… and letters aaaaaaa…") == set()


def test_hex32_identifier_is_caught() -> None:
    assert rules_hit("zone 4f1a9c2e7b3d8f6a0c5e1b9d2f7a3c8e") == {"hex-32"}


def test_gps_pair_is_caught() -> None:
    assert rules_hit("site at 52.37403, 4.88969") == {"gps"}
    assert rules_hit("ratios 0.5, 1.25 and version 3.12") == set()


def test_private_host_suffix_is_caught_and_cluster_dns_passes() -> None:
    assert rules_hit("ssh bastion01.ops.corp") == {"private-host"}
    assert rules_hit("http://litellm.automation.svc.cluster.local:4000") == set()


def test_credential_assignment_is_caught_and_references_are_not() -> None:
    assert "credential" in rules_hit('password: "Wx7qT9zr2Lm4"')
    clean = (
        "password: <redacted>\n"
        "token: ${{ secrets.GITHUB_TOKEN }}\n"
        "api_key: os.environ/ANTHROPIC_API_KEY\n"
        "secretKey: dbPassword\n"
        "password: CHANGEME_PLEASE\n"
    )
    assert rules_hit(clean) == set()


def test_allow_entry_can_be_scoped_to_paths() -> None:
    rules = Rules(
        literals=(),
        allow=Allowlist(
            (AllowEntry("ipv4-public", "scoped", value="93.184.216.34", paths=("public/*",)),)
        ),
        placeholders=PLACEHOLDERS,
    )
    files = {"public/a.md": b"93.184.216.34\n", "other/b.md": b"93.184.216.34\n"}
    assert [f.path for f in audit_files(files, rules).findings] == ["other/b.md"]


# --- binaries and encodings --------------------------------------------------------------


def test_uncleared_binary_is_a_finding() -> None:
    result = audit_files({"img/diagram.png": b"\x89PNG\r\n\x1a\n\x00\x00"}, RULES)
    assert [f.rule for f in result.findings] == ["binary-not-cleared"]


def test_binary_cleared_by_hash_passes() -> None:
    blob = b"\x89PNG\r\n\x1a\n\x00\x00"
    cleared = frozenset({hashlib.sha256(blob).hexdigest()})
    assert audit_files({"img/diagram.png": blob}, RULES, cleared_binaries=cleared).findings == []


def test_invalid_utf8_counts_as_binary() -> None:
    result = audit_files({"notes.md": b"caf\xe9 at Hollowbrook"}, RULES)
    assert "binary-not-cleared" in {f.rule for f in result.findings}


# --- layer 3: novelty --------------------------------------------------------------------


def test_unclassified_candidate_fails_closed() -> None:
    result = audit_files(
        {"page.md": b"clean\n"},
        RULES,
        novelty=Novelty(candidates=(NoveltyCandidate("Brackenfold", "page.md:1"),), decisions={}),
    )
    assert [f.rule for f in result.findings] == ["novelty-unclassified"]
    assert not result.passed()


def test_sensitive_unmapped_candidate_fails() -> None:
    result = audit_files(
        {"page.md": b"clean\n"},
        RULES,
        novelty=Novelty(
            candidates=(NoveltyCandidate("Brackenfold", "page.md:1"),),
            decisions={"brackenfold": NoveltyDecision(sensitive=True, origin="llm")},
        ),
    )
    assert [f.rule for f in result.findings] == ["novelty-sensitive"]


def test_candidate_classified_public_passes() -> None:
    result = audit_files(
        {"page.md": b"clean\n"},
        RULES,
        novelty=Novelty(
            candidates=(NoveltyCandidate("Traefik", "page.md:1"),),
            decisions={"traefik": NoveltyDecision(sensitive=False, origin="llm")},
        ),
    )
    assert result.passed()


def test_novelty_layer_is_required_unless_explicitly_waived() -> None:
    result = audit_files({"page.md": b"clean\n"}, RULES)
    assert result.layers["novelty"].startswith("skipped")
    assert not result.passed()
    assert result.passed(required=("literal", "patterns"))


# --- outbound text and reporting ---------------------------------------------------------


def test_outbound_text_is_audited_too() -> None:
    result = audit_files(
        {"page.md": b"clean\n"},
        RULES,
        extra_texts={"pull request body": "Synced from hollowbrook.nl"},
    )
    assert [(f.path, f.rule) for f in result.findings] == [("<pull request body>", "literal")]


def test_public_rendering_never_carries_the_matched_text() -> None:
    finding = run("Owned by Hollowbrook.")[0]
    assert "Hollowbrook" in finding.match
    assert "ollowbrook" not in finding.public()
    assert "ollowbrook" not in finding.masked()


def test_audit_tree_reads_a_directory_and_skips_git_internals(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("url = https://hollowbrook.nl\n")
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "a.md").write_text("see 93.184.216.34\n")
    result = audit_tree(tmp_path, RULES)
    assert [(f.path, f.rule) for f in result.findings] == [("docs/a.md", "ipv4-public")]
    assert result.files == 1
