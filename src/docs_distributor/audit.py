"""The leak gate. Nothing publishes unless this passes.

Read this module as a security control, written for a reviewer who does not trust the rest
of the tool:

* **Standard library only.** No network, no LLM, no third-party parser.
  ``tests/test_audit.py`` fails if an import outside the standard library ever appears.
* **Table-driven.** Every layer-2 rule is one row of :data:`PATTERN_CLASSES`, with the reason
  it exists beside it. Adding or dropping a rule is a one-line diff.
* **Fail-closed.** Text that is not valid UTF-8 is treated as binary, and a binary is a
  finding unless a human cleared its SHA-256. A layer that did not run is reported as
  skipped, and :meth:`AuditResult.passed` is false unless every required layer ran clean.

The three layers, all of which must pass before anything is pushed:

1. **literal**: no real value from the mapping appears in the output, in any letter case,
   with any whitespace between its words, or truncated. A truncation is a prefix of six or
   more characters followed by ``…``, ``-…`` or ``...``. A careful manual port once leaked
   four values that were on its own literal list, because they had been shortened.
2. **pattern classes**: shapes that identify an organisation whatever it is called, such as
   account numbers, public addresses, UUIDs, domains, emails, keys, coordinates and private
   host suffixes. Placeholders and a justified allowlist are exempt.
3. **novelty**: every name-like token found in the *source* was mapped, allowed, known
   vocabulary, or classified. A term classified as sensitive that has no mapping fails.

A :class:`Finding` keeps the offending text in ``match``. That text can be a real value, so it
belongs in the private run report only. :meth:`Finding.public` is the only rendering that
logs, issues, pull requests or chat messages may carry.
"""

from __future__ import annotations

import bisect
import hashlib
import ipaddress
import re
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path

LAYERS = ("literal", "patterns", "novelty")

#: The shortest prefix of a real value that still counts as that value when followed by an
#: ellipsis. Shorter prefixes collide with ordinary words and hex fragments too often.
MIN_TRUNCATION = 6

_ELLIPSIS = r"(?:…|\.\.\.)"

# RFC 5737 (IPv4) and RFC 3849 (IPv6) documentation ranges: the only public-looking
# addresses a placeholder may use.
DOCUMENTATION_NETWORKS = tuple(
    ipaddress.ip_network(n)
    for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)

# RFC 2606 and RFC 6761: names that can never belong to anyone.
RESERVED_DOMAINS = ("example.com", "example.net", "example.org", "example.io")
RESERVED_TLDS = ("example", "test", "invalid", "localhost")


# --- inputs ------------------------------------------------------------------------------


@dataclass(frozen=True)
class Literal:
    """One real value that must not appear in the output.

    ``origin`` is a safe label for the rule that produced it ("mapping rule 12 (person)").
    ``boundary`` restricts the match to whole words. It is set for short values and for
    derived name variants, where a substring match would fire on ordinary words.
    """

    value: str
    origin: str
    boundary: bool | None = None

    @property
    def whole_word(self) -> bool:
        return self.boundary if self.boundary is not None else len(self.value) < 5


@dataclass(frozen=True)
class AllowEntry:
    """A verified-public value that one layer-2 class must let through.

    Exactly one of ``value`` (the literal, compared case-insensitively; for domains it also
    covers subdomains unless ``subdomains`` is false; for addresses it may be a CIDR),
    ``pattern`` (a regex the whole match must satisfy) or ``context`` (a regex searched in
    the line around the match) says what is allowed. ``paths`` optionally limits where.
    ``why`` is mandatory: it is what a reviewer checks.
    """

    cls: str
    why: str
    value: str | None = None
    pattern: str | None = None
    context: str | None = None
    paths: tuple[str, ...] = ()
    subdomains: bool = True

    def __post_init__(self) -> None:
        given = [x for x in (self.value, self.pattern, self.context) if x is not None]
        if len(given) != 1:
            raise ValueError(
                f"allow entry for {self.cls!r} needs exactly one of value/pattern/context"
            )
        if not self.why.strip():
            raise ValueError(f"allow entry for {self.cls!r} has no justification")


@dataclass(frozen=True)
class Allowlist:
    entries: tuple[AllowEntry, ...] = ()

    def permits(self, cls: str, value: str, line: str, path: str) -> bool:
        for entry in self.entries:
            if entry.cls != cls:
                continue
            if entry.paths and not any(fnmatchcase(path, glob) for glob in entry.paths):
                continue
            if entry.context is not None:
                if re.search(entry.context, line):
                    return True
            elif entry.pattern is not None:
                if re.fullmatch(entry.pattern, value, re.IGNORECASE):
                    return True
            elif entry.value is not None and _value_allowed(cls, entry, value):
                return True
        return False


def _value_allowed(cls: str, entry: AllowEntry, value: str) -> bool:
    allowed = entry.value or ""
    if cls in ("domain", "private-host"):
        host, want = value.lower().rstrip("."), allowed.lower()
        return host == want or (entry.subdomains and host.endswith("." + want))
    if cls in ("ipv4-public", "ipv6-public"):
        try:
            return ipaddress.ip_network(value, strict=False).subnet_of(
                ipaddress.ip_network(allowed, strict=False)  # type: ignore[arg-type]
            )
        except (ValueError, TypeError):
            return False
    if cls == "email" and allowed.startswith("@"):
        return value.lower().endswith(allowed.lower())
    return value.lower() == allowed.lower()


@dataclass(frozen=True)
class Placeholders:
    """The target side of the mapping: values that are fictional by construction.

    ``values`` are exact placeholder strings (compared case-insensitively). ``patterns`` are
    per-class regexes for placeholder shapes such as ``xxxxxxxx-1111-2222-3333-xxxxxxxxxxxx``.
    ``domains`` are placeholder domains that also cover their subdomains. The reserved
    domains and documentation ranges above are always included.
    """

    values: frozenset[str] = frozenset()
    patterns: Mapping[str, tuple[re.Pattern[str], ...]] = field(default_factory=dict)
    domains: tuple[str, ...] = RESERVED_DOMAINS

    @classmethod
    def build(
        cls,
        values: Iterable[str] = (),
        patterns: Mapping[str, Iterable[str]] | None = None,
        domains: Iterable[str] = (),
    ) -> Placeholders:
        return cls(
            values=frozenset(v.lower() for v in values),
            patterns={
                name: tuple(re.compile(p, re.IGNORECASE) for p in pats)
                for name, pats in (patterns or {}).items()
            },
            domains=tuple(dict.fromkeys((*RESERVED_DOMAINS, *(d.lower() for d in domains)))),
        )

    def permits(self, cls: str, value: str) -> bool:
        low = value.lower()
        if low in self.values:
            return True
        if any(p.fullmatch(value) for p in self.patterns.get(cls, ())):
            return True
        if cls in ("domain", "private-host", "email"):
            host = low.rsplit("@", 1)[-1].rstrip(".")
            if host.rsplit(".", 1)[-1] in RESERVED_TLDS:
                return True
            return any(host == d or host.endswith("." + d) for d in self.domains)
        return False


@dataclass(frozen=True)
class Rules:
    literals: tuple[Literal, ...] | Sequence[Literal] = ()
    allow: Allowlist = field(default_factory=Allowlist)
    placeholders: Placeholders = field(default_factory=Placeholders)


@dataclass(frozen=True)
class NoveltyCandidate:
    """A name-like source token that no mapping, allow entry or vocabulary covers.

    ``where`` is an OUTPUT location ("path:line"), which is safe to publish; the source
    location is not.
    """

    term: str
    where: str


@dataclass(frozen=True)
class NoveltyDecision:
    sensitive: bool
    origin: str


@dataclass(frozen=True)
class Novelty:
    candidates: tuple[NoveltyCandidate, ...]
    #: keyed by ``term.casefold()``
    decisions: Mapping[str, NoveltyDecision]


# --- outputs -----------------------------------------------------------------------------


@dataclass(frozen=True)
class Finding:
    layer: int
    rule: str
    path: str
    line: int  # 1-based; 0 means the path itself
    column: int
    match: str  # PRIVATE: may be a real value. Report file only.
    detail: str  # safe to publish

    def public(self) -> str:
        where = self.path if self.line == 0 else f"{self.path}:{self.line}:{self.column}"
        return f"{where}: layer {self.layer} {self.rule}: {self.detail}"

    def masked(self) -> str:
        """The match with all but the first character of each word hidden."""
        return re.sub(r"(?<=\w)\w", "*", self.match)


@dataclass
class AuditResult:
    findings: list[Finding]
    layers: dict[str, str]  # layer -> "passed" | "failed" | "skipped: <why>"
    files: int

    def passed(self, required: Iterable[str] = LAYERS) -> bool:
        return not self.findings and all(self.layers.get(name) == "passed" for name in required)


# --- layer 1: literal --------------------------------------------------------------------


class _LiteralMatcher:
    def __init__(self, literals: Iterable[Literal]) -> None:
        by_key: dict[str, Literal] = {}
        for lit in literals:
            if lit.value.strip():
                by_key.setdefault(_fold(lit.value), lit)
        self._by_key = by_key
        # Longest first, so a value is reported as itself rather than as a shorter value it
        # happens to contain. Words may be separated by any whitespace, including a line
        # break inside a Markdown paragraph.
        ordered = sorted(by_key.values(), key=lambda lit: (-len(lit.value), _fold(lit.value)))
        loose = [_spaced(lit.value) for lit in ordered if not lit.whole_word]
        whole = [_spaced(lit.value) for lit in ordered if lit.whole_word]
        self._loose = re.compile("|".join(loose), re.IGNORECASE) if loose else None
        self._whole = (
            re.compile(
                r"(?<![A-Za-z0-9])(?:" + "|".join(whole) + r")(?![A-Za-z0-9])", re.IGNORECASE
            )
            if whole
            else None
        )
        self._prefixable = sorted(k for k in by_key if len(k) > MIN_TRUNCATION)

    def find(self, text: str) -> Iterator[tuple[int, int, Literal | None]]:
        spans: list[tuple[int, int]] = []
        for rx in (self._loose, self._whole):
            if rx is None:
                continue
            for m in rx.finditer(text):
                if any(s < m.end() and m.start() < e for s, e in spans):
                    continue
                spans.append((m.start(), m.end()))
                yield m.start(), m.end(), self._by_key.get(_fold(m.group(0)))

    def find_truncated(self, text: str) -> Iterator[tuple[int, int, Literal]]:
        if not self._prefixable:
            return
        for m in _TRUNCATION.finditer(text):
            token, token_start = m.group("tok"), m.start("tok")
            # Try every suffix of the token that starts at a boundary, so that
            # "/subscriptions/1a2b3c4d-…" is tested as "1a2b3c4d" as well.
            starts = [0] + [i + 1 for i, ch in enumerate(token) if not ch.isalnum()]
            for start in starts:
                candidate = token[start:].rstrip("-._:/")
                key = _fold(candidate)
                if len(key) < MIN_TRUNCATION:
                    continue
                i = bisect.bisect_left(self._prefixable, key)
                if i < len(self._prefixable) and self._prefixable[i].startswith(key):
                    yield token_start + start, m.end(), self._by_key[self._prefixable[i]]
                    break


_TRUNCATION = re.compile(r"(?P<tok>[A-Za-z0-9][A-Za-z0-9._:/@+-]*?)-?" + _ELLIPSIS)


def _fold(value: str) -> str:
    return " ".join(value.split()).casefold()


def _spaced(value: str) -> str:
    return r"\s+".join(re.escape(word) for word in value.split())


def person_variants(name: str) -> list[str]:
    """Every form a person's name takes in docs and code, for the literal layer.

    ``"Jan de Vries"`` yields the full name, ``de vries``, joined forms such as
    ``jan.devries``, ``jan.de.vries``, ``jdevries`` and ``j.devries``, and the surname alone
    when it has five letters or more. A first name alone is never included: it is not
    evidence of anything and it collides with ordinary text.
    """
    words = name.split()
    if len(words) < 2:
        return [name]
    first, rest = words[0], words[1:]
    last_joined = "".join(rest)
    last_dotted = ".".join(rest)
    initial = first[0]
    forms = [
        name,
        " ".join(rest),
        f"{first}.{last_joined}",
        f"{first}.{last_dotted}",
        f"{first}_{last_joined}",
        f"{first}-{last_joined}",
        f"{first}{last_joined}",
        f"{initial}{last_joined}",
        f"{initial}.{last_joined}",
        last_joined,
    ]
    if len(rest[-1]) >= 5:
        forms.append(rest[-1])
    return list(dict.fromkeys(f for f in forms if len(f) >= 4))


# --- layer 2: pattern classes ------------------------------------------------------------

_Finder = Callable[[str], Iterator[tuple[int, int, str]]]


@dataclass(frozen=True)
class PatternClass:
    name: str
    why: str
    find: _Finder


def _regex(
    pattern: str, *, group: int | str = 0, flags: int = 0, keep: Callable[[str], bool] | None = None
) -> _Finder:
    rx = re.compile(pattern, flags)

    def find(text: str) -> Iterator[tuple[int, int, str]]:
        for m in rx.finditer(text):
            value = m.group(group)
            if keep is None or keep(value):
                yield m.start(group), m.end(group), value

    return find


# Placeholder spellings for tokens that have a vendor prefix: "xoxb-your-token",
# "sk-ant-...", "<token>", "xxxx". Matching one of these is documentation, not a leak.
_TOKEN_PLACEHOLDER = re.compile(
    r"(?:[xX.*_\-…]*|<[^>]*>|(?:your|my|example|placeholder|redacted|changeme|dummy|fake|"
    r"test|token|secret|key|value|xxx)\b.*)",
    re.IGNORECASE,
)


def _vendor_token(prefix: str, body: str) -> _Finder:
    rx = re.compile(rf"(?<![A-Za-z0-9])({prefix})({body})")

    def find(text: str) -> Iterator[tuple[int, int, str]]:
        for m in rx.finditer(text):
            if not _TOKEN_PLACEHOLDER.fullmatch(m.group(2)):
                yield m.start(), m.end(), m.group(0)

    return find


def _has_digit_and_letter(value: str) -> bool:
    return any(c.isdigit() for c in value) and any(c.isalpha() for c in value)


# First labels of dotted CODE expressions whose last label happens to spell a TLD:
# Terraform (var.org, local.eu), GitHub Actions (inputs.org, env.no), Python (self.io).
# Deliberately short. Words like "status", "data" or "github" are ordinary leftmost labels
# of real domains (status.<org>.nl, data.<gov>.nl), and skipping them would blind the class
# to exactly the hosts it exists to catch. Most code expressions never reach this list
# anyway, because their last label is not a TLD.
_CODE_ROOTS = frozenset(
    [
        "var",
        "local",
        "locals",
        "module",
        "inputs",
        "secrets",
        "env",
        "steps",
        "matrix",
        "needs",
        "vars",
        "self",
        "this",
        "each",
        "count",
        "terraform",
        "runner",
        "strategy",
    ]
)

# Two-letter endings that are file extensions far more often than country domains. A real
# domain on one of these is still caught by the literal layer when it is in the mapping.
_EXTENSION_TLDS = frozenset(
    [
        "md",
        "py",
        "sh",
        "tf",
        "rs",
        "pl",
        "ps",
        "cs",
        "rb",
        "js",
        "ts",
        "go",
        "cc",
        "hs",
        "ml",
        "mk",
        "in",
        "db",
        "so",
        "gz",
        "xz",
        "bz",
        "ac",
        "am",
        "sv",
        "vb",
        "fs",
        "el",
        "lo",
        "la",
        "pm",
        "cm",
        "ex",
    ]
)

# Generic and geographic TLDs an organisation registers. Every two-letter label is also
# treated as a country code (minus the extensions above), which is where most leaks live.
_GENERIC_TLDS = frozenset(
    [
        "com",
        "net",
        "org",
        "info",
        "biz",
        "edu",
        "gov",
        "mil",
        "int",
        "aero",
        "asia",
        "coop",
        "jobs",
        "mobi",
        "museum",
        "pro",
        "tel",
        "travel",
        "app",
        "dev",
        "page",
        "cloud",
        "tech",
        "online",
        "site",
        "website",
        "store",
        "shop",
        "blog",
        "xyz",
        "top",
        "club",
        "vip",
        "live",
        "news",
        "link",
        "life",
        "world",
        "today",
        "email",
        "digital",
        "systems",
        "services",
        "solutions",
        "software",
        "technology",
        "tools",
        "agency",
        "company",
        "consulting",
        "group",
        "global",
        "media",
        "studio",
        "design",
        "space",
        "zone",
        "security",
        "support",
        "team",
        "works",
        "host",
        "hosting",
        "icu",
        "one",
        "global",
        "amsterdam",
        "frl",
        "brussels",
        "vlaanderen",
        "gent",
        "berlin",
        "hamburg",
        "koeln",
        "london",
        "paris",
        "wien",
        "nyc",
        "tokyo",
        "microsoft",
        "azure",
        "google",
        "amazon",
        "aws",
    ]
)


def _is_tld(label: str) -> bool:
    if not label.isascii() or not label.isalpha() or label != label.lower():
        return False
    if len(label) == 2:
        return label not in _EXTENSION_TLDS
    return label in _GENERIC_TLDS


# A host is not followed by ".<more>": "environments.dev.account_id" is a key path in HCL,
# not the domain environments.dev. A sentence-ending full stop is still fine.
_HOST = re.compile(
    r"(?<![A-Za-z0-9._%+@-])"
    r"((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63})"
    r"(?![A-Za-z0-9_-])(?!\.[A-Za-z0-9_])"
)


def _called(text: str, end: int) -> bool:
    """``m.group(1)`` and ``items.info[0]`` are code: a host is never called or indexed."""
    return text[end : end + 1] in ("(", "[")


def _find_domains(text: str) -> Iterator[tuple[int, int, str]]:
    for m in _HOST.finditer(text):
        host = m.group(1)
        labels = host.split(".")
        if labels[0].lower() in _CODE_ROOTS or not _is_tld(labels[-1]) or _called(text, m.end(1)):
            continue
        yield m.start(1), m.end(1), host


_PRIVATE_SUFFIXES = (
    "internal",
    "local",
    "lan",
    "corp",
    "intranet",
    "intra",
    "private",
    "localdomain",
    "home.arpa",
)
_PRIVATE_HOST = re.compile(
    r"(?<![A-Za-z0-9._-])((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+(?:"
    + "|".join(re.escape(s) for s in _PRIVATE_SUFFIXES)
    + r"))(?![A-Za-z0-9_-])(?!\.[A-Za-z0-9])",  # the suffix is the LAST label
    re.IGNORECASE,
)


def _find_private_hosts(text: str) -> Iterator[tuple[int, int, str]]:
    for m in _PRIVATE_HOST.finditer(text):
        if m.group(1).split(".")[0].lower() not in _CODE_ROOTS and not _called(text, m.end(1)):
            yield m.start(1), m.end(1), m.group(1)


_EMAIL = re.compile(
    r"(?<![A-Za-z0-9._%+-])([A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63})(?![A-Za-z0-9-])"
)


def _find_emails(text: str) -> Iterator[tuple[int, int, str]]:
    for m in _EMAIL.finditer(text):
        yield m.start(1), m.end(1), m.group(1)


# An address not preceded by a version marker or another octet, and not followed by more
# octets. "v1.2.3.4" is a version; "1.2.3.4" is somebody's host.
_IPV4 = re.compile(r"(?<![0-9A-Za-z.])(?<![vV])(\d{1,3}(?:\.\d{1,3}){3})(/\d{1,2})?(?!\.?\d)")


def _find_public_ipv4(text: str) -> Iterator[tuple[int, int, str]]:
    for m in _IPV4.finditer(text):
        try:
            addr = ipaddress.IPv4Address(m.group(1))
        except ValueError:
            continue
        if _is_public(addr):
            yield m.start(), m.end(), m.group(0)


_IPV6_CANDIDATE = re.compile(
    r"(?<![0-9A-Za-z:.])([0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7})(/\d{1,3})?(?![0-9A-Za-z:])"
)


def _find_public_ipv6(text: str) -> Iterator[tuple[int, int, str]]:
    for m in _IPV6_CANDIDATE.finditer(text):
        try:
            addr = ipaddress.IPv6Address(m.group(1))
        except ValueError:
            continue
        if _is_public(addr):
            yield m.start(), m.end(), m.group(0)


def _is_public(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if any(addr in net for net in DOCUMENTATION_NETWORKS):
        return False
    return addr.is_global and not addr.is_multicast


_GPS = re.compile(r"(?<![\d.])(-?\d{1,2}\.\d{4,})\s*,\s*(-?\d{1,3}\.\d{4,})(?![\d.])")


def _find_gps(text: str) -> Iterator[tuple[int, int, str]]:
    for m in _GPS.finditer(text):
        lat, lon = float(m.group(1)), float(m.group(2))
        if abs(lat) <= 90 and abs(lon) <= 180:
            yield m.start(), m.end(), m.group(0)


_ACCOUNT_12 = re.compile(r"(?<![0-9A-Za-z-])(\d{12}|\d{4}-\d{4}-\d{4})(?![0-9A-Za-z]|-\d)")


def _find_accounts(text: str) -> Iterator[tuple[int, int, str]]:
    for m in _ACCOUNT_12.finditer(text):
        yield m.start(1), m.end(1), m.group(1).replace("-", "")


_CREDENTIAL = re.compile(
    r"(?i)(?<![A-Za-z0-9])(?:password|passwd|pwd|secret|token|api[_-]?key|client[_-]?secret)"
    r"(?![A-Za-z0-9])\s*[:=]\s*['\"]?(?P<v>[^\s'\"`<>{}$]{8,})"
)
_REFERENCE_MARKERS = (
    "os.environ",
    "secretkeyref",
    "valuefrom",
    "vault:",
    "op://",
    "keyvault",
    "ref+",
    "env:",
)


def _find_credentials(text: str) -> Iterator[tuple[int, int, str]]:
    for m in _CREDENTIAL.finditer(text):
        value = m.group("v")
        low = value.lower()
        if (
            not _has_digit_and_letter(value)
            or re.fullmatch(r"[A-Z0-9_]+", value)  # an environment variable NAME
            or any(marker in low for marker in _REFERENCE_MARKERS)
            or _TOKEN_PLACEHOLDER.fullmatch(value)
            or re.match(r"(?i)(?:changeme|replace|example|placeholder|redacted|xxx)", value)
        ):
            continue
        yield m.start("v"), m.end("v"), value


#: Layer 2. Each row names a shape, why it identifies an organisation or opens a door, and
#: how to find it. Order does not matter.
PATTERN_CLASSES: tuple[PatternClass, ...] = (
    PatternClass(
        "account-12",
        "A 12-digit number is an AWS account ID until shown otherwise; it names the tenant.",
        _find_accounts,
    ),
    PatternClass(
        "uuid",
        "Azure subscription, tenant, client and object IDs are UUIDs and identify the estate.",
        _regex(
            r"(?<![0-9A-Za-z-])[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?![0-9A-Za-z-])"
        ),
    ),
    PatternClass(
        "truncated-id",
        "A shortened hex identifier is still that identifier: truncation is how IDs slipped "
        "past a literal list.",
        _regex(
            r"(?<![0-9A-Za-z])([0-9a-fA-F]{6,}(?:-[0-9a-fA-F]{1,12})*)-?" + _ELLIPSIS,
            group=1,
            keep=_has_digit_and_letter,
        ),
    ),
    PatternClass(
        "hex-32",
        "32-character hex strings are Cloudflare account/zone IDs and similar tenant handles.",
        _regex(r"(?<![0-9A-Za-z])[0-9a-f]{32}(?![0-9A-Za-z])", keep=_has_digit_and_letter),
    ),
    PatternClass(
        "ipv4-public",
        "A public address outside the documentation ranges belongs to someone, often the "
        "source org.",
        _find_public_ipv4,
    ),
    PatternClass("ipv6-public", "As ipv4-public, for IPv6.", _find_public_ipv6),
    PatternClass(
        "domain",
        "A registrable domain that is neither a placeholder nor allowlisted may be the org's own.",
        _find_domains,
    ),
    PatternClass(
        "private-host",
        "Internal DNS suffixes (.internal, .corp, .local, ...) name private infrastructure.",
        _find_private_hosts,
    ),
    PatternClass(
        "email",
        "An address outside the placeholder domains names a person or a team.",
        _find_emails,
    ),
    PatternClass("gps", "A decimal coordinate pair locates a site.", _find_gps),
    PatternClass(
        "age-recipient",
        "An age recipient is a public key, but a unique one: it ties the page to one key "
        "custodian.",
        _regex(r"(?<![A-Za-z0-9])age1[a-z0-9]{10,}"),
    ),
    PatternClass("age-secret-key", "An age private key.", _regex(r"AGE-SECRET-KEY-1[0-9A-Z]{10,}")),
    PatternClass(
        "aws-access-key-id",
        "An AWS access key ID.",
        _regex(r"(?<![A-Z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])"),
    ),
    PatternClass("slack-token", "A Slack token.", _vendor_token(r"xox[baprs]-", r"[A-Za-z0-9-]*")),
    PatternClass(
        "github-token",
        "A GitHub token.",
        _vendor_token(r"gh[pousr]_|github_pat_", r"[A-Za-z0-9_]{20,}"),
    ),
    PatternClass(
        "anthropic-key",
        "An Anthropic API key or OAuth token.",
        _vendor_token(r"sk-ant-", r"[A-Za-z0-9_-]{8,}"),
    ),
    PatternClass(
        "openai-style-key",
        "An OpenAI or LiteLLM virtual key.",
        _vendor_token(r"sk-(?:proj-)?", r"[A-Za-z0-9]{20,}"),
    ),
    PatternClass(
        "onepassword-token",
        "A 1Password service-account token.",
        _vendor_token(r"ops_", r"[A-Za-z0-9_-]{20,}"),
    ),
    PatternClass("google-api-key", "A Google API key.", _regex(r"AIza[0-9A-Za-z_-]{35}")),
    PatternClass(
        "google-oauth-secret",
        "A Google OAuth client secret.",
        _vendor_token(r"GOCSPX-", r"[A-Za-z0-9_-]{10,}"),
    ),
    PatternClass(
        "private-key", "A private key block.", _regex(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----")
    ),
    PatternClass(
        "jwt",
        "A signed token carries claims that name the issuer and subject.",
        _regex(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    ),
    PatternClass(
        "webhook-url",
        "Incoming-webhook URLs are bearer credentials.",
        _regex(
            r"https://(?:hooks\.slack\.com/services|[A-Za-z0-9-]+\.webhook\.office\.com|discord(?:app)?\.com/api/webhooks)/[^\s)>\]]+"
        ),
    ),
    PatternClass("azure-sas", "An Azure SAS signature.", _regex(r"[?&]sig=[A-Za-z0-9%/+=]{20,}")),
    PatternClass(
        "azure-account-key",
        "An Azure storage account key.",
        _regex(r"AccountKey=[A-Za-z0-9+/=]{20,}"),
    ),
    PatternClass(
        "credential",
        "A password, secret or token assigned inline in an example.",
        _find_credentials,
    ),
)


# --- running the layers ------------------------------------------------------------------


class _Lines:
    """Offset -> (line, column) for one text, and the text of a given line."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.starts = [0] + [m.end() for m in re.finditer("\n", text)]

    def locate(self, offset: int) -> tuple[int, int]:
        i = bisect.bisect_right(self.starts, offset) - 1
        return i + 1, offset - self.starts[i] + 1

    def line_at(self, offset: int) -> str:
        i = bisect.bisect_right(self.starts, offset) - 1
        end = self.starts[i + 1] - 1 if i + 1 < len(self.starts) else len(self.text)
        return self.text[self.starts[i] : end]


def _scan_text(
    label: str, text: str, rules: Rules, matcher: _LiteralMatcher, *, is_path: bool = False
) -> list[Finding]:
    lines = _Lines(text)
    findings: list[Finding] = []
    literal_spans: list[tuple[int, int]] = []

    def at(offset: int) -> tuple[int, int]:
        return (0, 0) if is_path else lines.locate(offset)

    for start, end, lit in matcher.find(text):
        line, col = at(start)
        origin = lit.origin if lit else "mapping value"
        findings.append(Finding(1, "literal", label, line, col, text[start:end], origin))
        literal_spans.append((start, end))
    for start, end, lit in matcher.find_truncated(text):
        if any(s < end and start < e for s, e in literal_spans):
            continue
        line, col = at(start)
        findings.append(
            Finding(
                1, "literal-truncated", label, line, col, text[start:end], f"truncated {lit.origin}"
            )
        )
        literal_spans.append((start, end))

    for pc in PATTERN_CLASSES:
        for start, end, value in pc.find(text):
            # A layer-2 hit inside a layer-1 hit is the same leak reported twice.
            if any(s < end and start < e for s, e in literal_spans):
                continue
            if rules.placeholders.permits(pc.name, value):
                continue
            if rules.allow.permits(pc.name, value, lines.line_at(start), label):
                continue
            line, col = at(start)
            findings.append(Finding(2, pc.name, label, line, col, value, pc.why))
    return findings


def audit_files(
    files: Mapping[str, bytes],
    rules: Rules,
    *,
    cleared_binaries: frozenset[str] = frozenset(),
    novelty: Novelty | None = None,
    extra_texts: Mapping[str, str] | None = None,
) -> AuditResult:
    """Audit an in-memory tree (relative POSIX path -> bytes) plus any outbound text.

    ``extra_texts`` is everything else that leaves the process: the pull-request title and
    body, commit messages, branch names, issue text, generated nav. Each is reported under
    ``<its name>``.
    """
    matcher = _LiteralMatcher(rules.literals)
    findings: list[Finding] = []

    for path in sorted(files):
        findings.extend(_scan_text(path, path, rules, matcher, is_path=True))
        data = files[path]
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = None
        if text is None or "\x00" in text:
            digest = hashlib.sha256(data).hexdigest()
            if digest not in cleared_binaries:
                findings.append(
                    Finding(
                        2,
                        "binary-not-cleared",
                        path,
                        0,
                        0,
                        digest,
                        "binary content no human has cleared by hash",
                    )
                )
            continue
        findings.extend(_scan_text(path, text, rules, matcher))

    for name in sorted(extra_texts or {}):
        findings.extend(_scan_text(f"<{name}>", (extra_texts or {})[name], rules, matcher))

    layers = {
        "literal": "passed" if rules.literals else "skipped: no mapping loaded",
        "patterns": "passed",
    }
    if novelty is None:
        layers["novelty"] = "skipped: no source scan supplied"
    else:
        findings.extend(_novelty_findings(novelty))
        layers["novelty"] = "passed"

    for layer_no, name in enumerate(LAYERS, start=1):
        if any(f.layer == layer_no for f in findings):
            layers[name] = "failed"
    return AuditResult(findings=findings, layers=layers, files=len(files))


def _novelty_findings(novelty: Novelty) -> Iterator[Finding]:
    for cand in sorted(novelty.candidates, key=lambda c: (c.where, c.term)):
        path, _, line = cand.where.rpartition(":")
        decision = novelty.decisions.get(cand.term.casefold())
        if decision is None:
            yield Finding(
                3,
                "novelty-unclassified",
                path,
                int(line or 0),
                0,
                cand.term,
                "unmapped name-like term was never classified",
            )
        elif decision.sensitive:
            yield Finding(
                3,
                "novelty-sensitive",
                path,
                int(line or 0),
                0,
                cand.term,
                f"classified sensitive ({decision.origin}) and has no mapping",
            )


def read_tree(root: Path) -> dict[str, bytes]:
    """Every file under ``root`` as relative POSIX path -> bytes, skipping VCS internals."""
    files: dict[str, bytes] = {}
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        if ".git" in rel.parts or not path.is_file():
            continue
        files[rel.as_posix()] = path.read_bytes()
    return files


def audit_tree(root: Path, rules: Rules, **kwargs: object) -> AuditResult:
    return audit_files(read_tree(root), rules, **kwargs)  # type: ignore[arg-type]
