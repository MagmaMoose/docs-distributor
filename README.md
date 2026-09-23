# docs-distributor

A Kubernetes CronJob that publishes documentation from private repositories into a public
MkDocs site, anonymised on the way. Every week it fetches the source docs, replaces every
real name through a private mapping, checks the result with a deterministic leak audit, and
opens or updates one pull request on the docs repository. If the audit finds anything, it
publishes nothing and exits non-zero.

It exists because doing this by hand, even carefully, leaks. An attentive LLM review of one
14,600-line manual port missed five proprietary values that a literal-and-pattern scan then
found: shortened IDs (an Azure subscription, a CDN cache policy, an age recipient, each cut
off with an ellipsis) and a person's full name in a code comment. The design follows from
that: the model may propose, and only deterministic code decides what publishes.

## Trust model

Only deterministic code decides whether anything publishes. The model is asked four narrow
questions (is this term sensitive, what stand-in fits, fix this grammar, where does this page
go) and never the question that matters. Every answer is checked by Python before it is used,
and the gate runs after all of them. The gate is [`audit.py`](src/docs_distributor/audit.py):
one standard-library-only file with no network and no model, which a test keeps that way,
and whose rules are a table you can read top to bottom. It fails closed on three layers:
**literal** (every real value in the mapping is absent, in any case, across line breaks, and
as any prefix of six or more characters followed by an ellipsis), **pattern classes**
(account numbers, public addresses outside RFC 5737, UUIDs, unknown domains, emails, keys,
coordinates, private host suffixes, minus placeholders and a justified allowlist), and
**novelty** (every name-like token that survived the mapping was classified, and none
classified sensitive is unmapped). Binaries publish only if a human cleared their SHA-256.
The same gate checks the pull-request text, the commit message and the nav before they leave
the process. This repository holds no private data: the mapping, the source URLs and every
token are injected at runtime from one Secret, and a pre-commit hook and a CI job refuse any
commit here that matches a private-value pattern.

## A run

```text
fetch (sparse, read-only) -> transform -> nav -> novelty -> [blocked? propose, issue, stop]
      -> repair -> audit -> verify -> audit the outbound text -> one PR -> Slack
```

| Stage | How | Why |
|---|---|---|
| Fetch | Python, `git` sparse clone of the docs dir only | Mechanical, and the rest of a private repo never lands in the pod |
| Apply the mapping | Python, one longest-first pass | Must be repeatable; a placeholder is never substituted again |
| Links and paths | Python | Private links become code spans; renamed pages keep working links and anchors |
| Candidate names | Python ([`novelty.py`](src/docs_distributor/novelty.py)) | Tokenise, subtract what is known |
| **Is a candidate sensitive?** | **Model**, cached per term | Semantic judgment: customer, or library? |
| **A stand-in for it** | **Model**, except series (`client-k`, `vendor-C`), which Python assigns | Has to fit the scheme |
| **Repair damaged prose** | **Model**, checked: same lines, no new words, placeholders kept | Grammar, not pattern matching |
| **Place an unlisted page** | **Model**, checked against the real nav; the YAML is written by Python | Editorial judgment |
| Audit | Python, no model | The control |
| Verify | Python | Line-count parity, link check, `mkdocs build --strict` |
| Publish | Python, Git Data API | One branch, one PR, never the default branch |

**Determinism.** Every model answer is cached on a volume, keyed by
`sha256(content + template name@version + model id)`. Re-running against unchanged sources
produces byte-identical output, the tree equals what the sync branch already carries, and no
commit or pull request is made. Bump a template's `version` in [`prompts/`](prompts) to
invalidate its answers on purpose.

**Failing closed.** Exit codes tell a CronJob's status apart at a glance: `0` published or
nothing to do, `2` blocked on new sensitive or unclassified terms, `3` audit failed, `4`
verification failed, `5` configuration, `6` fetch or API failure. A blocked run files an issue
that names no term (counts, classes and proposed stand-ins only) and writes the full mapping
proposal to the private run report on the volume.

## Inputs

**Private** (one Kubernetes Secret, never committed anywhere):

```yaml
# mapping.yml: real value -> placeholder. Merge several files with mapping.d/.
version: 1
rules:
  - {from: Acme Logistics, to: the platform owner, class: org, case: preserve}
  - {from: acme-logistics.test, to: example.com, class: domain}
  - {from: Jan de Vries, to: engineer-e, class: person}   # also audits jan.devries, jdevries, ...
  - {from: 'acme-(prd|acc)-west', to: cluster-west, class: cluster, regex: true}  # sparingly; `to` may not copy groups
sources:
  cloud-platform:
    url: https://git.internal.example/org/infra.git      # a URL usually names the org
    drop: ["scratch/**"]                                   # never published
    rename: {"old/path.md": "new/path.md"}
    binaries: [{path: assets/net.png, sha256: ..., why: "reviewed: no names, no addresses"}]
links:
  private_hosts: [git.internal.example]                   # links here become code spans
allow:                                                    # public facts only this source needs
  - {class: term, value: SomeVendorProduct, why: "public product"}
deny:                                                     # must never appear; no stand-in
  - {value: ..., why: ...}
```

Placeholders are vetted on load: each must pass the gate on its own, so a stand-in on a real
top-level domain, which someone could register, or a public address can never be used.

**Public** (committed here): [`allow.yml`](src/docs_distributor/rules/allow.yml) (verified
public values, each with a `why`), [`vocabulary.yml`](src/docs_distributor/rules/vocabulary.yml)
(the placeholder scheme the corpus already uses), and
[`tech-vocabulary.txt`](src/docs_distributor/rules/tech-vocabulary.txt).

## Commands

```bash
docs-distributor plan  --config config.yml --source cloud-platform=../infra --docs-repo ../docs --out /tmp/out
docs-distributor sync  --config config.yml            # what the CronJob runs
docs-distributor audit docs/cloud-platform            # the gate alone; --mapping adds the literal layer
docs-distributor onboard ../infra --name cloud-platform --out ~/.config/docs-distributor/proposal.yml
```

The mapping is found at `--mapping`, `$DOCS_DISTRIBUTOR_MAPPING`, the Secret mount, or
`~/.config/docs-distributor/`. `plan` never edits a working tree it is pointed at, and puts
its private report under `~/.cache/docs-distributor/`. `onboard` writes a private proposal:
every candidate, the model's decision, and a stand-in for each sensitive term, for a human
to review before anything goes into the Secret.

## Deploying

The chart is [`charts/docs-distributor`](charts/docs-distributor). With default values it
renders a suspended CronJob; configure `target`, `sources` and `secrets.existingSecret`, and
own that Secret with an ExternalSecret:

```yaml
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata: {name: docs-distributor}
spec:
  secretStoreRef: {kind: ClusterSecretStore, name: your-store}
  target: {name: docs-distributor}
  data:
    - {secretKey: mapping.yml, remoteRef: {key: docs-distributor-mapping}}
    - {secretKey: github-app-id, remoteRef: {key: docs-distributor-github-app-id}}
    - {secretKey: github-app-private-key, remoteRef: {key: docs-distributor-github-app-key}}
    - {secretKey: source-token-cloud-platform, remoteRef: {key: docs-distributor-source-token}}
    - {secretKey: claude-oauth-token, remoteRef: {key: docs-distributor-claude-oauth-token}}
    - {secretKey: litellm-api-key, remoteRef: {key: docs-distributor-litellm-key}}
```

The model runs as headless Claude Code (`claude -p`), which is how a Claude subscription is
used from automation. Set `llm.baseUrl` to route it through a LiteLLM gateway: the OAuth token
from `claude setup-token` becomes the upstream bearer and the gateway's virtual key rides
`x-litellm-api-key`, on the gateway's raw listener. `llm.backend: anthropic` uses an API key
instead.

The GitHub App needs contents and pull-requests write on the docs repository (issues write on
`report.issueRepo`). Source tokens need read access and nothing else: this tool never writes
to a source.

## Development

```bash
uv sync
uv run pytest            # includes a real mkdocs build --strict when helm/mkdocs are present
uv run ruff check src tests && uv run mypy
UPDATE_GOLDEN=1 uv run pytest tests/test_acceptance.py   # then review the golden diff
```

The fixture corpus under [`tests/fixtures`](tests/fixtures) is synthetic: there is no
Hollowbrook. [`tests/fixtures/planted`](tests/fixtures/planted) plants one of each leak the
gate must catch.
