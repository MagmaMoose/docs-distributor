"""Open or update ONE pull request on the docs repo. Never write to its default branch.

A pull request on a public repository is publication: its diff is world-readable the moment
it exists. So this module only ever runs after the audit has passed, and everything it sends
(title, body, commit message, branch name) was passed through the same audit first.

Idempotence is structural. The tree for this run is built on top of the current default
branch; when it equals the default branch there is nothing to propose, and when it equals
the tree already on the sync branch there is nothing new to push. Either way no commit is
made and no second pull request is opened.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from docs_distributor.github import GitHub, blob_sha


class PublishRefused(RuntimeError):
    pass


@dataclass(frozen=True)
class Outcome:
    action: str  # unchanged | up-to-date | created | updated | closed
    branch: str
    pr_url: str | None = None
    commit: str | None = None


def changes_for(
    current: Mapping[str, bytes], generated: Mapping[str, bytes], managed: Sequence[str]
) -> dict[str, bytes | None]:
    """The file changes that make each ``managed`` directory equal ``generated``.

    Paths are relative to the repo root. ``None`` deletes. Files outside the managed
    directories are only ever touched when ``generated`` names them (mkdocs.yml).
    """
    out: dict[str, bytes | None] = {}
    for path in sorted(generated):
        if current.get(path) != generated[path]:
            out[path] = generated[path]
    for path in sorted(current):
        if any(path.startswith(d.rstrip("/") + "/") for d in managed) and path not in generated:
            out[path] = None
    return out


def publish(
    gh: GitHub,
    repo: str,
    *,
    base: str,
    branch: str,
    branch_prefix: str,
    changes: Mapping[str, bytes | None],
    current_blobs: Mapping[str, str],
    title: str,
    body: str,
    commit_message: str,
    labels: Sequence[str] = (),
) -> Outcome:
    """Make the sync branch carry ``changes`` on top of ``base`` and keep one PR open for it.

    ``current_blobs`` (path -> blob sha on the base branch) lets unchanged files skip the
    upload entirely.
    """
    if not branch or branch == base or not branch.startswith(branch_prefix):
        raise PublishRefused(f"refusing to publish to branch {branch!r}")

    existing = gh.open_pull(repo, branch)
    if not changes:
        if existing is not None:
            gh.close_pull(
                repo,
                int(existing["number"]),
                "The published docs already match the sources, so there is nothing left to merge.",
            )
            return Outcome("closed", branch, str(existing["html_url"]))
        return Outcome("unchanged", branch)

    base_head = gh.branch_head(repo, base)
    if base_head is None:
        raise PublishRefused(f"base branch {base!r} does not exist")
    base_tree = gh.commit_tree(repo, base_head)

    entries = []
    for path in sorted(changes):
        data = changes[path]
        if data is None:
            entries.append({"path": path, "mode": "100644", "type": "blob", "sha": None})
            continue
        sha = blob_sha(data)
        if current_blobs.get(path) != sha:
            sha = gh.create_blob(repo, data)
        entries.append({"path": path, "mode": "100644", "type": "blob", "sha": sha})
    tree = gh.create_tree(repo, base_tree, entries)
    if tree == base_tree:
        return Outcome("unchanged", branch)

    branch_head = gh.branch_head(repo, branch)
    if branch_head is not None and gh.commit_tree(repo, branch_head) == tree:
        if existing is None:
            pr = gh.create_pull(repo, title=title, body=body, head=branch, base=base)
            gh.add_labels(repo, int(pr["number"]), list(labels))
            return Outcome("created", branch, str(pr["html_url"]), branch_head)
        if existing.get("title") != title or (existing.get("body") or "") != body:
            gh.update_pull(repo, int(existing["number"]), title=title, body=body)
        return Outcome("up-to-date", branch, str(existing["html_url"]), branch_head)

    commit = gh.create_commit(repo, commit_message, tree, base_head)
    gh.set_branch(repo, branch, commit, exists=branch_head is not None)
    if existing is not None:
        gh.update_pull(repo, int(existing["number"]), title=title, body=body)
        return Outcome("updated", branch, str(existing["html_url"]), commit)
    pr = gh.create_pull(repo, title=title, body=body, head=branch, base=base)
    gh.add_labels(repo, int(pr["number"]), list(labels))
    return Outcome("created", branch, str(pr["html_url"]), commit)
