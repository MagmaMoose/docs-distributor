"""A small GitHub REST client: the calls the pipeline makes, and GitHub App authentication.

Commits are created through the Git Data API rather than pushed. That needs no git binary
for the target, and GitHub signs a commit an App creates this way, so it shows as verified.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import io
import json
import tarfile
import time
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import Any

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from docs_distributor.config import Auth


class GitHubError(RuntimeError):
    def __init__(self, method: str, path: str, status: int, message: str = "") -> None:
        self.status = status
        super().__init__(f"GitHub {method} {path} -> {status} {message}".strip())


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def app_jwt(app_id: str, private_key_pem: str, now: float | None = None) -> str:
    now = int(now if now is not None else time.time())
    header = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    # Backdated a minute for clock skew; GitHub rejects anything valid for over ten minutes.
    claims = _b64url(json.dumps({"iat": now - 60, "exp": now + 540, "iss": app_id}).encode())
    key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("the GitHub App private key is not an RSA key")
    signature = key.sign(f"{header}.{claims}".encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{header}.{claims}.{_b64url(signature)}"


def token_for(
    auth: Auth,
    environ: Mapping[str, str],
    repo: str | None = None,
    client: httpx.Client | None = None,
) -> str | None:
    """A token for one host, from a plain token or a GitHub App installation."""
    if auth.kind == "none":
        return None
    if auth.kind == "token":
        return environ.get(auth.token_env or "", "") or None
    app_id = environ.get(auth.app_id_env, "")
    key = environ.get(auth.private_key_env, "")
    if not app_id or not key:
        raise GitHubError(
            "AUTH", auth.api_url, 0, f"{auth.app_id_env}/{auth.private_key_env} not set"
        )
    jwt = app_jwt(app_id, key)
    http = client or httpx.Client(timeout=30)
    headers = {"authorization": f"Bearer {jwt}", "accept": "application/vnd.github+json"}
    installation = environ.get(auth.installation_id_env, "")
    if not installation:
        if not repo:
            raise GitHubError(
                "AUTH", auth.api_url, 0, "no installation id and no repo to look it up by"
            )
        r = http.get(f"{auth.api_url}/repos/{repo}/installation", headers=headers)
        if r.status_code != 200:
            raise GitHubError("GET", "/repos/{repo}/installation", r.status_code)
        installation = str(r.json()["id"])
    r = http.post(f"{auth.api_url}/app/installations/{installation}/access_tokens", headers=headers)
    if r.status_code != 201:
        raise GitHubError("POST", "/app/installations/{id}/access_tokens", r.status_code)
    return str(r.json()["token"])


def blob_sha(content: bytes) -> str:
    """The git object id GitHub will give this content."""
    return hashlib.sha1(
        f"blob {len(content)}\0".encode() + content, usedforsecurity=False
    ).hexdigest()


class GitHub:
    def __init__(self, api_url: str, token: str | None, client: httpx.Client | None = None) -> None:
        self.api = api_url.rstrip("/")
        self.http = client or httpx.Client(timeout=60, follow_redirects=True)
        self.headers = {
            "accept": "application/vnd.github+json",
            "x-github-api-version": "2022-11-28",
        }
        if token:
            self.headers["authorization"] = f"Bearer {token}"

    def call(self, method: str, path: str, *, ok: tuple[int, ...] = (200, 201), **kw: Any) -> Any:
        r = self.http.request(method, f"{self.api}{path}", headers=self.headers, **kw)
        if r.status_code not in ok:
            message = ""
            with contextlib.suppress(ValueError):
                message = str(r.json().get("message", ""))[:120]
            raise GitHubError(method, path, r.status_code, message)
        return r.json() if r.content else None

    # repository ------------------------------------------------------------------------

    def default_branch(self, repo: str) -> str:
        return str(self.call("GET", f"/repos/{repo}")["default_branch"])

    def is_private(self, repo: str) -> bool:
        return bool(self.call("GET", f"/repos/{repo}")["private"])

    def branch_head(self, repo: str, branch: str) -> str | None:
        try:
            ref = self.call("GET", f"/repos/{repo}/git/ref/heads/{branch}")
        except GitHubError as exc:
            if exc.status == 404:
                return None
            raise
        return str(ref["object"]["sha"])

    def commit_tree(self, repo: str, commit: str) -> str:
        return str(self.call("GET", f"/repos/{repo}/git/commits/{commit}")["tree"]["sha"])

    def download(self, repo: str, ref: str, dest: Path) -> Path:
        """Extract ``repo`` at ``ref`` into ``dest`` (the tarball's top directory stripped)."""
        r = self.http.get(f"{self.api}/repos/{repo}/tarball/{ref}", headers=self.headers)
        if r.status_code != 200:
            raise GitHubError("GET", f"/repos/{repo}/tarball", r.status_code)
        dest.mkdir(parents=True, exist_ok=True)
        with tarfile.open(fileobj=io.BytesIO(r.content), mode="r:gz") as tar:
            for member in tar.getmembers():
                parts = PurePosixPath(member.name).parts[1:]
                if not parts or not (member.isfile() or member.isdir()):
                    continue
                target = dest.joinpath(*parts)
                if ".." in parts or not target.resolve().is_relative_to(dest.resolve()):
                    continue  # a path that escapes the destination is never written
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    fh = tar.extractfile(member)
                    target.write_bytes(fh.read() if fh else b"")
        return dest

    # git data --------------------------------------------------------------------------

    def create_blob(self, repo: str, content: bytes) -> str:
        body = {"content": base64.b64encode(content).decode(), "encoding": "base64"}
        return str(self.call("POST", f"/repos/{repo}/git/blobs", json=body)["sha"])

    def create_tree(self, repo: str, base_tree: str, entries: list[dict[str, Any]]) -> str:
        return str(
            self.call(
                "POST", f"/repos/{repo}/git/trees", json={"base_tree": base_tree, "tree": entries}
            )["sha"]
        )

    def create_commit(self, repo: str, message: str, tree: str, parent: str) -> str:
        body = {"message": message, "tree": tree, "parents": [parent]}
        return str(self.call("POST", f"/repos/{repo}/git/commits", json=body)["sha"])

    def set_branch(self, repo: str, branch: str, sha: str, *, exists: bool) -> None:
        if exists:
            self.call(
                "PATCH", f"/repos/{repo}/git/refs/heads/{branch}", json={"sha": sha, "force": True}
            )
        else:
            self.call(
                "POST", f"/repos/{repo}/git/refs", json={"ref": f"refs/heads/{branch}", "sha": sha}
            )

    # pull requests and issues ----------------------------------------------------------

    def open_pull(self, repo: str, branch: str) -> dict[str, Any] | None:
        owner = repo.split("/")[0]
        pulls = self.call(
            "GET", f"/repos/{repo}/pulls", params={"head": f"{owner}:{branch}", "state": "open"}
        )
        return pulls[0] if pulls else None

    def create_pull(
        self, repo: str, *, title: str, body: str, head: str, base: str
    ) -> dict[str, Any]:
        return dict(
            self.call(
                "POST",
                f"/repos/{repo}/pulls",
                json={"title": title, "body": body, "head": head, "base": base},
            )
        )

    def update_pull(self, repo: str, number: int, *, title: str, body: str) -> None:
        self.call("PATCH", f"/repos/{repo}/pulls/{number}", json={"title": title, "body": body})

    def close_pull(self, repo: str, number: int, comment: str) -> None:
        self.call("POST", f"/repos/{repo}/issues/{number}/comments", json={"body": comment})
        self.call("PATCH", f"/repos/{repo}/pulls/{number}", json={"state": "closed"})

    def add_labels(self, repo: str, number: int, labels: list[str]) -> None:
        if labels:
            self.call("POST", f"/repos/{repo}/issues/{number}/labels", json={"labels": labels})

    def find_issue(self, repo: str, marker: str) -> dict[str, Any] | None:
        issues = self.call(
            "GET", f"/repos/{repo}/issues", params={"state": "open", "per_page": 100}
        )
        return next(
            (i for i in issues if marker in (i.get("body") or "") and "pull_request" not in i), None
        )

    def upsert_issue(self, repo: str, marker: str, title: str, body: str) -> str:
        existing = self.find_issue(repo, marker)
        if existing:
            self.call(
                "PATCH",
                f"/repos/{repo}/issues/{existing['number']}",
                json={"title": title, "body": body},
            )
            return str(existing["html_url"])
        created = self.call("POST", f"/repos/{repo}/issues", json={"title": title, "body": body})
        return str(created["html_url"])
