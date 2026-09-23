"""Fetch source repositories: read-only, shallow, and only the docs.

Sync is one-way. This module can clone and nothing else; there is no push anywhere in it,
and the credentials a source is given should be read-only as well.

A clone is sparse: the docs directory and the nav file are the only paths checked out, so
the rest of a private repository (state files, secrets, application code) never lands in the
pod.
"""

from __future__ import annotations

import base64
import os
import subprocess  # nosec B404 - git runs with a fixed argv and no shell
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from docs_distributor.config import SourceConfig, load_yaml


class SourceError(RuntimeError):
    pass


@dataclass
class FetchedSource:
    name: str
    docs: dict[str, bytes]  # path relative to the docs dir -> content
    nav: list[Any] | None
    revision: str  # PRIVATE: a commit of a private repository; the report only


def read_docs(root: Path, cfg: SourceConfig) -> tuple[dict[str, bytes], list[Any] | None]:
    docs_root = root / cfg.docs_dir
    if not docs_root.is_dir():
        raise SourceError(f"source {cfg.name}: docs directory {cfg.docs_dir!r} not found")
    files = {
        p.relative_to(docs_root).as_posix(): p.read_bytes()
        for p in sorted(docs_root.rglob("*"))
        if p.is_file() and ".git" not in p.relative_to(root).parts
    }
    nav = None
    if cfg.nav_file and (root / cfg.nav_file).is_file():
        data = load_yaml(root / cfg.nav_file)
        nav = data.get("nav") if isinstance(data, dict) else None
    return files, nav


def load_local(cfg: SourceConfig, path: Path) -> FetchedSource:
    """A source that is already on disk (``plan --source name=PATH``)."""
    files, nav = read_docs(path, cfg)
    revision = (
        _git(["rev-parse", "HEAD"], cwd=path, env=_git_env(None), check=False).strip() or "local"
    )
    return FetchedSource(cfg.name, files, nav, revision)


def fetch(cfg: SourceConfig, url: str, token: str | None, workdir: Path) -> FetchedSource:
    dest = workdir / "sources" / cfg.name
    if dest.exists():
        _rmtree(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    env = _git_env(token)
    _git(
        [
            "clone",
            "--quiet",
            "--depth",
            "1",
            "--branch",
            cfg.ref,
            "--filter=blob:none",
            "--no-checkout",
            "--",
            url,
            str(dest),
        ],
        cwd=workdir,
        env=env,
    )
    paths = [f"/{cfg.docs_dir}/"]
    if cfg.nav_file:
        paths.append(f"/{cfg.nav_file}")
    _git(["sparse-checkout", "set", "--no-cone", *paths], cwd=dest, env=env)
    _git(["checkout", "--quiet"], cwd=dest, env=env)
    revision = _git(["rev-parse", "HEAD"], cwd=dest, env=env).strip()
    files, nav = read_docs(dest, cfg)
    return FetchedSource(cfg.name, files, nav, revision)


def _git_env(token: str | None) -> dict[str, str]:
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", tempfile.gettempdir()),  # git wants one; writes nothing
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
    }
    if token:
        # The credential rides an HTTP header set through the environment, so it is never in
        # argv (visible in the process table) or written to .git/config.
        basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        env |= {
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "http.extraHeader",
            "GIT_CONFIG_VALUE_0": f"Authorization: Basic {basic}",
        }
    return env


def _git(args: list[str], *, cwd: Path, env: Mapping[str, str], check: bool = True) -> str:
    try:
        proc = subprocess.run(  # noqa: S603 # nosec B603 B607 - fixed argv, no shell
            ["git", *args],  # noqa: S607 — git from PATH, as in any container
            cwd=cwd,
            env=dict(env),
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SourceError(f"git {args[0]} failed to run: {type(exc).__name__}") from exc
    if check and proc.returncode != 0:
        # git's stderr can echo the remote URL, which names the source. Report the verb and
        # the exit code only; the private report gets nothing more either.
        raise SourceError(f"git {args[0]} exited {proc.returncode}")
    return proc.stdout


def _rmtree(path: Path) -> None:
    import shutil

    shutil.rmtree(path)
