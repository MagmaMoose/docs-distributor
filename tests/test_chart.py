"""The chart and the program must agree: the config.yml the chart renders has to be one the
program accepts, and every guard has to fire. Skipped when helm is not installed."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from docs_distributor import config

CHART = Path(__file__).resolve().parents[1] / "charts" / "docs-distributor"
CI_VALUES = CHART / "ci" / "default-values.yaml"

pytestmark = pytest.mark.skipif(shutil.which("helm") is None, reason="helm is not installed")


def render(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["helm", "template", "t", str(CHART), *args], capture_output=True, text=True, check=False
    )


def documents(*args: str) -> list[dict]:
    out = render(*args)
    assert out.returncode == 0, out.stderr
    return [d for d in yaml.safe_load_all(out.stdout) if d]


def test_default_values_render_an_inert_suspended_cronjob() -> None:
    kinds = {d["kind"]: d for d in documents()}
    assert kinds["CronJob"]["spec"]["suspend"] is True
    assert "Secret" not in kinds


def test_rendered_config_is_accepted_by_the_program() -> None:
    (cm,) = [d for d in documents("--values", str(CI_VALUES)) if d["kind"] == "ConfigMap"]
    cfg = config.parse_config(yaml.safe_load(cm["data"]["config.yml"]))
    assert [s.name for s in cfg.sources] == ["cloud-platform", "public-handbook"]
    assert cfg.sources[0].auth.token_env == "DD_SOURCE_TOKEN_CLOUD_PLATFORM"
    assert cfg.sources[0].url is None  # the private URL comes from the mapping
    gateway = "http://litellm.automation.svc.cluster.local:4000"  # DevSkim: ignore DS137138
    assert cfg.llm.base_url == gateway


def test_the_job_is_hardened() -> None:
    (cron,) = [d for d in documents("--values", str(CI_VALUES)) if d["kind"] == "CronJob"]
    spec = cron["spec"]
    pod = spec["jobTemplate"]["spec"]["template"]["spec"]
    (container,) = pod["containers"]
    assert spec["concurrencyPolicy"] == "Forbid"
    assert pod["securityContext"]["runAsNonRoot"] is True
    assert container["securityContext"]["readOnlyRootFilesystem"] is True
    assert container["securityContext"]["capabilities"]["drop"] == ["ALL"]
    assert container["resources"]["limits"]
    assert pod["automountServiceAccountToken"] is False
    env = {e["name"]: e for e in container["env"]}
    assert env["DD_SOURCE_TOKEN_CLOUD_PLATFORM"]["valueFrom"]["secretKeyRef"]["key"] == (
        "source-token-cloud-platform"
    )
    mapping = next(v for v in pod["volumes"] if v["name"] == "mapping")
    assert [i["key"] for i in mapping["secret"]["items"]] == ["mapping.yml", "mapping-people.yml"]


BASE = ["--values", str(CI_VALUES)]


@pytest.mark.parametrize(
    ("args", "needle"),
    [
        (["--set", "mapping=x"], "Do not put the mapping in values"),
        (["--set", "secrets.existingSecret="], "secrets.existingSecret is required"),
        (["--set", "target.repo=nope"], "target.repo must be owner/name"),
        (["--set", "sources[0].target=elsewhere/x"], "docs/"),  # the schema or the guard
        (["--set", "sources[0].auth.tokenSecretKey="], "tokenSecretKey is required"),
        (["--set", "sources[1].target=docs/cloud-platform"], "share a target directory"),
        (["--set", "secrets.keys.litellmApiKey="], "needs its virtual key"),
        (["--set", "persistence.enabled=false"], "persistent LLM cache"),
        (["--set", "securityContext.readOnlyRootFilesystem=false"], "must stay true"),
    ],
)
def test_guards_fire(args: list[str], needle: str) -> None:
    out = render(*BASE, *args)
    assert out.returncode != 0
    assert needle in out.stderr
