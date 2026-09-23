# syntax=docker/dockerfile:1

# Accepted Chargate/KICS findings for this Dockerfile (deliberate, not vulnerabilities):
#   965a08d7 / e36d8880  apt packages (git, ca-certificates) are not version-pinned: they
#                        are toolchain packages from the base image's own Debian release,
#                        and pinning Debian versions breaks on every base-image refresh.
# kics-scan disable=965a08d7-ef86-4f14-8792-4a3b2098937e,e36d8880-3f78-4546-b9a1-12f0745ca0d5

# Builder and runtime share one Python minor: the venv installs into lib/python<minor>, so a
# mismatch makes every import fail at runtime.
ARG PYTHON_VERSION=3.13
ARG NODE_VERSION=22

# ---- builder ----------------------------------------------------------------------------
FROM ghcr.io/astral-sh/uv:python${PYTHON_VERSION}-bookworm-slim AS builder

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /app

# Locked runtime dependencies plus the `verify` extra (the docs site's MkDocs toolchain, so
# `mkdocs build --strict` runs in the pod), then the project itself as a regular install so
# the venv is self-contained.
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --frozen --no-dev --extra verify --no-install-project

COPY . /app
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --extra verify --no-editable

# ---- node -------------------------------------------------------------------------------
# The Claude Code CLI needs Node 22 or newer, and Debian's nodejs package is older, so Node
# comes from the official image (multi-arch, like everything else here).
FROM node:${NODE_VERSION}-bookworm-slim AS node

# ---- runtime ----------------------------------------------------------------------------
FROM python:${PYTHON_VERSION}-slim AS runtime

# The headless `claude` CLI the LLM calls go through. Pinned: a new CLI is a new behaviour,
# and the cache key only covers the model and the prompt template, not the client.
ARG CLAUDE_CODE_VERSION=2.1.280

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:$PATH" \
    DISABLE_AUTOUPDATER=1 \
    DISABLE_TELEMETRY=1 \
    DISABLE_ERROR_REPORTING=1 \
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1

COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules

# git: sparse, shallow, read-only clones of the source repositories. Versions come from
# the base image's Debian release (see the KICS note at the top).
# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
    && node -e "if (Number(process.versions.node.split('.')[0]) < 22) { throw new Error('Node 22+ is required') }" \
    && npm install -g "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}" \
    && claude --version \
    && npm cache clean --force \
    && rm /usr/local/bin/npm \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/.venv /app/.venv

# Non-root, no home in the image: the chart mounts writable emptyDirs for HOME and /work and
# the persistent volume for the LLM cache and run reports, and the root filesystem is
# read-only.
RUN useradd --uid 10001 --user-group --no-create-home --home-dir /home/docs-distributor docs-distributor \
    && docs-distributor --version
USER 10001:10001
WORKDIR /work

ENTRYPOINT ["docs-distributor"]
CMD ["sync"]
