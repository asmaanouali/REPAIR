# syntax=docker/dockerfile:1.7
# Multi-stage Dockerfile for IR-SAM.
#
#   ir-sam:dev    - Python + JDK (host language + Spoon). Used for unit/property/
#                   integration tests and day-to-day development.
#   ir-sam:eval   - dev + CodeQL CLI + Semgrep + Maven. Used for stage-A
#                   integration tests and full eval runs.
#   ir-sam:oracle - eval + DB clients (mysql/psql/openldap-utils/saxon).
#                   Used for the deep differential oracle.
#
# Each stage is reproducible: pinned base image, pinned CodeQL CLI version,
# pinned IR-SAM Python deps via pyproject.toml.

# ---------- base ----------
FROM python:3.10.14-slim-bookworm AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        git curl ca-certificates build-essential default-jre-headless \
        unzip xz-utils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

# ---------- dev ----------
FROM base AS dev

COPY pyproject.toml /workspace/
RUN pip install --upgrade pip && pip install -e ".[dev]"

COPY . /workspace
CMD ["bash"]

# ---------- eval ----------
FROM dev AS eval

# CodeQL CLI (pinned for reproducibility).
ARG CODEQL_VERSION=2.17.3
RUN curl -fSL -o /tmp/codeql.zip \
        "https://github.com/github/codeql-cli-binaries/releases/download/v${CODEQL_VERSION}/codeql-linux64.zip" \
    && unzip -q /tmp/codeql.zip -d /opt \
    && rm /tmp/codeql.zip \
    && ln -s /opt/codeql/codeql /usr/local/bin/codeql

# Maven (for stage-A and -G integration on real Java projects).
RUN apt-get update && apt-get install -y --no-install-recommends \
        maven \
    && rm -rf /var/lib/apt/lists/*

# Semgrep + production test deps (mutmut, pip-audit, bandit, vcrpy, scipy, ...).
RUN pip install "semgrep>=1.70" && pip install -e ".[test-prod]"

CMD ["bash"]

# ---------- oracle ----------
FROM eval AS oracle

RUN apt-get update && apt-get install -y --no-install-recommends \
        default-mysql-client postgresql-client \
        ldap-utils libsaxonb-java \
    && rm -rf /var/lib/apt/lists/*

CMD ["bash"]
