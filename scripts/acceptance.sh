#!/bin/sh
# Run from the repository root. Never turn an unavailable Docker daemon into
# a passing or skipped acceptance test.
set -eu

go_command=${1:-go}

if [ -z "${LOCALSTACK_AUTH_TOKEN:-}" ]; then
    echo "acceptance: LOCALSTACK_AUTH_TOKEN is required for the pinned LocalStack image." >&2
    echo "Set your developer token locally, or a CI token as a GitHub Actions secret." >&2
    echo "See docs/ci-troubleshooting.md. Do not commit or print the token." >&2
    exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
    echo "acceptance: Docker CLI is missing. Install/start Docker Desktop or Docker Engine." >&2
    exit 1
fi

if ! docker info >/dev/null; then
    echo "acceptance: Docker is not reachable with the current CLI settings." >&2
    echo "Start Docker Desktop or Docker Engine, then check: docker info; docker context ls" >&2
    echo "Also check DOCKER_HOST and DOCKER_CONTEXT for stale overrides." >&2
    exit 1
fi

# Docker Desktop and Colima can use a context socket other than
# /var/run/docker.sock. Pass that same local socket to the Go SDK explicitly.
# Respect an explicit DOCKER_HOST unless DOCKER_CONTEXT overrides it in the CLI.
if [ -n "${DOCKER_CONTEXT:-}" ] || [ -z "${DOCKER_HOST:-}" ]; then
    if ! endpoint=$(docker context inspect --format '{{.Endpoints.docker.Host}}'); then
        echo "acceptance: Cannot inspect the current Docker context." >&2
        exit 1
    fi
    case "$endpoint" in
        unix://*|npipe://*) export DOCKER_HOST="$endpoint" ;;
        *)
            echo "acceptance: Context endpoint is $endpoint; no local socket override applied." >&2
            echo "Remote/SSH/TLS runtimes may need explicit Testcontainers configuration." >&2
            ;;
    esac
fi

echo "acceptance: Docker preflight passed; starting the LocalStack test."
exec "$go_command" test -tags=acceptance ./cmd/csg -run TestAcceptance -count=1 -v
