#!/usr/bin/env bash
set -eu

# Guard: only run locally, not in CI or deployed environments
if [ -n "${CI:-}" ] || [ -n "${GITHUB_ACTIONS:-}" ] || [ -n "${CODEBUILD_BUILD_ID:-}" ]; then
  echo "CI environment detected, skipping Docker check."
  exit 0
fi

if docker info > /dev/null 2>&1; then
  echo "Docker daemon is already running."
  exit 0
fi

echo "Docker daemon is not running. Attempting to start Docker Desktop..."

if [ "$(uname -s)" != "Darwin" ]; then
  echo "Error: Docker is not running. Please start Docker manually." >&2
  exit 1
fi

open -a Docker

DOCKER_STARTUP_TIMEOUT=60
DOCKER_POLL_INTERVAL=3
elapsed=0

echo "Waiting for Docker to start..."
while ! docker info > /dev/null 2>&1; do
  sleep ${DOCKER_POLL_INTERVAL}
  elapsed=$((elapsed + DOCKER_POLL_INTERVAL))

  if [ ${elapsed} -ge ${DOCKER_STARTUP_TIMEOUT} ]; then
    echo "Error: Docker failed to start within ${DOCKER_STARTUP_TIMEOUT}s" >&2
    exit 1
  fi
done

echo "Docker is now running (took ~${elapsed}s)."
