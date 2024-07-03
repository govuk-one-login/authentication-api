#!/usr/bin/env bash
set -euo pipefail

if ! command -v "gh" &> /dev/null; then
  echo "'gh' is required to run this script. Please install it from https://cli.github.com/"
  exit 1
fi

# Update the remote to get the latest branches
git remote update &> /dev/null

current_branch=$(git rev-parse --abbrev-ref HEAD)
if [ -z "${current_branch}" ]; then
  echo "Failed to determine current branch"
  exit 1
fi

if ! git merge-base --is-ancestor HEAD "@{u}"; then
  echo "Local branch appears to be diverged from remote. This may be okay, I just thought you should know."
fi

gh workflow run "deploy-api-modules-dev.yml" --ref "${current_branch}"
