#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)" || exit 1

if ! command -v tfupdate &> /dev/null; then
  echo "!! tfupdate is not installed. Please install it by running 'brew install tfupdate'"
  exit 1
fi

echo "Running tfupdate lock for all platforms... this may take a while"
tfupdate lock \
  --platform linux_amd64 \
  --platform linux_arm64 \
  --platform darwin_amd64 \
  --platform darwin_arm64 \
  --platform windows_amd64 \
  -r "./ci/terraform"
