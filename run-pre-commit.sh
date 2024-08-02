#!/usr/bin/env bash
set -euo pipefail

pre-commit run --all-files --from-ref=main --to-ref=HEAD
