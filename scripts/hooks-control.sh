#!/usr/bin/env bash
set -e

echo "Pre-commit hook management:"
echo "  1) Install light hooks (.pre-commit-config-light.yaml only)"
echo "  2) Install full hooks (.pre-commit-config.yaml)"
echo "  3) Uninstall hooks"
read -rp "Choose [1-3]: " choice

case "${choice}" in
  1) pre-commit install -c .pre-commit-config-light.yaml && echo "Light hooks installed." ;;
  2) pre-commit install && echo "Full hooks installed." ;;
  3) pre-commit uninstall && echo "Hooks uninstalled." ;;
  *) echo "Invalid choice." && exit 1 ;;
esac
