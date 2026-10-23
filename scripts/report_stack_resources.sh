#!/usr/bin/env bash
#
# report_stack_resources.sh
#
# Reports CloudFormation resource usage for a stack template directory and
# compares it against the hard 500-resource-per-stack limit.
#
# Produces three views:
#   1. Totals        - authored + estimated SAM-expanded count vs the limit
#   2. By type       - count of each AWS::* resource type across the stack
#   3. By endpoint   - per source file (function/*.yaml etc): total + type breakdown
#                      (each function/*.yaml corresponds to one endpoint/lambda;
#                       logical IDs share a "<Name>Function" prefix)
#
# The stack is assembled the same way the deploy pipeline does: rain merge over
# all *.yaml/*.yml. Merge is purely textual, so no gradle build is required.
#
# Usage:
#   scripts/report_stack_resources.sh <template-source-dir> [stack-name]
#
# Env:
#   HARD_LIMIT        default 500    (CloudFormation resources-per-stack limit)
#   WARN_THRESHOLD    default 450    (warn when estimate >= this)
#   FAIL_ON_WARN      default "false" (exit 1 when >= WARN_THRESHOLD if "true")
#   GITHUB_STEP_SUMMARY  if set, a Markdown report is appended there
#
set -euo pipefail

SRC_DIR="${1:?usage: report_stack_resources.sh <template-source-dir> [stack-name]}"
STACK_NAME="${2:-$(basename "${SRC_DIR}")}"

HARD_LIMIT="${HARD_LIMIT:-500}"
WARN_THRESHOLD="${WARN_THRESHOLD:-450}"
FAIL_ON_WARN="${FAIL_ON_WARN:-false}"

[[ -d "${SRC_DIR}" ]] || { echo "error: dir not found: ${SRC_DIR}" >&2; exit 2; }
# rain is only needed when we have to merge ourselves (no pre-merged MERGED_TEMPLATE).
if [[ -z "${MERGED_TEMPLATE:-}" || ! -f "${MERGED_TEMPLATE:-}" ]]; then
  command -v rain >/dev/null 2>&1 || { echo "error: rain not installed" >&2; exit 2; }
fi

MERGED_FILE="$(mktemp -t "${STACK_NAME}-merged.XXXXXX.yaml")"
trap 'rm -f "${MERGED_FILE}"' EXIT

mapfile_portable() {
  # Build TEMPLATE_FILES array without relying on `mapfile` (bash 4+ only).
  TEMPLATE_FILES=()
  while IFS= read -r _line; do
    TEMPLATE_FILES+=("${_line}")
  done < <(find "${SRC_DIR}" -type f \( -name "*.yaml" -o -name "*.yml" \) | sort)
}
mapfile_portable

# If MERGED_TEMPLATE points at an already-merged file (e.g. produced earlier in the
# CI job by scripts/merge-templates.sh), reuse it instead of merging again.
if [[ -n "${MERGED_TEMPLATE:-}" && -f "${MERGED_TEMPLATE}" ]]; then
  trap - EXIT
  rm -f "${MERGED_FILE}"
  MERGED_FILE="${MERGED_TEMPLATE}"
else
  rain merge "${TEMPLATE_FILES[@]}" -o "${MERGED_FILE}"
fi

# ---- helper: count "Type: AWS::..." lines in a file ----
count_resources() { grep -cE "^[[:space:]]*Type:[[:space:]]*['\"]?AWS::" "$1" 2>/dev/null || true; }

# ================= 1. TOTALS =================
AUTHORED=$(count_resources "${MERGED_FILE}")
SF=$(grep -cE "Type:[[:space:]]*['\"]?AWS::Serverless::Function" "${MERGED_FILE}" || true)
SA=$(grep -cE "Type:[[:space:]]*['\"]?AWS::Serverless::Api" "${MERGED_FILE}" || true)
EXPANDED=$(( AUTHORED + 2 * SF + 3 * SA ))   # Function:+2(Version,Alias), Api:+3
REMAINING=$(( HARD_LIMIT - EXPANDED ))
PCT=$(( EXPANDED * 100 / HARD_LIMIT ))

STATUS="OK"; EMOJI="✅"
if   (( EXPANDED >= HARD_LIMIT ));     then STATUS="OVER LIMIT"; EMOJI="⛔"
elif (( EXPANDED >= WARN_THRESHOLD )); then STATUS="WARN";       EMOJI="⚠️"
fi

# ================= 2. BY TYPE =================
BY_TYPE=$(grep -ohE "AWS::[A-Za-z0-9]+::[A-Za-z0-9]+" "${MERGED_FILE}" | sort | uniq -c | sort -rn)

# ================= 3. BY ENDPOINT (per source file) =================
# One row per template file, with its resource count and a compact type breakdown.
build_by_endpoint() {
  local f rel total types
  for f in "${TEMPLATE_FILES[@]}"; do
    total=$(count_resources "$f")
    (( total > 0 )) || continue
    rel="${f#"${SRC_DIR}"/}"
    # compact per-type breakdown e.g. "Function x1, LogGroup x1, Alarm x2"
    types=$(grep -ohE "AWS::[A-Za-z0-9]+::[A-Za-z0-9]+" "$f" \
      | sed -E 's/AWS::[A-Za-z0-9]+:://' \
      | sort | uniq -c | sort -rn \
      | awk '{printf "%s x%s, ", $2, $1}' | sed 's/, $//')
    printf '%s\t%s\t%s\n' "$total" "$rel" "$types"
  done | sort -rn
}
BY_ENDPOINT=$(build_by_endpoint)

# ================= CONSOLE =================
{
  echo "=================================================================="
  echo " Stack resource report: ${STACK_NAME}   [${STATUS}]"
  echo "=================================================================="
  echo " Source dir         : ${SRC_DIR}"
  echo " Authored resources : ${AUTHORED}"
  echo " Serverless::Function: ${SF} (+2 each)   Serverless::Api: ${SA} (+3 each)"
  echo " Estimated expanded : ${EXPANDED} / ${HARD_LIMIT} (${PCT}%)   headroom: ${REMAINING}"
  echo "------------------------------------------------------------------"
  echo " By resource type:"
  echo "${BY_TYPE}" | sed 's/^/   /'
  echo "------------------------------------------------------------------"
  echo " By endpoint (source file)   [count  file  types]:"
  echo "${BY_ENDPOINT}" | awk -F'\t' '{printf "   %3s  %-40s %s\n", $1, $2, $3}'
  echo "=================================================================="
} >&2

# ================= GITHUB STEP SUMMARY =================
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    echo "### ${EMOJI} \`${STACK_NAME}\` — ${EXPANDED}/${HARD_LIMIT} resources (${PCT}%) — ${STATUS}"
    echo ""
    echo "| Metric | Value |"
    echo "|---|---|"
    echo "| Authored resources | ${AUTHORED} |"
    echo "| Serverless::Function (× +2) | ${SF} |"
    echo "| Serverless::Api (× +3) | ${SA} |"
    echo "| **Estimated expanded** | **${EXPANDED} / ${HARD_LIMIT}** |"
    echo "| Remaining headroom | ${REMAINING} |"
    echo "| Warn threshold | ${WARN_THRESHOLD} |"
    echo ""

    echo "<details><summary>By resource type</summary>"
    echo ""
    echo "| Count | Type |"
    echo "|---:|---|"
    echo "${BY_TYPE}" | awk '{t=$2; $1=$1; printf "| %s | %s |\n", $1, t}'
    echo ""
    echo "</details>"
    echo ""

    echo "<details><summary>By endpoint (source file)</summary>"
    echo ""
    echo "| Count | Source file | Resource types |"
    echo "|---:|---|---|"
    echo "${BY_ENDPOINT}" | awk -F'\t' '{printf "| %s | `%s` | %s |\n", $1, $2, $3}'
    echo ""
    echo "</details>"
    echo ""
    echo "_Expanded total is an estimate (Serverless::Function +2, Serverless::Api +3). Per-file counts are authored resources and exclude SAM expansion. Actual counts vary with active Conditions per environment._"
    echo ""
  } >> "${GITHUB_STEP_SUMMARY}"
fi

# ================= EXIT CODE =================
if (( EXPANDED >= HARD_LIMIT )); then
  echo "::error::${STACK_NAME} at/over ${HARD_LIMIT}-resource limit (estimated ${EXPANDED})."
  exit 1
fi
if (( EXPANDED >= WARN_THRESHOLD )); then
  echo "::warning::${STACK_NAME} estimated ${EXPANDED} resources (headroom ${REMAINING})."
  [[ "${FAIL_ON_WARN}" == "true" ]] && exit 1
fi
exit 0
