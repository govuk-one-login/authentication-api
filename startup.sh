#!/usr/bin/env bash
set -eu

source ./scripts/functions.sh

auth_api_startup_start_seconds=$SECONDS

startup

record_timings "startup total" auth_api_startup_start_seconds $SECONDS true

printf "\nauth api startup task timings:\n\n"
for i in "${task_timings[@]}"; do echo "$i"; done
printf "\n"