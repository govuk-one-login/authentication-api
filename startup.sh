#!/usr/bin/env bash
set -eu

./gradlew installDist

./build/install/di-authentication-api/bin/di-authentication-api server authentication-api.yml