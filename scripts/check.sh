#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
CHECK_PYTHON="$(command -v python)"
CHECK_TMP="$(mktemp -d "$PWD/.check-XXXXXX")"
trap 'rm -rf -- "$CHECK_TMP"' EXIT HUP INT TERM
env -i PATH="/usr/bin:/bin" HOME="$CHECK_TMP" TMPDIR="$CHECK_TMP" \
    PYTHONDONTWRITEBYTECODE=1 "$CHECK_PYTHON" -I scripts/offline_checks.py
