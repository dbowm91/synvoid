#!/usr/bin/env bash
# Thin wrapper for the manual-only multi-service benchmark driver.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$HERE/../driver.py" "$@"
