#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <version>" >&2
  exit 1
fi

VERSION="${1#v}"
CHANGELOG="CHANGELOG.md"

if [[ ! -f "$CHANGELOG" ]]; then
  echo "Missing $CHANGELOG" >&2
  exit 1
fi

awk -v version="$VERSION" '
  $0 ~ "^## \\[" version "\\] -" { in_section=1; print; next }
  in_section && $0 ~ /^## \[/ { exit }
  in_section { print }
' "$CHANGELOG"
