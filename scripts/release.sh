#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

if ! command -v gh >/dev/null 2>&1; then
  echo "gh CLI is required" >&2
  exit 1
fi

VERSION="$(sed -n "s/^version = '\''\([^'\'']*\)'\''$/\1/p" build.gradle | head -n 1)"
if [[ -z "$VERSION" ]]; then
  echo "Could not determine version from build.gradle" >&2
  exit 1
fi
TAG="v$VERSION"
VERSIONED_JAR="build/libs/ClientSideEye-Burp-$VERSION.jar"
ROOT_JAR="ClientSideEye-Burp.jar"
NOTES_FILE="$(mktemp)"
trap 'rm -f "$NOTES_FILE"' EXIT

./gradlew clean check jar

if [[ ! -f "$VERSIONED_JAR" ]]; then
  echo "Missing versioned jar: $VERSIONED_JAR" >&2
  exit 1
fi
if [[ ! -f "$ROOT_JAR" ]]; then
  echo "Missing root jar: $ROOT_JAR" >&2
  exit 1
fi

scripts/extract-release-notes.sh "$TAG" > "$NOTES_FILE"

if ! git rev-parse "$TAG" >/dev/null 2>&1; then
  git tag -a "$TAG" -m "ClientSideEye-Burp $VERSION"
  git push origin "$TAG"
fi

if gh release view "$TAG" >/dev/null 2>&1; then
  gh release edit "$TAG" --title "ClientSideEye-Burp $VERSION" --notes-file "$NOTES_FILE"
  gh release upload "$TAG" "$ROOT_JAR" "$VERSIONED_JAR" --clobber
else
  gh release create "$TAG" "$ROOT_JAR" "$VERSIONED_JAR" \
    --title "ClientSideEye-Burp $VERSION" \
    --notes-file "$NOTES_FILE"
fi
