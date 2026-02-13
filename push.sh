#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$HOME/Tools/ClientSideEye-Burp/ClientSideEye-Burp"
EXCLUDE_FILE=".rules"
EXPECTED_REMOTE_PREFIX="git@github-personal:U17Leetha/ClientSideEye-Burp.git"

cd "$REPO_DIR"

# --- Sanity checks ---
if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "[!] Not a git repository: $REPO_DIR"
  exit 1
fi

BRANCH="$(git branch --show-current)"
if [[ -z "${BRANCH:-}" ]]; then
  echo "[!] Detached HEAD state. Aborting."
  exit 1
fi

REMOTE_URL="$(git remote get-url origin)"

echo "[*] Repository : $REPO_DIR"
echo "[*] Branch     : $BRANCH"
echo "[*] Remote     : $REMOTE_URL"
echo "[*] Excluding  : $EXCLUDE_FILE"
echo

# --- Remote guardrail ---
if [[ "$REMOTE_URL" != "$EXPECTED_REMOTE_PREFIX" ]]; then
  echo "[!] Remote mismatch!"
  echo "    Expected: $EXPECTED_REMOTE_PREFIX"
  echo "    Found   : $REMOTE_URL"
  echo
  echo "    This script is restricted to your PERSONAL GitHub remote."
  echo "    Aborting to prevent pushing with the wrong identity."
  exit 1
fi

# --- Fetch to sync remote state ---
git fetch -q origin "$BRANCH" 2>/dev/null || true

echo "[*] Git status (excluding $EXCLUDE_FILE):"
git status --short | grep -vE "^.. $EXCLUDE_FILE$" || true
echo

WORK_CHANGES="$(git status --porcelain | grep -vE "^.. $EXCLUDE_FILE$" || true)"

AHEAD_COUNT=0
if git show-ref --verify --quiet "refs/remotes/origin/$BRANCH"; then
  AHEAD_COUNT="$(git rev-list --count "origin/$BRANCH..$BRANCH" 2>/dev/null || echo 0)"
fi

# --- Push-only path ---
if [[ -z "$WORK_CHANGES" && "$AHEAD_COUNT" -gt 0 ]]; then
  echo "[*] Working tree clean, but branch is ahead by $AHEAD_COUNT commit(s)."
  read -rp "[?] Push existing commits now? (y/N): " CONFIRM
  [[ "$CONFIRM" =~ ^[Yy]$ ]] || { echo "[*] Aborted."; exit 0; }

  git push origin "$BRANCH"
  echo
  echo "[✓] Push complete (pushed $AHEAD_COUNT existing commit(s))."
  exit 0
fi

# --- Nothing to do ---
if [[ -z "$WORK_CHANGES" && "$AHEAD_COUNT" -eq 0 ]]; then
  echo "[*] No changes to commit and nothing ahead of origin."
  exit 0
fi

# --- Commit + push path ---
read -rp "[?] Continue with commit + push? (y/N): " CONFIRM
[[ "$CONFIRM" =~ ^[Yy]$ ]] || { echo "[*] Aborted."; exit 0; }

read -rp "[?] Commit message: " COMMIT_MSG
if [[ -z "${COMMIT_MSG:-}" ]]; then
  echo "[!] Commit message cannot be empty."
  exit 1
fi

git add -A
git reset "$EXCLUDE_FILE" 2>/dev/null || true

git commit -m "$COMMIT_MSG"
git push origin "$BRANCH"

echo
echo "[✓] Push complete (excluded $EXCLUDE_FILE)."

