#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$HOME/Tools/ClientSideEye-Burp/ClientSideEye-Burp"
EXCLUDE_FILE=".rules"

cd "$REPO_DIR"

# --- Sanity checks ---
if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "[!] Not a git repository: $REPO_DIR"
  exit 1
fi

BRANCH="$(git branch --show-current)"
if [[ -z "$BRANCH" ]]; then
  echo "[!] Detached HEAD state. Aborting."
  exit 1
fi

echo "[*] Repository : $REPO_DIR"
echo "[*] Branch     : $BRANCH"
echo "[*] Remote     : $(git remote get-url origin)"
echo "[*] Excluding  : $EXCLUDE_FILE"
echo

# --- Show status (excluding .rules) ---
echo "[*] Git status (excluding $EXCLUDE_FILE):"
git status --short | grep -vE "^.. $EXCLUDE_FILE$" || true
echo

if [[ -z "$(git status --porcelain | grep -vE "^.. $EXCLUDE_FILE$")" ]]; then
  echo "[*] No changes to push (after exclusions)."
  exit 0
fi

# --- Confirm ---
read -rp "[?] Continue with commit + push? (y/N): " CONFIRM
if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
  echo "[*] Aborted."
  exit 0
fi

# --- Commit message ---
read -rp "[?] Commit message: " COMMIT_MSG
if [[ -z "$COMMIT_MSG" ]]; then
  echo "[!] Commit message cannot be empty."
  exit 1
fi

# --- Stage everything except .rules ---
git add -A
git reset "$EXCLUDE_FILE" 2>/dev/null || true

git commit -m "$COMMIT_MSG"
git push origin "$BRANCH"

echo
echo "[✓] Push complete (excluded $EXCLUDE_FILE)."

