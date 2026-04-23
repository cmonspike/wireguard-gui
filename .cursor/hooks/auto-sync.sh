#!/usr/bin/env bash
set -euo pipefail

if ! command -v git >/dev/null 2>&1; then
  exit 0
fi

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  exit 0
fi

if ! git remote get-url origin >/dev/null 2>&1; then
  exit 0
fi

# Do nothing when there are no tracked/untracked changes.
if [ -z "$(git status --porcelain)" ]; then
  exit 0
fi

# Stage everything except ignored files.
git add -A

# Re-check in case only ignored paths changed.
if [ -z "$(git status --porcelain)" ]; then
  exit 0
fi

timestamp="$(date -u +"%Y-%m-%d %H:%M:%S UTC")"
export GIT_TERMINAL_PROMPT=0
git commit -m "Auto-sync: ${timestamp}" >/dev/null 2>&1 || exit 0
git push >/dev/null 2>&1 || exit 0

exit 0
