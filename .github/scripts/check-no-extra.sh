#!/usr/bin/env bash
# Fails if any part of upstream's non-AGPL code could be present or
# referenced by the build:
#   1. a tracked path with a component named "extra"
#   2. a tracked file carrying upstream's "no rights granted" notice
#   3. mix.exs, Dockerfile or the main stylesheet referencing "extra"
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

fail=0

paths=$(git ls-files | grep -E '(^|/)extra(/|$)' || true)
if [ -n "$paths" ]; then
  echo "ERROR: tracked paths named 'extra':"
  echo "$paths" | head -20
  fail=1
fi

# Split so this script does not match itself.
notice="no rights to use, distribute"" or otherwise exploit"
files=$(git ls-files -z | xargs -0 grep -IlF "$notice" -- 2>/dev/null || true)
if [ -n "$files" ]; then
  echo "ERROR: files carrying the non-AGPL notice:"
  echo "$files"
  fail=1
fi

for f in mix.exs Dockerfile .dockerignore assets/css/app.css; do
  [ -f "$f" ] || continue
  hits=$(grep -nP '\bextra\b' "$f" || true)
  if [ -n "$hits" ]; then
    echo "ERROR: $f references 'extra':"
    echo "$hits"
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  exit 1
fi
echo "OK: no excluded upstream code present or referenced"
