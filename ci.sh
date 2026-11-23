#!/bin/sh
set -eu
project=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# Tek çağrının çıkış kodunu koru. Ret halinde teslim süreci başlatılmaz.
if decision=$(node "$project/gate.cjs" "$@"); then
  printf '%s\n' "$decision"
else
  status=$?
  printf '%s\n' "$decision"
  exit "$status"
fi
printf '%s\n' "$decision" | node "$project/receive.cjs" "$3"
