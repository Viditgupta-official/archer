#!/bin/sh
set -eu
: "${ARCHER_API_TOKEN:?Set ARCHER_API_TOKEN in the service environment first}"
build_profile="${1:-release}"
case "$build_profile" in debug|release) ;; *) echo 'Use debug or release' >&2; exit 2;; esac
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
exec "$root/target/$build_profile/archer-api"
