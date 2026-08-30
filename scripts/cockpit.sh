#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/apps/cockpit"
npm run build
cd "$ROOT"
# HOST/ALLOW_HOST follow PORT's convention. Binding every interface refuses a
# request whose Host is a name -- see README, "Reaching it from another machine"
# -- so ALLOW_HOST is how an operator declares the one name they reach it by.
ARGS=(--port "${PORT:-8791}" --host "${HOST:-127.0.0.1}")
if [ -n "${ALLOW_HOST:-}" ]; then
  for name in ${ALLOW_HOST}; do ARGS+=(--allow-host "$name"); done
fi
exec python3 -m server.app "${ARGS[@]}"
