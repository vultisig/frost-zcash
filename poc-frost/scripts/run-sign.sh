#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

SESSION_ID="${1:?Usage: run-sign.sh <session-id> [message]}"
SIGN_MESSAGE="${2:-frost-zcash test message}"
SIGNERS="${3:-party-1,party-2}"

echo "=== FROST Sign ==="
echo "Session: $SESSION_ID"
echo "Message: $SIGN_MESSAGE"
echo "Signers: $SIGNERS"
echo ""

SESSION_ID="$SESSION_ID" \
  OPERATION=sign \
  SIGN_MESSAGE="$SIGN_MESSAGE" \
  SIGNERS="$SIGNERS" \
  docker compose up party-1 party-2 relay redis --build --abort-on-container-exit

echo ""
echo "=== Signing Complete ==="
