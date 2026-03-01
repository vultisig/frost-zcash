#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

SESSION_ID="${1:-frozt-import-$(date +%s)}"

if [ -f .env ]; then
  set -a
  source .env
  set +a
fi

if [ -z "${MNEMONIC:-}" ]; then
  echo "ERROR: MNEMONIC not set. Create a .env file with MNEMONIC=..."
  exit 1
fi

echo "=== FROZT Key Import ==="
echo "Session: $SESSION_ID"
echo "Parties: party-1, party-2, party-3 (2-of-3 threshold)"
echo "Expected address: ${EXPECTED_ADDRESS:-<none>}"
echo ""

SESSION_ID="$SESSION_ID" \
  OPERATION=key-import \
  MNEMONIC="$MNEMONIC" \
  EXPECTED_ADDRESS="${EXPECTED_ADDRESS:-}" \
  docker compose up --build --abort-on-container-exit

echo ""
echo "=== Key Import Complete ==="
echo "Session ID: $SESSION_ID"
echo "Keys stored in Docker volumes: party-{1,2,3}-data"
echo ""
echo "To spend: ./scripts/run-spend.sh $SESSION_ID"
