#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

SESSION_ID="${1:-frozt-keygen-$(date +%s)}"

echo "=== FROZT Keygen ==="
echo "Session: $SESSION_ID"
echo "Parties: party-1, party-2, party-3 (3-of-2 threshold)"
echo ""

SESSION_ID="$SESSION_ID" OPERATION=keygen docker compose up --build --abort-on-container-exit

echo ""
echo "=== Keygen Complete ==="
echo "Session ID: $SESSION_ID"
echo "Keys stored in Docker volumes: party-{1,2,3}-data"
echo ""
echo "To sign:  ./scripts/run-sign.sh $SESSION_ID"
