#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

SESSION_ID="${1:?Usage: run-spend.sh <session-id> [recipient-address] [send-amount-zatoshis]}"
RECIPIENT_ADDRESS="${2:-zs16e9zw4av0tnduqenmz2y5kllpwm09juz29wxusvdzp9acl6fs33geyzfhd0xfp8f903tuk0l74z}"
SEND_AMOUNT="${3:-5000000}"
SIGNERS="${4:-party-1,party-2}"
LIGHTWALLETD_ENDPOINT="${LIGHTWALLETD_ENDPOINT:-mainnet.lightwalletd.com:9067}"

if [ -f .env ]; then
  set -a
  source .env
  set +a
fi

echo "=== FROZT Spend ==="
echo "Session: $SESSION_ID"
echo "Recipient: $RECIPIENT_ADDRESS"
echo "Amount: $SEND_AMOUNT zatoshis"
echo "Signers: $SIGNERS"
echo "Lightwalletd: $LIGHTWALLETD_ENDPOINT"
echo "Birthday: ${BIRTHDAY:-<auto>}"
echo ""

SESSION_ID="$SESSION_ID" \
  OPERATION=spend \
  SIGNERS="$SIGNERS" \
  RECIPIENT_ADDRESS="$RECIPIENT_ADDRESS" \
  SEND_AMOUNT="$SEND_AMOUNT" \
  LIGHTWALLETD_ENDPOINT="$LIGHTWALLETD_ENDPOINT" \
  BIRTHDAY="${BIRTHDAY:-}" \
  docker compose up party-1 party-2 relay redis --build --abort-on-container-exit

echo ""
echo "=== Spend Complete ==="
