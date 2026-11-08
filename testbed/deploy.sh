#!/usr/bin/env bash
# Deploys Registry to any EVM network and runs a smoke test (register gateway + device, anchor one root).
# Usage: ./deploy.sh <vars-file>
#   testbed/besu/besu.vars       local QBFT network (public Anvil test keys)
#   testbed/purechain/.env       PureChain (secret experiment keys, git-ignored)
# The vars file defines RPC, RESPONSE_WINDOW (seconds), ADMIN_KEY, GATEWAY_KEY, GATEWAY_ADDR, DEVICE_ADDR.
# Writes the deployed address next to the vars file as registry-address.txt.
set -euo pipefail
VARS="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
OUT_DIR="$(dirname "$VARS")"
# shellcheck disable=SC1090
set -a; source "$VARS"; set +a
cd "$(dirname "$0")/../contracts"

FOUNDRY_IMAGE="ghcr.io/foundry-rs/foundry:v1.8.4"
HOST_DIR="$(pwd -W 2>/dev/null || pwd)"
foundry() {
  MSYS_NO_PATHCONV=1 docker run --rm --add-host=host.docker.internal:host-gateway \
    -v "$HOST_DIR:/work" -w /work --entrypoint "$1" "$FOUNDRY_IMAGE" "${@:2}"
}
send() { foundry cast send --legacy --gas-price 0 --rpc-url "$RPC" "$@"; }

ADDR=$(foundry forge create src/Registry.sol:Registry --legacy --gas-price 0 --broadcast \
  --rpc-url "$RPC" --private-key "$ADMIN_KEY" --constructor-args "$RESPONSE_WINDOW" "${CHALLENGE_BOND:-0}" \
  | awk '/Deployed to:/ {print $3}')
[[ -n "$ADDR" ]] || { echo "deployment failed" >&2; exit 1; }
echo "Registry deployed at $ADDR"
echo "$ADDR" > "$OUT_DIR/registry-address.txt"

send --private-key "$ADMIN_KEY" "$ADDR" "registerGateway(address)" "$GATEWAY_ADDR" > /dev/null
send --private-key "$ADMIN_KEY" "$ADDR" "registerDevice(uint64,address,address)" 7 "$DEVICE_ADDR" "$GATEWAY_ADDR" > /dev/null

ROOT=$(foundry cast keccak "smoke-test-root-$(date +%s%N)")
OUT=$(send --private-key "$GATEWAY_KEY" --json "$ADDR" "anchor(bytes32)" "$ROOT")
GAS=$(echo "$OUT" | python -c "import sys,json; print(int(json.load(sys.stdin)['gasUsed'],16))")
BLK=$(echo "$OUT" | python -c "import sys,json; print(int(json.load(sys.stdin)['blockNumber'],16))")
TS=$(foundry cast block "$BLK" --field timestamp --rpc-url "$RPC")
AT=$(foundry cast call --rpc-url "$RPC" "$ADDR" "anchoredAt(address,bytes32)(uint256)" "$GATEWAY_ADDR" "$ROOT" | awk '{print $1}')
echo "anchor: gasUsed=$GAS block=$BLK blockTimestamp=$TS anchoredAt=$AT"
[[ "$AT" == "$TS" ]] && echo "SMOKE TEST PASSED" || { echo "SMOKE TEST FAILED"; exit 1; }
