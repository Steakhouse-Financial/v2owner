#!/bin/bash
set -euo pipefail

# Usage:
#   ./deploy.sh mainnet MyContract
#   ./deploy.sh base MyContract


# Load environment variables from .env if it exists
set -a
source .env
set +a


if [ $# -lt 2 ]; then
  echo "Usage: $0 <network> <ContractName> [constructor_signature] [constructor_args...]"
  echo "Example: $0 sepolia MyContract constructor(address,uint256) 0x1234... 42"
  exit 1
fi

NETWORK=$1
CONTRACT_NAME=$2
shift 2
CONSTRUCTOR_VALUES=("$@")

if [ "$NETWORK" = "mainnet" ]; then
  RPC_URL="${ETH_RPC_URL}"
  CHAIN_ID=1
elif [ "$NETWORK" = "base" ]; then
  RPC_URL="${BASE_RPC_URL}"
  CHAIN_ID=8453
elif [ "$NETWORK" = "arbitrum" ]; then
  RPC_URL="${ARBITRUM_RPC_URL}"
  CHAIN_ID=42161
else
  echo "Unknown network: $NETWORK"
  echo "Use: mainnet or base"
  exit 1
fi

if [ -z "${PRIVATE_KEY:-}" ] || [ -z "${ETHERSCAN_API_KEY:-}" ]; then
  echo "Please set PRIVATE_KEY and ETHERSCAN_API_KEY environment variables."
  exit 1
fi

ABI_PATH="out/${CONTRACT_NAME}.sol/${CONTRACT_NAME}.json"
if [ ! -f "$ABI_PATH" ]; then
  echo "ABI file not found: $ABI_PATH"
  exit 1
fi

# Extract constructor inputs from ABI
CONSTRUCTOR_SIG=$(jq -r '.abi[] | select(.type=="constructor") | .inputs | map(.type) | join(",")' "$ABI_PATH")
echo "$CONSTRUCTOR_SIG"


CONSTRUCTOR_FLAG=()
# If you provided any constructor values on the CLI, pass them through directly.
if [ ${#CONSTRUCTOR_VALUES[@]} -gt 0 ]; then
  CONSTRUCTOR_FLAG=(--constructor-args "${CONSTRUCTOR_VALUES[@]}")
fi


# Deploy & verify
forge create src/${CONTRACT_NAME}.sol:${CONTRACT_NAME} \
  --chain-id $CHAIN_ID \
  --broadcast \
  --rpc-url $RPC_URL \
  --private-key $PRIVATE_KEY \
  --etherscan-api-key $ETHERSCAN_API_KEY \
  --verify \
  "${CONSTRUCTOR_FLAG[@]}"