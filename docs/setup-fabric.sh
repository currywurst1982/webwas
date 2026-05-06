#!/usr/bin/env bash
# Quick bootstrap for the local STO demo on Linux.
# Assumes: docker, docker compose v2, Java 17, Maven 3.9+, curl, git.

set -euo pipefail

WORKDIR="${WORKDIR:-$HOME/sto-demo}"
FABRIC_VERSION="${FABRIC_VERSION:-2.5.5}"
CA_VERSION="${CA_VERSION:-1.5.7}"
CHANNEL="${CHANNEL:-stochannel}"
CC_NAME="${CC_NAME:-securitytoken}"

mkdir -p "$WORKDIR"
cd "$WORKDIR"

if [ ! -d fabric-samples ]; then
  echo "[1/4] Installing Fabric ${FABRIC_VERSION}..."
  curl -sSL https://raw.githubusercontent.com/hyperledger/fabric/main/scripts/install-fabric.sh \
    | bash -s -- --fabric-version "${FABRIC_VERSION}" --ca-version "${CA_VERSION}" docker binary samples
fi

export PATH="$WORKDIR/fabric-samples/bin:$PATH"

echo "[2/4] Building chaincode..."
( cd "$(dirname "$0")/../chaincode/securitytoken" && mvn -q -DskipTests package )

CC_PATH="$(cd "$(dirname "$0")/../chaincode/securitytoken" && pwd)"

echo "[3/4] Bringing up test network..."
cd "$WORKDIR/fabric-samples/test-network"
./network.sh down || true
./network.sh up createChannel -c "${CHANNEL}" -ca

echo "[4/4] Deploying chaincode..."
./network.sh deployCC \
  -c "${CHANNEL}" \
  -ccn "${CC_NAME}" \
  -ccp "${CC_PATH}" \
  -ccl java

echo
echo "Network up. Set these envs for the WildFly backend:"
echo "  export FABRIC_CHANNEL=${CHANNEL}"
echo "  export FABRIC_CHAINCODE=${CC_NAME}"
echo "  export FABRIC_TLS_CERT=$WORKDIR/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt"
echo "  export FABRIC_USER_CERT=$WORKDIR/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp/signcerts/Admin@org1.example.com-cert.pem"
echo "  export FABRIC_USER_KEY_DIR=$WORKDIR/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp/keystore"
