#!/usr/bin/env bash
set -euo pipefail

EC2_NAME="${EC2_NAME:-kali-ares}"
TARGET="${TARGET:-dreadgoad}"
BLUE_ENABLED="${BLUE_ENABLED:-1}"

echo "=== Deploying binaries to ${EC2_NAME} ==="
task -y ec2:deploy EC2_NAME="${EC2_NAME}"

echo ""
echo "=== Stopping any running operation ==="
task ec2:stop-op EC2_NAME="${EC2_NAME}" LATEST=true 2>/dev/null || true

echo ""
echo "=== Wiping Redis ==="
task ec2:exec EC2_NAME="${EC2_NAME}" CMD="redis-cli FLUSHALL"

echo ""
echo "=== Launching operation against ${TARGET} (blue=${BLUE_ENABLED}) ==="
task -y red:ec2:multi TARGET="${TARGET}" EC2_NAME="${EC2_NAME}" BLUE_ENABLED="${BLUE_ENABLED}"
