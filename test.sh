#!/usr/bin/env bash
set -euo pipefail

# zig 0.16's linker chokes on absurdly high FD limits (e.g. 1048576 from a
# tuned shell) when the kernel's per-process cap is much lower. Clamp to a
# concrete value that zig is happy with — task's internal shell (mvdan/sh)
# doesn't implement `ulimit` so we have to set this here, in real bash.
ulimit -n 65536 || ulimit -n 10240 || true

EC2_NAME="${EC2_NAME:-kali-ares}"
TARGET="${TARGET:-dreadgoad}"
BLUE_ENABLED="${BLUE_ENABLED:-1}"
export S3_BUCKET=dread-infra-alpha-operator-range-staging-us-west-1

echo "=== Stopping workers + any running operation ==="
task ec2:stop EC2_NAME="${EC2_NAME}" 2>/dev/null || true
task ec2:stop-op EC2_NAME="${EC2_NAME}" LATEST=true 2>/dev/null || true

echo ""
echo "=== Deploying binaries to ${EC2_NAME} ==="
task -y ec2:deploy EC2_NAME="${EC2_NAME}"

echo ""
echo "=== Wiping Redis ==="
task ec2:exec EC2_NAME="${EC2_NAME}" CMD="redis-cli FLUSHALL"

echo ""
echo "=== Starting workers on fresh Redis with new binary ==="
task ec2:start EC2_NAME="${EC2_NAME}"

echo ""
echo "=== Launching operation against ${TARGET} (blue=${BLUE_ENABLED}) ==="
task -y red:ec2:multi TARGET="${TARGET}" EC2_NAME="${EC2_NAME}" BLUE_ENABLED="${BLUE_ENABLED}"
