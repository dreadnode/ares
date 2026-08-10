#!/bin/bash
# Runtime readiness check for an ares EC2 instance.
#
# Provisioning (Redis, NATS, the ares@ worker fleet, system-ares.slice, swap,
# and OOM sysctls) is baked into the attack-box AMI by the Ansible collection
# in ansible/ (playbooks/ares/goad_attack_box.yml -> base/redis/nats roles).
# This script does NOT re-install any of that; to (re)provision, re-bake the
# AMI or run the playbook over SSM. It only:
#   1. Guards against impacket pip drift (a runtime-only concern, see below).
#   2. Ensures the already-installed services are up (anti-wedge safety net).
#   3. Smoke-tests Redis + NATS.
set -euo pipefail

WORKER_ROLES=(recon credential_access cracker acl privesc lateral coercion)

echo "=== Guarding against impacket pip drift ==="
# The tool roles install impacket from GitHub *source*, editable, so it ships
# the impacket.examples.regsecrets module NetExec needs (NetExec#685). An
# editable install leaves only a .pth pointer in dist-packages. A full
# `impacket/` directory there is a *released* (non-editable) install that
# shadows the source one and drops regsecrets. If some tool's dep pulled one
# in post-bake, remove it so the source install wins again.
if [ -d /usr/local/lib/python3.13/dist-packages/impacket ]; then
	pip3 uninstall -y impacket --break-system-packages 2>/dev/null || true
	rm -rf /usr/local/lib/python3.13/dist-packages/impacket \
		/usr/local/lib/python3.13/dist-packages/impacket-*.dist-info
	echo "Removed released impacket shadow — source (regsecrets) install wins"
fi

echo "=== Ensuring baked services are running ==="
# Idempotent: units already exist + are enabled on the baked AMI. If a unit is
# missing the instance was not provisioned from the attack-box AMI — say so
# loudly instead of silently leaving the fleet down (which wedges ops at zero
# progress with "no responders" while still burning tokens).
ensure_up() {
	local unit="$1"
	if systemctl list-unit-files "$unit" >/dev/null 2>&1 &&
		systemctl cat "$unit" >/dev/null 2>&1; then
		systemctl enable --now "$unit" 2>/dev/null || systemctl start "$unit" || true
	else
		echo "WARNING: $unit not installed — instance not provisioned from the attack-box AMI"
	fi
}

systemctl start redis-server 2>/dev/null || systemctl start redis 2>/dev/null || true
ensure_up nats-server.service
for role in "${WORKER_ROLES[@]}"; do
	ensure_up "ares@${role}.service"
done

echo "=== Smoke test ==="
redis-cli ping 2>/dev/null || echo "Redis not responding"
curl -fsS http://127.0.0.1:8222/varz >/dev/null 2>&1 && echo "NATS responding" || echo "NATS not responding"
for role in "${WORKER_ROLES[@]}"; do
	state="$(systemctl is-active "ares@${role}.service" 2>/dev/null || true)"
	echo "ares@${role}: ${state:-unknown}"
done

echo "=== Setup complete ==="
