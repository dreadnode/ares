#!/bin/bash
# Show ares process status on EC2

echo "=== Redis ==="
redis-cli ping 2>/dev/null && redis-cli info server 2>/dev/null | grep -E "redis_version|uptime_in_seconds|connected_clients" || echo "Redis not running"
echo ""

echo "=== NATS ==="
if curl -fsS http://127.0.0.1:8222/varz 2>/dev/null | grep -E '"version"|"now"|"connections"' | head -3; then
	curl -fsS http://127.0.0.1:8222/jsz 2>/dev/null | grep -E '"streams"|"messages"|"bytes"' | head -3 || true
else
	echo "NATS not running"
fi
echo ""

echo "=== Dispatch mode ==="
if [ "$(printf '%s' "${ARES_TOOL_DISPATCH:-}")" = "local" ]; then
	echo "  in-process (ARES_TOOL_DISPATCH=local) — no separate worker fleet"
else
	echo "  NATS worker fleet (ARES_TOOL_DISPATCH unset) — tools route to ares@<role>.service"
	for role in recon credential_access cracker acl privesc lateral coercion; do
		printf '  ares@%-18s %s\n' "$role" "$(systemctl is-active "ares@${role}.service" 2>/dev/null || echo unknown)"
	done
fi
echo ""

echo "=== Orchestrator ==="
ORCH_PID=$(pgrep -f 'ares orchestrator' 2>/dev/null || true)
if [ -n "$ORCH_PID" ]; then
	echo "  Running (PID: $ORCH_PID)"
	ps -p "$ORCH_PID" -o etime=,args= 2>/dev/null | head -1
else
	echo "  Not running"
fi
echo ""

# Duplicated in `.taskfiles/ec2/scripts/hashcat-status.sh` (used by `task
# ec2:hashcat`). Both scripts are uploaded to SSM as inline text so they can't
# source each other — keep the two in sync when editing.
echo "=== Hashcat ==="
HC_PIDS=$(pgrep -x hashcat 2>/dev/null || true)
if [ -n "$HC_PIDS" ]; then
	HC_COUNT=$(echo "$HC_PIDS" | wc -l | tr -d ' ')
	echo "  Running: $HC_COUNT job(s)"
	for pid in $HC_PIDS; do
		LINE=$(ps -p "$pid" -o etime=,args= 2>/dev/null | head -1 | sed 's/^ *//')
		[ -z "$LINE" ] && continue
		ETIME=$(echo "$LINE" | awk '{print $1}')
		ARGS=$(echo "$LINE" | cut -d' ' -f2-)
		MODE=$(echo "$ARGS" | grep -oE -- '-m *[0-9]+' | head -1 | tr -d ' ' | sed 's/^-m//')
		SESSION=$(echo "$ARGS" | grep -oE -- '--session[ =][^ ]+' | head -1 | sed 's/^--session[ =]//')
		printf '    PID=%s etime=%s mode=%s session=%s\n' \
			"$pid" "$ETIME" "${MODE:-?}" "${SESSION:-?}"
	done
	CRACKER_STATE=$(systemctl is-active ares@cracker.service 2>/dev/null || echo unknown)
	echo "  ares@cracker: $CRACKER_STATE"
else
	echo "  idle (no hashcat processes)"
	CRACKER_STATE=$(systemctl is-active ares@cracker.service 2>/dev/null || echo unknown)
	echo "  ares@cracker: $CRACKER_STATE"
fi
echo ""

echo "=== Disk ==="
df -h / | tail -1
echo ""

echo "=== Logs ==="
ls -lhS /var/log/ares/ 2>/dev/null || echo "  No log directory"
