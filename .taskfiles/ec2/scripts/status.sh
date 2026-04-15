#!/bin/bash
# Show ares process status on EC2

echo "=== Redis ==="
redis-cli ping 2> /dev/null && redis-cli info server 2> /dev/null | grep -E "redis_version|uptime_in_seconds|connected_clients" || echo "Redis not running"
echo ""

echo "=== Workers ==="
for role in recon credential_access cracker acl privesc lateral coercion; do
    st=$(systemctl is-active ares-worker@${role} 2> /dev/null || echo dead)
    pid=""
    if [ "$st" = "active" ]; then
        pid=$(systemctl show ares-worker@${role} --property=MainPID --value 2> /dev/null || echo "?")
    fi
    printf "  %-20s %-8s %s\n" "$role" "$st" "${pid:+PID: $pid}"
done
echo ""

echo "=== Orchestrator ==="
ORCH_PID=$(pgrep -f ares-orchestrator 2> /dev/null || true)
if [ -n "$ORCH_PID" ]; then
    echo "  Running (PID: $ORCH_PID)"
    ps -p "$ORCH_PID" -o etime=,args= 2> /dev/null | head -1
else
    echo "  Not running"
fi
echo ""

echo "=== Disk ==="
df -h / | tail -1
echo ""

echo "=== Logs ==="
ls -lhS /var/log/ares/ 2> /dev/null || echo "  No log directory"
