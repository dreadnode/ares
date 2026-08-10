#!/bin/bash
# Report hashcat activity on the box.
#
# ares@cracker.service spawns hashcat with `--session ares-hc-<pid>-<seq>`.
# Surface running jobs so operators can see whether a red op is stalled on a
# grind. Invoked standalone by `task ec2:hashcat` and also sourced by
# `.taskfiles/ec2/scripts/status.sh` so it appears in `task ec2:status`.

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
