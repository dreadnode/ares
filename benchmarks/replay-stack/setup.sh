#!/usr/bin/env bash
# Stage a captured snapshot into the replay stack and start it.
#
#   SNAPSHOT_DIR=/path/to/snapshot ./setup.sh
#
# Reproduces argonaut's observability surface for one snapshot: loads the Loki
# chunks, backfills Prometheus metrics (if captured), provisions dashboards, and
# seeds the fired alerts as Grafana annotations. Idempotent — safe to re-run.
set -euo pipefail
STACK_DIR="$(cd "$(dirname "$0")" && pwd)"
SNAP="${SNAPSHOT_DIR:?set SNAPSHOT_DIR to the downloaded snapshot directory}"
DATA="$STACK_DIR/data"
GRAFANA="${GRAFANA_URL:-http://localhost:3000}"

echo "[1/6] staging Loki chunks..."
rm -rf "$DATA/loki"
mkdir -p "$DATA/loki/chunks"
[ -d "$SNAP/loki/fake" ] && cp -r "$SNAP/loki/fake" "$DATA/loki/chunks/fake"
if [ -d "$SNAP/loki/index" ]; then
	mkdir -p "$DATA/loki/chunks/index"
	cp -r "$SNAP/loki/index/." "$DATA/loki/chunks/index/"
fi
# base64-rename raw S3 chunk keys → filesystem-store names (kept from the
# original replay design; runs on this throwaway box, touches only our copy).
if [ -d "$DATA/loki/chunks/fake" ]; then
	find "$DATA/loki/chunks/fake" -type f | while read -r f; do
		d=$(dirname "$f")
		n=$(basename "$f")
		b=$(printf '%s' "$n" | base64 | tr -d '\n')
		if [ "$n" != "$b" ]; then
			mv "$f" "$d/$b" || true
		fi
	done
fi

echo "[2/6] loading Prometheus metrics (if captured)..."
rm -rf "$DATA/prometheus"
mkdir -p "$DATA/prometheus"
if [ -d "$SNAP/prometheus/tsdb" ]; then
	# Pre-built TSDB blocks (created at capture time) — just copy them in,
	# avoiding the multi-minute OpenMetrics→promtool conversion on every replay.
	cp -r "$SNAP/prometheus/tsdb/." "$DATA/prometheus/"
	echo "  (loaded pre-built TSDB blocks)"
elif [ -f "$SNAP/prometheus/metrics.json" ] && [ -f "$STACK_DIR/prom_backfill.py" ]; then
	# Fallback for older snapshots without pre-built blocks: convert at replay.
	python3 "$STACK_DIR/prom_backfill.py" "$SNAP/prometheus/metrics.json" "$DATA/prometheus" ||
		echo "  (metric backfill failed — Prometheus will serve empty)"
else
	echo "  (no captured metrics — Prometheus will serve empty)"
fi

echo "[3/6] staging dashboards..."
rm -rf "$DATA/grafana/dashboards"
mkdir -p "$DATA/grafana/dashboards"
if [ -d "$SNAP/grafana/dashboards" ]; then
	for f in "$SNAP/grafana/dashboards"/*.json; do
		[ -e "$f" ] || continue
		jq '.dashboard // .' "$f" >"$DATA/grafana/dashboards/$(basename "$f")" 2>/dev/null || cp "$f" "$DATA/grafana/dashboards/"
	done
fi
mkdir -p "$DATA/mimir"

echo "[4/6] starting stack..."
(cd "$STACK_DIR" && docker compose up -d)
# The loki/prometheus bind mounts were just repopulated under any already-running
# containers; force them to re-read the staged data (`up -d` no-ops if the
# container already exists).
(cd "$STACK_DIR" && docker compose restart loki prometheus)

echo "[5/6] waiting for Grafana + Loki readiness..."
for _ in $(seq 1 60); do
	curl -sf "$GRAFANA/api/health" >/dev/null 2>&1 && break
	sleep 2
done
for _ in $(seq 1 60); do
	curl -sf "http://localhost:3100/ready" >/dev/null 2>&1 && break
	sleep 2
done

# Note: fired-alerts.json is the deterministic seeding source. The capture also
# writes grafana/annotations.json (the full unfiltered annotation set), but it is
# intentionally NOT re-seeded here — POST /api/annotations can't reproduce the
# original alertId/panelId, and re-posting would duplicate these firings. Wire it
# in here only if a future blue tool needs non-firing annotations in replay.
echo "[6/6] seeding fired alerts as Grafana annotations..."
if [ -f "$SNAP/fired-alerts.json" ]; then
	n=0
	while read -r a; do
		[ -z "$a" ] && continue
		ts=$(printf '%s' "$a" | jq -r '.fired_at')
		# GNU `date -d` (this runs on the Linux replay box). If the timestamp can't
		# be parsed, skip the firing rather than silently seeding it at epoch 0
		# (which would place it outside the replay window and hide it from the agent).
		if ! secs=$(date -u -d "$ts" +%s 2>/dev/null); then
			echo "  warning: unparsable fired_at='$ts' (need GNU date) — skipping firing" >&2
			continue
		fi
		tms=$((secs * 1000))
		# text = full alert name; keep the original labels/annotations in `data`
		# (Grafana truncates whitespace in tags, so don't encode the name as a tag).
		body=$(printf '%s' "$a" | jq -c --argjson time "$tms" \
			'{text: (.alert_name // "alert"), time: $time, tags: ["ares-replay-firing"],
        data: {labels: (.labels // {}), annotations: (.annotations // {})}}')
		if curl -sf -X POST "$GRAFANA/api/annotations" -H 'Content-Type: application/json' -d "$body" >/dev/null 2>&1; then
			n=$((n + 1))
		fi
	done < <(jq -c '.[]' "$SNAP/fired-alerts.json")
	echo "  seeded $n firings"
fi

echo "ready. grafana=$GRAFANA loki=:3100 prometheus=:9090 tempo=:3200"
