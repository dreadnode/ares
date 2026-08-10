#!/usr/bin/env bash
# preflight.sh — demo-morning green-light gate.
#
# Runs 15 minutes before the Black Hat live demo. Every check must pass
# green before the script exits 0 — that's the operator's cue to run the
# actual `ares benchmark run` in front of the audience. Any failure exits
# non-zero with the exact fix printed on stdout so there's no
# "what does this mean" moment while a room is watching.
#
# See docs/DEMO-PLAN.md § Pre-flight probe for the check inventory this
# script implements.
#
# Usage:
#   demo/preflight.sh                          # canonical demo defaults
#   HERO_OP=op-20260705-101128 demo/preflight.sh
#   demo/preflight.sh --namespace replay --hero-op op-...

set -euo pipefail

# ---------- config ----------------------------------------------------------

NAMESPACE="${NAMESPACE:-replay}"
GRAFANA_URL="${GRAFANA_URL:-http://127.0.0.1:3000}"
LOKI_URL="${LOKI_URL:-http://127.0.0.1:3100}"
TEMPO_URL="${TEMPO_URL:-http://127.0.0.1:3200}"
# The captured op the demo replays against. Must exist in Loki + Tempo when
# preflight runs; the visual-replay path is deterministic against this ID.
HERO_OP="${HERO_OP:-}"
# Minimum alert rules the demo dashboard depends on. Anything less means a
# ConfigMap didn't reconcile.
MIN_ALERT_RULES="${MIN_ALERT_RULES:-4}"
# Timeout for individual health probes (seconds). Longer than a
# well-provisioned stack needs; shorter than "the operator gives up".
PROBE_TIMEOUT="${PROBE_TIMEOUT:-5}"

# ---------- CLI parsing -----------------------------------------------------

while [[ $# -gt 0 ]]; do
	case "$1" in
	--namespace)
		NAMESPACE="$2"
		shift 2
		;;
	--hero-op)
		HERO_OP="$2"
		shift 2
		;;
	--grafana-url)
		GRAFANA_URL="$2"
		shift 2
		;;
	--loki-url)
		LOKI_URL="$2"
		shift 2
		;;
	--tempo-url)
		TEMPO_URL="$2"
		shift 2
		;;
	--min-alert-rules)
		MIN_ALERT_RULES="$2"
		shift 2
		;;
	-h | --help)
		cat <<'HELP'
preflight.sh — demo-morning green-light gate.

Runs 15 minutes before the demo. Every check must pass green before the
script exits 0. On failure, prints the exact fix so there is no ambiguity
in front of an audience.

Usage:
  demo/preflight.sh                                        # canonical defaults
  HERO_OP=op-20260705-101128 demo/preflight.sh
  demo/preflight.sh --namespace replay --hero-op op-...

Flags:
  --namespace <ns>          K8s namespace for orchestrator pod
                            (default: replay, env: NAMESPACE)
  --hero-op <op-id>         Captured op the demo replays against
                            (required; env: HERO_OP)
  --grafana-url <url>       Grafana base URL       (env: GRAFANA_URL)
  --loki-url <url>          Loki base URL          (env: LOKI_URL)
  --tempo-url <url>         Tempo base URL         (env: TEMPO_URL)
  --min-alert-rules <n>     Minimum rules loaded   (env: MIN_ALERT_RULES)
  -h, --help                Show this and exit 0
HELP
		exit 0
		;;
	*)
		echo "unknown flag: $1 (see --help)" >&2
		exit 2
		;;
	esac
done

if [[ -z "$HERO_OP" ]]; then
	echo "HERO_OP is required — set env var or pass --hero-op op-YYYYMMDD-HHMMSS" >&2
	echo "  fix: HERO_OP=op-20260705-101128 demo/preflight.sh" >&2
	exit 2
fi

# ---------- pretty output ---------------------------------------------------

PASS_MARK="ok"
FAIL_MARK="FAIL"
if [[ -t 1 ]]; then
	PASS_MARK=$'\033[32mok\033[0m'
	FAIL_MARK=$'\033[31mFAIL\033[0m'
fi

FAILURES=0
declare -a FIXES=()

pass() {
	printf "  [%s] %s\n" "$PASS_MARK" "$1"
}

fail() {
	printf "  [%s] %s\n" "$FAIL_MARK" "$1"
	FIXES+=("  * $2")
	FAILURES=$((FAILURES + 1))
}

section() {
	printf "\n[%s] %s\n" "$1" "$2"
}

# ---------- tool preflight --------------------------------------------------

need_bin() {
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "missing required tool: $1" >&2
		echo "  fix: install $1 and re-run preflight" >&2
		exit 2
	fi
}
need_bin curl
need_bin jq
need_bin kubectl

# ---------- 1. Kubernetes reachable -----------------------------------------

section 1/7 "Kubernetes"

if kubectl version --client=false --request-timeout="${PROBE_TIMEOUT}s" >/dev/null 2>&1; then
	pass "cluster reachable"
else
	fail "cluster unreachable" \
		"kubectl config current-context   # confirm the right cluster is selected"
fi

if kubectl get ns "$NAMESPACE" >/dev/null 2>&1; then
	pass "namespace '$NAMESPACE' present"
else
	fail "namespace '$NAMESPACE' missing" \
		"kubectl create namespace $NAMESPACE   # or --namespace <existing>"
fi

# ---------- 2. Grafana health -----------------------------------------------

section 2/7 "Grafana"

grafana_health="$(curl -fsS --max-time "$PROBE_TIMEOUT" "$GRAFANA_URL/api/health" 2>/dev/null || true)"
if echo "$grafana_health" | jq -e '.database == "ok"' >/dev/null 2>&1; then
	pass "$GRAFANA_URL /api/health database=ok"
else
	fail "Grafana /api/health did not return database=ok" \
		"curl -v $GRAFANA_URL/api/health   # is grafana up? correct URL?"
fi

# ---------- 3. Loki has streams for HERO_OP ---------------------------------

section 3/7 "Loki"

# `count_over_time({op="<hero>"}[1h])` returns > 0 if the snapshot ingest
# actually loaded the op's logs. Use a wide 24h window so a snapshot loaded
# yesterday still counts.
loki_query='count_over_time({op="'"$HERO_OP"'"}[24h])'
loki_resp="$(curl -fsS --max-time "$PROBE_TIMEOUT" --get \
	--data-urlencode "query=$loki_query" \
	"$LOKI_URL/loki/api/v1/query" 2>/dev/null || true)"
loki_value="$(echo "$loki_resp" |
	jq -r '.data.result[0].value[1] // "0"' 2>/dev/null || echo "0")"
if [[ "$loki_value" != "0" && "$loki_value" != "null" && -n "$loki_value" ]]; then
	pass "Loki has logs for op=$HERO_OP (samples: $loki_value)"
else
	fail "Loki returned zero samples for op=$HERO_OP" \
		"ares benchmark load ~/demo/snapshots/$HERO_OP   # (re)load the snapshot"
fi

# ---------- 4. Tempo has traces for HERO_OP ---------------------------------

section 4/7 "Tempo"

tempo_search="$(curl -fsS --max-time "$PROBE_TIMEOUT" --get \
	--data-urlencode "q={ .attack_operation_id = \"$HERO_OP\" }" \
	--data-urlencode "limit=1" \
	"$TEMPO_URL/api/search" 2>/dev/null || true)"
tempo_count="$(echo "$tempo_search" |
	jq -r '.traces | length' 2>/dev/null || echo "0")"
if [[ "$tempo_count" =~ ^[0-9]+$ && "$tempo_count" -gt 0 ]]; then
	pass "Tempo has at least one trace for op=$HERO_OP"
else
	fail "Tempo has zero traces for op=$HERO_OP" \
		"ares benchmark run --snapshot $HERO_OP --push-traces-only   # replay tempo bundle"
fi

# ---------- 5. Blue orchestrator pod ready ----------------------------------

section 5/7 "Blue orchestrator"

# Pod name pattern varies by deployment (orchestrator vs orchestrator-0); take
# the first pod carrying the ares-orchestrator label. The pod must be Ready.
orch_ready="$(kubectl -n "$NAMESPACE" get pods -l app=ares-orchestrator \
	-o jsonpath='{.items[0].status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)"
if [[ "$orch_ready" == "True" ]]; then
	pass "orchestrator pod Ready"
else
	fail "orchestrator pod not Ready (got: '${orch_ready:-<no-pod>}')" \
		"kubectl -n $NAMESPACE rollout status deploy/ares-orchestrator --timeout=90s"
fi

# ---------- 6. Alert rules loaded -------------------------------------------

section 6/7 "Grafana alert rules"

alert_rules="$(curl -fsS --max-time "$PROBE_TIMEOUT" \
	"$GRAFANA_URL/api/prometheus/grafana/api/v1/rules" 2>/dev/null || true)"
alert_count="$(echo "$alert_rules" |
	jq -r '[.data.groups[]?.rules[]?] | length' 2>/dev/null || echo "0")"
alert_count="${alert_count:-0}"
if [[ "$alert_count" =~ ^[0-9]+$ && "$alert_count" -ge "$MIN_ALERT_RULES" ]]; then
	pass "loaded $alert_count alert rules (>= $MIN_ALERT_RULES required)"
else
	fail "loaded only $alert_count alert rules (need >= $MIN_ALERT_RULES)" \
		"kubectl -n $NAMESPACE rollout restart deploy/grafana   # reconcile the ConfigMap"
fi

# ---------- 7. Replay clock paused ------------------------------------------

section 7/7 "Replay clock"

# Convention (see ares-core/src/replay_clock.rs): ARES_REPLAY_CLOCK_MODE is
# set to "paused" between rehearsals so the wallclock advance does not start
# on pod boot. If unset, the pod isn't running the replay build.
clock_mode="$(kubectl -n "$NAMESPACE" get deploy ares-orchestrator \
	-o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="ARES_REPLAY_CLOCK_MODE")].value}' 2>/dev/null || true)"
if [[ "$clock_mode" == "paused" ]]; then
	pass "orchestrator env ARES_REPLAY_CLOCK_MODE=paused"
else
	fail "ARES_REPLAY_CLOCK_MODE is '${clock_mode:-<unset>}' (expected 'paused')" \
		"kubectl -n $NAMESPACE set env deploy/ares-orchestrator ARES_REPLAY_CLOCK_MODE=paused"
fi

# ---------- summary ---------------------------------------------------------

echo
if ((FAILURES == 0)); then
	echo "preflight passed — green light for demo"
	exit 0
fi

echo "preflight FAILED — $FAILURES check(s) blocking demo start:"
for fix in "${FIXES[@]}"; do
	printf "%s\n" "$fix"
done
exit 1
