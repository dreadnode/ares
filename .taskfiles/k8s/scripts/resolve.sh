#!/usr/bin/env bash
# Shared kubectl helpers.
#
# Source from a task cmd block, then call the functions:
#     . .taskfiles/k8s/scripts/resolve.sh
#     POD=$(resolve_pod "$NAMESPACE" "app=redis")
#
# The `head -1` selection pattern on `kubectl get pods -l ... -o name` is
# non-deterministic when a rolling update overlaps two pods or a scale-out
# leaves both alive. `resolve_pod` sorts by creationTimestamp so the newest
# pod wins predictably and warns to stderr when more than one matches.

set -o pipefail

# resolve_pod <namespace> <label-selector>
#   Prints the name (with kind prefix, e.g. `pod/redis-abc`) of the newest
#   pod matching <label-selector> in <namespace>. Warns to stderr and lists
#   candidates when more than one exists. Returns non-zero if nothing matches.
resolve_pod() {
	local namespace="$1"
	local selector="$2"
	local candidates picked count
	# --sort-by returns ascending order; `tail -1` picks the newest.
	candidates=$(kubectl get pods -n "$namespace" -l "$selector" \
		--sort-by=.metadata.creationTimestamp \
		-o name 2>/dev/null)
	if [ -z "$candidates" ]; then
		printf '\033[0;31m[ERROR]\033[0m No pod matches selector %q in namespace %q\n' \
			"$selector" "$namespace" >&2
		return 1
	fi
	picked=$(printf '%s\n' "$candidates" | tail -1)
	count=$(printf '%s\n' "$candidates" | wc -l | tr -d ' ')
	if [ "$count" -gt 1 ]; then
		printf '\033[1;33m[WARN]\033[0m %s pods match %q in %q; picking newest (%s). Narrow the selector to pin.\n' \
			"$count" "$selector" "$namespace" "$picked" >&2
		printf '%s\n' "$candidates" | sed 's/^/  /' >&2
	fi
	printf '%s' "$picked"
}
