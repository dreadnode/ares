#!/usr/bin/env bash
# List all ares operation IDs from Redis with started_at + derived status.
#
# Status derivation mirrors ares-cli/src/ops/list.rs:
#   - ares:lock:<op> present    -> running
#   - meta.completed_at present -> completed
#   - otherwise                 -> stopped (crashed / killed / never finalized)
#
# Sorted chronologically by started_at, columns separated by " | ".

set -o pipefail

# kali-ares does not ship util-linux `column`; pad with awk instead.
# Widths: started_at RFC3339 fits ≤27 chars; status ≤9; op_id is last so no cap.
{
	printf 'STARTED_AT\tSTATUS\tOP_ID\n'
	redis-cli --scan --pattern 'ares:op:*:meta' |
		sed -E 's|ares:op:(.*):meta|\1|' |
		while read -r op; do
			# meta values are JSON-encoded (e.g. `"2026-..."`); strip the surrounding quotes.
			started=$(redis-cli hget "ares:op:$op:meta" started_at | sed -E 's/^"(.*)"$/\1/')
			completed=$(redis-cli hget "ares:op:$op:meta" completed_at | sed -E 's/^"(.*)"$/\1/')
			if [ "$(redis-cli exists "ares:lock:$op")" = '1' ]; then
				status=running
			elif [ -n "$completed" ]; then
				status=completed
			else
				status=stopped
			fi
			printf '%s\t%s\t%s\n' "${started:-?}" "$status" "$op"
		done |
		sort -r
} | awk -F'\t' '{ printf "%-28s | %-9s | %s\n", $1, $2, $3 }'
