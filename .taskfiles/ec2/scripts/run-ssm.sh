#!/usr/bin/env bash
# Shared SSM helpers for .taskfiles/ec2/Taskfile.yaml.
#
# Source from a task cmd block, then call the functions:
#     . .taskfiles/ec2/scripts/run-ssm.sh
#     INSTANCE_ID=$(resolve_instance_id "$EC2_NAME")
#     run_ssm_cmd "$INSTANCE_ID" "redis-cli ping" 30
#
# Required in the caller's environment: AWS_REGION, plus either AWS_PROFILE
# or exported session credentials (AWS_ACCESS_KEY_ID/…).
#
# run_ssm_cmd contract:
#   - On success: writes StandardOutputContent to stdout, returns 0.
#   - On failure: prints an [ERROR] banner (with a PingStatus ConnectionLost
#     recovery hint when StatusDetails == Undeliverable), echoes any captured
#     stdout and StandardErrorContent to stderr, returns 1.
#   - Uses --timeout-seconds equal to the poll budget so SSM does not outlive
#     the local loop.

set -o pipefail

# If temporary env credentials are already exported (assume, aws-vault, instance
# metadata), skip --profile so the AWS CLI uses them. Otherwise fall back to
# --profile "$AWS_PROFILE" and let the CLI resolve the named profile from
# ~/.aws/config. Use a bash array so the flag can expand to zero args cleanly
# without shellcheck word-splitting warnings.
if [ -n "${AWS_ACCESS_KEY_ID:-}" ]; then
	AWS_PROFILE_ARG=()
else
	AWS_PROFILE_ARG=(--profile "${AWS_PROFILE:-lab}")
fi

# _resolve_ec2 <name-tag-glob>
#   Prints the newest matching "<LaunchTime>\t<InstanceId>\t<PrivateIpAddress>"
#   row on stdout. Sort is LaunchTime desc, InstanceId tiebreaker, so repeated
#   calls always return the same box. On multi-match, warns to stderr so the
#   ambiguity is surfaced instead of silently swallowed by `head -1`.
#   Returns non-zero if nothing matches. Internal helper for resolve_instance_id
#   / resolve_instance_ip.
_resolve_ec2() {
	local name="$1"
	local candidates picked count _launch picked_id picked_ip
	candidates=$(aws ec2 describe-instances \
		"${AWS_PROFILE_ARG[@]}" \
		--region "$AWS_REGION" \
		--filters "Name=instance-state-name,Values=running" \
		"Name=tag:Name,Values=*${name}*" \
		--query "Reservations[*].Instances[*].[LaunchTime,InstanceId,PrivateIpAddress]" \
		--output text | awk 'NF==3' | sort -k1,1r -k2,2)
	if [ -z "$candidates" ]; then
		printf '\033[0;31m[ERROR]\033[0m No running instance found matching: %s\n' "$name" >&2
		return 1
	fi
	picked=$(printf '%s\n' "$candidates" | head -1)
	count=$(printf '%s\n' "$candidates" | wc -l | tr -d ' ')
	if [ "$count" -gt 1 ]; then
		read -r _launch picked_id picked_ip <<<"$picked"
		printf '\033[1;33m[WARN]\033[0m %s instances match "*%s*"; picking newest (%s / %s). Set EC2_INSTANCE_ID or use a more specific name to pin.\n' \
			"$count" "$name" "$picked_id" "$picked_ip" >&2
		printf '%s\n' "$candidates" | awk '{printf "  %s  %s  %s\n", $2, $3, $1}' >&2
	fi
	printf '%s' "$picked"
}

# resolve_instance_id <name-tag-glob>
#   Prints a single running InstanceId whose Name tag matches *<name>*.
#   Set EC2_INSTANCE_ID to bypass the tag lookup entirely.
#   Returns non-zero if nothing matches.
resolve_instance_id() {
	if [ -n "${EC2_INSTANCE_ID:-}" ]; then
		printf '%s' "$EC2_INSTANCE_ID"
		return 0
	fi
	local row
	row=$(_resolve_ec2 "$1") || return 1
	awk '{printf "%s", $2}' <<<"$row"
}

# resolve_instance_ip <name-tag-glob>
#   Prints the PrivateIpAddress of a single running instance whose Name tag
#   matches *<name>*. Same determinism/WARN semantics as resolve_instance_id.
#   Returns non-zero if nothing matches.
resolve_instance_ip() {
	local row
	row=$(_resolve_ec2 "$1") || return 1
	awk '{printf "%s", $3}' <<<"$row"
}

# resolve_targets <name-tag-glob>
#   Prints a comma-separated list of private IPs for running instances whose
#   Name tag matches *<name>* — e.g. `resolve_targets dreadgoad` returns the
#   dreadgoad DCs/SRVs but naturally excludes `kali-ares`. Returns non-zero
#   if nothing matches.
resolve_targets() {
	local name="$1"
	local ips
	ips=$(aws ec2 describe-instances \
		"${AWS_PROFILE_ARG[@]}" \
		--region "$AWS_REGION" \
		--filters "Name=instance-state-name,Values=running" \
		"Name=tag:Name,Values=*${name}*" \
		--query "Reservations[*].Instances[*].PrivateIpAddress" \
		--output text | tr '[:space:]' '\n' | grep -v '^$' | sort -V | paste -sd, -)
	if [ -z "$ips" ]; then
		printf '\033[0;31m[ERROR]\033[0m No running instances found for range: %s\n' "$name" >&2
		return 1
	fi
	printf '%s' "$ips"
}

# run_ssm_cmd <instance_id> <payload> [timeout_seconds]
#   Ships <payload> to <instance_id> via AWS-RunShellScript, polls once/sec
#   until the command reaches a terminal state or <timeout_seconds> (default
#   120) elapses. Prints StandardOutputContent on success; on failure prints
#   a banner + captured output/stderr to fd 2 and returns 1.
run_ssm_cmd() {
	local instance_id="$1"
	local payload="$2"
	local timeout="${3:-120}"
	local params_file cmd_id status output details

	params_file=$(mktemp)
	jq -n --arg cmd "$payload" '{"commands": [$cmd]}' >"$params_file"

	cmd_id=$(aws ssm send-command \
		"${AWS_PROFILE_ARG[@]}" \
		--region "$AWS_REGION" \
		--instance-ids "$instance_id" \
		--document-name "AWS-RunShellScript" \
		--parameters "file://$params_file" \
		--timeout-seconds "$timeout" \
		--query "Command.CommandId" --output text)

	rm -f "$params_file"

	status=""
	for _ in $(seq 1 "$timeout"); do
		status=$(aws ssm get-command-invocation \
			"${AWS_PROFILE_ARG[@]}" \
			--region "$AWS_REGION" \
			--command-id "$cmd_id" \
			--instance-id "$instance_id" \
			--query "Status" --output text 2>/dev/null) || true
		case "$status" in
		Success | Failed | Cancelled | TimedOut) break ;;
		esac
		sleep 1
	done

	output=$(aws ssm get-command-invocation \
		"${AWS_PROFILE_ARG[@]}" \
		--region "$AWS_REGION" \
		--command-id "$cmd_id" \
		--instance-id "$instance_id" \
		--query "StandardOutputContent" --output text)

	if [ "$status" != "Success" ]; then
		details=$(aws ssm get-command-invocation \
			"${AWS_PROFILE_ARG[@]}" \
			--region "$AWS_REGION" \
			--command-id "$cmd_id" \
			--instance-id "$instance_id" \
			--query "StatusDetails" --output text 2>/dev/null)
		case "$status" in
		Failed | Cancelled | TimedOut)
			printf '\033[0;31m[ERROR]\033[0m SSM command failed (status: %s, details: %s)\n' "$status" "$details" >&2
			;;
		*)
			printf '\033[0;31m[ERROR]\033[0m Gave up polling after %ss — SSM command %s is still %s on %s. The payload is STILL RUNNING; this is a local poll-budget expiry, not a command failure.\n' \
				"$timeout" "$cmd_id" "$status" "$instance_id" >&2
			printf '\033[0;31m[ERROR]\033[0m Recovery: raise the run_ssm_cmd timeout for this call site, or follow the command with: aws ssm get-command-invocation --region %s --command-id %s --instance-id %s\n' \
				"$AWS_REGION" "$cmd_id" "$instance_id" >&2
			;;
		esac
		if [ "$details" = "Undeliverable" ]; then
			printf '\033[0;31m[ERROR]\033[0m SSM could not deliver the command to %s (PingStatus likely ConnectionLost).\n' "$instance_id" >&2
			printf '\033[0;31m[ERROR]\033[0m Recovery: reboot the instance ('\''aws ec2 reboot-instances --instance-ids %s'\'').\n' "$instance_id" >&2
		fi
		if [ -n "$output" ]; then
			printf '%s\n' "$output" >&2
		fi
		aws ssm get-command-invocation \
			"${AWS_PROFILE_ARG[@]}" \
			--region "$AWS_REGION" \
			--command-id "$cmd_id" \
			--instance-id "$instance_id" \
			--query "StandardErrorContent" --output text >&2
		return 1
	fi

	printf '%s' "$output"
}
