#!/usr/bin/env bash
# e2e-op.sh — end-to-end launch of a fresh red(+blue)-team op on an EC2 box.
#
# Driven by `task ec2:e2e`; runnable directly for one-off tweaks.
#
# Flow:
#   1. Sanity-check repo root + task binary + S3_BUCKET env var.
#   2. Ensure a host-native ares CLI exists. ec2:kill, ec2:watch and
#      ec2:report run the CLI locally and proxy to the box over SSM
#      (`ares --ec2 ...`), so they need a binary for THIS host — a
#      different artifact from the Linux one ec2:deploy ships. Only
#      ec2:watch declares a precondition for it; ec2:kill dies with a
#      bare exit 127, skipping the stale-op cleanup, and ec2:watch aborts
#      after the op has already launched, so a successful launch exits
#      non-zero and reads like a failed one.
#   3. Build & deploy the current ares binary to the EC2 box.
#   4. Restart the workers (drops the in-memory ENOENT tool cache; deploy
#      alone leaves the pre-fix binary running with poisoned state).
#   5. Verify tool binaries actually resolve on the box.
#   6. Kill any operations still running on the box so the new op starts
#      from a clean slate (stop + delete every running op).
#   7. Launch a fresh red-team operation and wait for terminal state.
#   8. Grep the op log for the tool-pruning-cascade signature so a
#      regression of the spawn-poison bug is caught in the same run.
#   9. Fetch the final red report locally.
#  10. If BLUE=1, surface the blue team's investigation status, fetch the
#      consolidated blue report locally, and count the simulated-response
#      containment signals (the "blue acted, red adapted" beat) from the
#      fresh-per-op orchestrator log.
#
# Usage:
#   task ec2:e2e                                 # defaults: TARGET=dreadgoad EC2_NAME=kali-ares
#   task ec2:e2e TARGET=... EC2_NAME=...
#   .taskfiles/ec2/scripts/e2e-op.sh <target>    # positional TARGET when run directly
#
# Knobs (task vars when invoked via `task ec2:e2e`, env vars when run directly).
# Booleans accept 1/true/yes/on:
#   EC2_NAME      Name tag of the target EC2 host (default: kali-ares)
#   AWS_REGION    Region the EC2_NAME tag is resolved in (default: us-west-1).
#                 kali-ares exists in more than one region and only the
#                 us-west-1 box has working blue (Loki/Grafana). Getting this
#                 wrong silently targets a different host.
#   GATE_STRING   Optional literal expected to appear in the freshly built
#                 binary (e.g. a log message added by the change under test).
#                 Asserted against the DEPLOYED binary after step 1. Use it
#                 when the SHA gate alone can't prove your edit shipped.
#   TARGET        Range name or comma-separated IP list (default: dreadgoad)
#   SKIP_DEPLOY   Skip build+deploy (reuse the on-box binary)
#   SKIP_RESTART  Reuse the current workers (risks poisoned cache). go-task
#                 reads the environment as template vars, so this reaches
#                 ec2:deploy's own SKIP_RESTART too and suppresses the
#                 ares@*.service restart that drops the unavailable-tool cache.
#   SKIP_KILL     Leave already-running ops alone (default: kill them)
#   CRED_USER     Assumed-breach seed. Empty (default) = blind start: the op
#   CRED_PASS     gets no initial credential and has to find its own way in.
#   CRED_DOMAIN   Set USER+PASS together to seed one; DOMAIN if unset.
#   DOMAIN        target_domain for the op (empty = ec2:launch's own default)
#   ALLOW_STALE   Build+deploy from a checkout that is behind its upstream.
#                 Default refuses: the step-2b SHA gate proves the binary was
#                 built by this run, NOT that the source was current, so a
#                 fresh build of a stale tree passes every gate and ships code
#                 predating your merges. That is how a third stale binary
#                 shipped on 2026-08-01.
#   BLUE          1 = run blue alongside red + surface its output (default 1).
#                 0 is REFUSED — ec2:launch ignores BLUE_ENABLED and hardcodes
#                 ARES_BLUE_ENABLED=1, so BLUE=0 would print "blue OFF" while
#                 blue ran. Use 'task red:ec2:multi BLUE_ENABLED=0' instead.
#                 Blue's containment producer merged to main
#                 (ares-cli/src/orchestrator/blue/simulated_response.rs, #258),
#                 so BLUE=1 warns only if the deployed tree predates that merge
#                 (blue would DETECT but not CONTAIN — no red-adapt beat).
#   BLUE_MODEL    Optional blue-team model spec (e.g. gpt-5.2). Empty reuses the
#                 red/orchestrator model.
#   BUILD_TOOL    Forwarded to ec2:deploy, whose default is 'remote' — the
#                 build runs natively ON the box, so no local ./target/release
#                 /ares appears after a deploy. Set 'auto' for a local
#                 cross-compile instead. On 'remote', tokio's linker can OOM
#                 kali-ares at stock RAM/swap; bump the instance or add swap.
#   POLL_INTERVAL Seconds between watch polls (default: 30)
#   MAX_WAIT      Seconds before watch gives up (default: 7200)
#   BLUE_SETTLE_WAIT / BLUE_STALL_WAIT
#                 Blue is enqueued, not synchronous, so consolidating the moment
#                 red finishes captures half-written state and under-reports
#                 coverage. SETTLE (default 1800) is the hard cap on waiting for
#                 it to drain; STALL (default 900) gives up sooner when the
#                 active count stops moving, which means an investigation was
#                 orphaned by shutdown and is stuck at in_progress forever —
#                 that count never reaches 0, so without STALL every such run
#                 would burn the full SETTLE budget.
#   OUTPUT_DIR    Where the fetched report lands (default: ./reports)
#   S3_BUCKET     Required for ec2:deploy — pass or export
#   ARES_CLI      Host-native CLI used by ec2:kill/watch/report (default:
#                 ./target/release/ares; falls back to ./target/debug/ares,
#                 else builds the release binary once)

set -euo pipefail

# Booleans accept 1/true/yes/on so `SKIP_DEPLOY=true` matches the rest of the
# taskfiles, where `true` is the idiom (e.g. ec2:deploy SKIP_RESTART=true).
is_true() { printf '%s' "${1:-}" | grep -qiE '^(1|true|yes|y|on)$'; }

EC2_NAME=${EC2_NAME:-kali-ares}
ALLOW_PROD=${ALLOW_PROD:-0}
ALLOW_STALE=${ALLOW_STALE:-0}
TARGET=${1:-${TARGET:-dreadgoad}}
SKIP_DEPLOY=${SKIP_DEPLOY:-0}
SKIP_RESTART=${SKIP_RESTART:-0}
SKIP_KILL=${SKIP_KILL:-0}
BLUE=${BLUE:-1}
BLUE_MODEL=${BLUE_MODEL:-}
CRED_USER=${CRED_USER:-}
CRED_PASS=${CRED_PASS:-}
CRED_DOMAIN=${CRED_DOMAIN:-}
DOMAIN=${DOMAIN:-}
POLL_INTERVAL=${POLL_INTERVAL:-30}
MAX_WAIT=${MAX_WAIT:-7200}
OUTPUT_DIR=${OUTPUT_DIR:-./reports}
AWS_REGION=${AWS_REGION:-us-west-1}
AWS_DEFAULT_REGION=${AWS_REGION}
export AWS_REGION AWS_DEFAULT_REGION
GATE_STRING=${GATE_STRING:-}

log() { printf '[e2e] %s\n' "$*"; }
step() { printf '\n=== %s ===\n' "$*"; }
die() {
	printf '[e2e] FATAL: %s\n' "$*" >&2
	exit 1
}

# mtime in epoch seconds, BSD (macOS) then GNU.
file_mtime() { stat -f %m "$1" 2>/dev/null || stat -c %Y "$1" 2>/dev/null; }

# Run a command on the box and echo its raw output. Base64-wrapped: go-task
# cannot parse a CMD containing quotes, newlines or '=' and fails the
# precondition with "CMD required", which a caller reads as an empty result.
remote_sh() {
	local b64
	b64=$(printf '%s' "$1" | base64 | tr -d '\n')
	task ec2:exec EC2_NAME="${EC2_NAME}" CMD="echo ${b64} | base64 -d | bash" 2>/dev/null
}

step "0. sanity checks"
cd "$(git rev-parse --show-toplevel)" || die "not inside a git repo"
command -v task >/dev/null || die "'task' binary not on PATH"
if ! is_true "$SKIP_DEPLOY" && [[ -z "${S3_BUCKET:-}" ]]; then
	die "S3_BUCKET not set (required for ec2:deploy). Export it or pass SKIP_DEPLOY=true."
fi
log "EC2_NAME=${EC2_NAME}  AWS_REGION=${AWS_REGION}  TARGET=${TARGET}  BLUE=${BLUE}"

# The step-2b SHA gate proves the binary was built by THIS run; it cannot prove
# the source it was built from is current. A fresh build of a stale checkout
# passes every downstream gate and ships code that predates your merges.
if ! is_true "$SKIP_DEPLOY" && ! is_true "${ALLOW_STALE}"; then
	step "0b. gate: source is current with upstream"
	UPSTREAM=$(git rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>/dev/null || true)
	if [[ -z "${UPSTREAM}" ]]; then
		log "WARN: '$(git rev-parse --abbrev-ref HEAD)' has no upstream — freshness unverified"
	else
		git fetch --quiet origin "$(git rev-parse --abbrev-ref HEAD)" 2>/dev/null ||
			log "WARN: git fetch failed — comparing against the last-known ${UPSTREAM}"
		BEHIND=$(git rev-list --count 'HEAD..@{u}' 2>/dev/null || echo 0)
		if [[ "${BEHIND}" -gt 0 ]]; then
			git log --oneline 'HEAD..@{u}' 2>/dev/null | sed 's/^/  missing: /' >&2
			die "checkout is ${BEHIND} commit(s) behind ${UPSTREAM} — a build from it would ship code that predates those commits, and the SHA gate would still pass. Run 'git pull --ff-only', or set ALLOW_STALE=true if testing the older tree is the point."
		fi
		log "source freshness PASSED — HEAD level with ${UPSTREAM} ($(git rev-parse --short HEAD))"
	fi
fi

# shellcheck disable=SC2016 # backticks are JMESPath syntax, not shell
RESOLVED=$(aws ec2 describe-instances --region "${AWS_REGION}" \
	--filters "Name=instance-state-name,Values=running" "Name=tag:Name,Values=*${EC2_NAME}*" \
	--query 'Reservations[].Instances[].[InstanceId,Tags[?Key==`Name`]|[0].Value]' \
	--output text 2>/dev/null || true)
MATCH_COUNT=$(printf '%s\n' "${RESOLVED}" | grep -c . || true)
if [[ "${MATCH_COUNT}" -ne 1 ]]; then
	[[ -n "${RESOLVED}" ]] && printf '%s\n' "${RESOLVED}" >&2
	die "EC2_NAME='${EC2_NAME}' matched ${MATCH_COUNT} running instances in ${AWS_REGION} — pass the fully-qualified Name tag"
fi
RESOLVED_NAME=$(printf '%s' "${RESOLVED}" | awk '{print $2}')
log "resolved target: ${RESOLVED_NAME}"
if [[ "${RESOLVED_NAME}" == *prod* ]] && ! is_true "${ALLOW_PROD}"; then
	die "refusing to target PROD host '${RESOLVED_NAME}': ec2:launch flushes its Redis and sanitizes its workspace. Re-run with ALLOW_PROD=true only if that is genuinely intended."
fi
if [[ -n "${CRED_USER}" ]]; then
	[[ -n "${CRED_PASS}" ]] || die "CRED_USER set without CRED_PASS — pass both or neither"
	log "start posture: ASSUMED BREACH — seeding ${CRED_USER}@${CRED_DOMAIN:-<DOMAIN>}"
elif [[ -n "${CRED_PASS}" ]]; then
	die "CRED_PASS set without CRED_USER — pass both or neither"
else
	log "start posture: BLIND — no credential seeded"
fi
if is_true "$BLUE"; then
	BLUE=1
	if [[ -f ares-cli/src/orchestrator/blue/simulated_response.rs ]]; then
		log "blue team ON — containment producer present in this tree ($(pwd))"
	else
		log "WARN: BLUE=1 but the blue containment producer"
		log "WARN: (ares-cli/src/orchestrator/blue/simulated_response.rs) is NOT in this tree."
		log "WARN: Blue will DETECT but not CONTAIN — no red-adapt beat. This merged to"
		log "WARN: main (#258); update your checkout: git checkout main && git pull"
	fi
else
	die "BLUE=0 cannot take effect through this script: step 6 launches via ec2:launch, which does not read BLUE_ENABLED and hardcodes 'export ARES_BLUE_ENABLED=1' (.taskfiles/ec2/Taskfile.yaml:1345). Its only blue var, BLUE_MODE, is declared and never referenced. Passing BLUE=0 would run blue anyway while this script printed 'blue team OFF', so the red-only baseline would be fabricated. For a genuine blue-off run use: task red:ec2:multi BLUE_ENABLED=0 TARGET=${TARGET} (.taskfiles/red/Taskfile.yaml:904 substitutes it into the launch template)."
fi

step "1. ensure a host-native ares CLI for ec2:kill / ec2:watch / ec2:report"
ARES_CLI=${ARES_CLI:-./target/release/ares}
export ARES_CLI
if [[ -x "${ARES_CLI}" ]]; then
	log "local CLI: ${ARES_CLI}"
elif [[ "${ARES_CLI}" == "./target/release/ares" && -x ./target/debug/ares ]]; then
	ARES_CLI=./target/debug/ares
	export ARES_CLI
	log "local CLI: ${ARES_CLI} (release build absent)"
elif [[ "${ARES_CLI}" == "./target/release/ares" ]]; then
	log "no local CLI — building (cargo build --release -p ares-cli)"
	cargo build --release -p ares-cli || die "failed to build the local ares CLI"
	log "local CLI: ${ARES_CLI}"
else
	die "ARES_CLI=${ARES_CLI} not found or not executable"
fi

BUILD_START=$(date +%s)
DEPLOY_LOG=$(mktemp -t ares-e2e-deploy.XXXXXX)
if ! is_true "$SKIP_DEPLOY"; then
	step "2. build + deploy binary to ${EC2_NAME}"
	task -y ec2:deploy EC2_NAME="${EC2_NAME}" 2>&1 | tee "${DEPLOY_LOG}"

	# ec2:deploy already chains sha256 from build artifact -> S3 -> installed
	# binary, so it proves the upload was faithful. It cannot prove the artifact
	# was rebuilt from the current tree: if the build no-ops or fails while a
	# previous target/ artifact survives, the whole chain ships that stale binary
	# and reports success. That is how this script shipped stale binaries twice.
	# Requiring a build SHA from THIS run closes it.
	#
	# The two build paths publish provenance differently: the local cross-compile
	# writes target/.deploy/ares.sha256, while the remote (on-box) build only
	# prints its own "Deploy SHA:" line and never touches that file. Accept
	# either, but only when it came from this run — otherwise a months-old
	# ares.sha256 makes the remote path look like a stale-binary hit.
	step "2b. gate: prove the deployed binary was built from this run"
	SHA_FILE=target/.deploy/ares.sha256
	EXPECTED_SHA=""
	if [[ -f "${SHA_FILE}" ]]; then
		SHA_MTIME=$(file_mtime "${SHA_FILE}")
		if [[ -n "${SHA_MTIME}" ]] && ((SHA_MTIME >= BUILD_START)); then
			EXPECTED_SHA=$(tr -d '[:space:]' <"${SHA_FILE}")
			log "provenance source: local build artifact sha"
		fi
	fi
	if [[ -z "${EXPECTED_SHA}" ]]; then
		EXPECTED_SHA=$(grep -oE 'Deploy SHA: *[0-9a-f]{64}' "${DEPLOY_LOG}" | tail -1 | grep -oE '[0-9a-f]{64}' || true)
		[[ -n "${EXPECTED_SHA}" ]] && log "provenance source: remote build Deploy SHA"
	fi
	[[ -n "${EXPECTED_SHA}" ]] || die "no build SHA from this run — neither a fresh ${SHA_FILE} nor a 'Deploy SHA:' line in the deploy output. The build produced no fresh artifact, so a STALE binary may have shipped (BUILD_TOOL=${BUILD_TOOL:-remote}). Deploy log: ${DEPLOY_LOG}"
	DEPLOYED_SHA=$(remote_sh 'sha256sum /usr/local/bin/ares' | grep -oE '[0-9a-f]{64}' | head -1 || true)
	[[ -n "${DEPLOYED_SHA}" ]] || die "could not read the deployed binary sha256 from ${EC2_NAME}"
	[[ "${EXPECTED_SHA}" == "${DEPLOYED_SHA}" ]] ||
		die "deployed binary != freshly built binary (built=${EXPECTED_SHA:0:12} deployed=${DEPLOYED_SHA:0:12})"
	log "binary gate PASSED — deployed sha ${DEPLOYED_SHA:0:12} matches this build"
else
	log "SKIP_DEPLOY set — using the binary already on the box"
	log "WARN: build-provenance gate skipped — results cannot be attributed to your edits"
fi

# The SHA gate proves the binary is freshly built; it cannot prove WHICH edit
# is in it. GATE_STRING asserts a literal from the change under test.
if [[ -n "${GATE_STRING}" ]]; then
	step "2c. gate: assert GATE_STRING appears in the deployed binary"
	HITS=$(remote_sh "printf 'GATEHITS=%s\\n' \"\$(grep -ac -- '${GATE_STRING}' /usr/local/bin/ares || echo 0)\"" |
		grep -oE 'GATEHITS=[0-9]+' | head -1 | cut -d= -f2 || true)
	[[ -n "${HITS}" && "${HITS}" -ge 1 ]] ||
		die "GATE_STRING absent from the deployed binary: '${GATE_STRING}' — your change did not ship"
	log "string gate PASSED — '${GATE_STRING}' present (${HITS} match(es))"
fi

# kali-ares resolves in more than one region and only the us-west-1 box has
# working blue. Name the host and its blue endpoints so a run can never be
# silently attributed to the wrong box.
step "2d. identify the targeted box"
# shellcheck disable=SC2016 # expands on the box, not here
remote_sh 'T=$(curl -s -X PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 60" 2>/dev/null); printf "instance=%s az=%s\n" "$(curl -s -H "X-aws-ec2-metadata-token: $T" http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null)" "$(curl -s -H "X-aws-ec2-metadata-token: $T" http://169.254.169.254/latest/meta-data/placement/availability-zone 2>/dev/null)"; grep -aE "^(LOKI_URL|GRAFANA_URL|ARES_DEPLOYMENT)=" /etc/ares/env 2>/dev/null' ||
	log "warn: could not identify the box — continuing"

if ! is_true "$SKIP_RESTART"; then
	step "3. restart workers (drops the in-memory ENOENT tool cache)"
	# ec2:deploy overwrites the binary on disk but leaves the running
	# process attached to the pre-deploy inode (marked (deleted) in
	# /proc/<pid>/exe). Without this restart, any tool poisoned in the
	# old process's unavailable_tools cache stays dead for the run.
	task -y ec2:restart EC2_NAME="${EC2_NAME}"
else
	log "SKIP_RESTART set — keeping current workers (risks stale cache)"
fi

step "4. verify tool binaries resolve on ${EC2_NAME}"
task ec2:exec EC2_NAME="${EC2_NAME}" \
	CMD='which nmap nxc netexec certipy hashcat 2>&1; echo ---; nmap --version 2>&1 | head -1; nxc --version 2>&1 | head -1' ||
	log "warn: verify step returned non-zero — continuing anyway"

if ! is_true "$SKIP_KILL"; then
	step "5. kill any operations still running on ${EC2_NAME}"
	# A worker restart bounces the processes but leaves prior operations in
	# Redis (queued or mid-flight); the restarted orchestrator can even
	# claim-next a stale queued op. Stop + delete every running op so the
	# launch below is the only thing in flight.
	task -y ec2:kill EC2_NAME="${EC2_NAME}" ALL=true ||
		log "warn: kill step returned non-zero — continuing anyway"
else
	log "SKIP_KILL set — leaving already-running ops in place"
fi

step "6. launch a fresh red-team op against ${TARGET}"
LAUNCH_LOG=$(mktemp -t ares-e2e-launch.XXXXXX)
trap 'rm -f "${LAUNCH_LOG}"' EXIT

task ec2:launch \
	EC2_NAME="${EC2_NAME}" \
	TARGETS="${TARGET}" \
	DOMAIN="${DOMAIN}" \
	CRED_USER="${CRED_USER}" \
	CRED_PASS="${CRED_PASS}" \
	CRED_DOMAIN="${CRED_DOMAIN}" \
	BLUE_ENABLED="${BLUE}" \
	BLUE_LLM_MODEL="${BLUE_MODEL}" \
	WAIT=true \
	POLL_INTERVAL="${POLL_INTERVAL}" \
	MAX_WAIT="${MAX_WAIT}" 2>&1 | tee "${LAUNCH_LOG}"

OP_ID=$(grep -oE 'op-[0-9]{8}-[0-9]{6}' "${LAUNCH_LOG}" | tail -1 || true)
if [[ -z "${OP_ID}" ]]; then
	log "warn: could not parse OP id from launch output — skipping pruning-cascade check"
else
	log "resolved OP id: ${OP_ID}"
fi

step "7. scan the op log for the tool-pruning-cascade signature"
# The bug this suite is guarding against: one transient spawn failure
# poisons the worker's unavailable_tools cache, and the LLM prunes the
# tool from active_tools for the rest of the op. If we see 3+ recon
# tools pruned in one op, the cascade is back — verify each is a truly
# missing binary before shrugging it off.
if [[ -n "${OP_ID}" ]]; then
	PRUNED=$(task ec2:exec EC2_NAME="${EC2_NAME}" \
		CMD="sudo grep -aE 'Tool binary not found' /var/log/ares/orchestrator.log 2>/dev/null | grep -a '${OP_ID}' | grep -oE 'tool=[a-z_]+' | sort -u" \
		2>/dev/null || true)
	if [[ -n "${PRUNED}" ]]; then
		log "pruned tools during ${OP_ID}:"
		# shellcheck disable=SC2086 # word-split intentionally: one tool per line
		printf '  %s\n' ${PRUNED}
		NUM=$(printf '%s\n' "${PRUNED}" | wc -l | tr -d ' ')
		if [[ "${NUM}" -ge 3 ]]; then
			log "SUSPECT CASCADE: ${NUM} tools pruned — confirm each is truly ENOENT (see .claude/skills/ares-debug)"
		fi
	else
		log "no tools pruned — clean recon path"
	fi
fi

step "8. fetch the final report locally"
mkdir -p "${OUTPUT_DIR}"
if [[ -n "${OP_ID}" ]]; then
	task ec2:report EC2_NAME="${EC2_NAME}" OPERATION_ID="${OP_ID}" OUTPUT_DIR="${OUTPUT_DIR}" ||
		log "warn: report fetch failed — retry with 'task ec2:report EC2_NAME=${EC2_NAME} OPERATION_ID=${OP_ID}'"
else
	task ec2:report EC2_NAME="${EC2_NAME}" LATEST=true OUTPUT_DIR="${OUTPUT_DIR}" ||
		log "warn: report fetch failed — retry with 'task ec2:report EC2_NAME=${EC2_NAME} LATEST=true'"
fi

if [[ "$BLUE" == "1" && -n "${OP_ID}" ]]; then
	step "9. blue-team output for ${OP_ID}"
	# Blue investigations live in the box's Redis; source /etc/ares/env so the
	# CLI resolves box-local Redis, then print the per-op aggregate.
	blue_active() {
		local out n done_at
		out=$(task ec2:exec EC2_NAME="${EC2_NAME}" \
			CMD="set -a; . /etc/ares/env 2>/dev/null; set +a; /usr/local/bin/ares blue operation-status ${OP_ID} 2>&1; echo '---COMPLETED_AT---'; redis-cli HGET 'ares:op:${OP_ID}:meta' completed_at" \
			2>/dev/null) || return 1
		n=$(awk '/^ *(Running|Submitted):/ {gsub(/[^0-9]/, "", $2); n += $2} END {print n + 0}' <<<"$out")
		# The terminal investigation — the only one built from complete loot and
		# the full attack window — is submitted by orchestrator completion AFTER
		# the red drain and teardown, minutes after `ops status` starts reporting
		# "completed" off red_completed_at. So Running+Submitted legitimately
		# reads 0 before it exists, and consolidating on that alone drops it from
		# the scorecard (op-20260810-030156: report 03:21:39, terminal inv
		# 03:22:38 — "Investigations | 1" is that exclusion). `completed_at` is
		# written by finalize_operation, which runs only after the blue drain, so
		# an unset value means blue is still outstanding no matter what the
		# counts say. red_blocked_on_blue is unusable here: it is written once at
		# red completion and never cleared.
		if [[ "$n" -eq 0 ]]; then
			done_at=$(sed -n '/---COMPLETED_AT---/,$p' <<<"$out" | tail -n +2 | tr -d '[:space:]')
			if [[ -z "$done_at" || "$done_at" == "null" ]]; then
				n=1
			fi
		fi
		echo "$n"
	}
	# Red reaching a terminal state does not mean blue has. `blue submit` only
	# enqueues, so consolidating here captures half-written investigations and
	# under-reports coverage. Wait for Running+Submitted to reach 0 AND the op to
	# be finalized.
	# A red-op shutdown that outruns its blue drain leaves the investigation
	# stuck at in_progress forever, so Running never reaches 0 and a plain
	# wait-for-zero would always burn the full timeout. Treat an unchanging
	# count as orphaned and stop early.
	BLUE_SETTLE_WAIT=${BLUE_SETTLE_WAIT:-1800}
	BLUE_STALL_WAIT=${BLUE_STALL_WAIT:-900}
	blue_waited=0
	blue_stalled=0
	blue_prev=""
	while :; do
		blue_n=$(blue_active) || blue_n=""
		if [[ -z "${blue_n}" ]]; then
			log "warn: blue operation-status unreadable — consolidating without waiting"
			break
		fi
		if [[ "${blue_n}" -eq 0 ]]; then
			log "blue investigations settled after ${blue_waited}s"
			break
		fi
		if [[ "${blue_n}" == "${blue_prev}" ]]; then
			blue_stalled=$((blue_stalled + POLL_INTERVAL))
		else
			blue_stalled=0
			blue_prev="${blue_n}"
		fi
		if ((blue_stalled >= BLUE_STALL_WAIT)); then
			log "warn: blue stuck at ${blue_n} active for ${blue_stalled}s — treating as orphaned"
			log "warn: (shutdown drops in-flight investigations; status stays in_progress forever)"
			log "warn: confirm with 'ares blue operation-status ${OP_ID}' — a stale in_progress never clears"
			break
		fi
		if ((blue_waited >= BLUE_SETTLE_WAIT)); then
			log "warn: ${blue_n} blue investigation(s) still active after ${BLUE_SETTLE_WAIT}s"
			log "warn: consolidating partial blue state — coverage will under-report"
			break
		fi
		log "blue: ${blue_n} investigation(s) active (${blue_waited}/${BLUE_SETTLE_WAIT}s)"
		sleep "${POLL_INTERVAL}"
		blue_waited=$((blue_waited + POLL_INTERVAL))
	done
	task ec2:exec EC2_NAME="${EC2_NAME}" \
		CMD="set -a; . /etc/ares/env 2>/dev/null; set +a; /usr/local/bin/ares blue operation-status ${OP_ID} 2>&1 | head -40" ||
		log "warn: blue operation-status returned non-zero"
	task blue:reports:consolidate OPERATION_ID="${OP_ID}" EC2_NAME="${EC2_NAME}" \
		EC2_REGION="${AWS_REGION}" OUTPUT_DIR="${OUTPUT_DIR}" ||
		log "warn: blue report fetch failed — retry with 'task blue:reports:consolidate OPERATION_ID=${OP_ID} EC2_NAME=${EC2_NAME} EC2_REGION=${AWS_REGION}'"
	# Demo-critical signal: did blue confirm a containment action AND did red drop
	# queued tasks in response? The orchestrator log is truncated per launch, so a
	# raw count is already scoped to this op.
	SIGNALS=$(task ec2:exec EC2_NAME="${EC2_NAME}" \
		CMD="sudo grep -acE 'blue\\.simulated_response|invalidated by blue containment' /var/log/ares/orchestrator.log 2>/dev/null || echo 0" \
		2>/dev/null | grep -oE '[0-9]+' | tail -1 || echo 0)
	log "blue containment / red-adapt signals in op log: ${SIGNALS:-0}"
	if [[ "${SIGNALS:-0}" -eq 0 ]]; then
		log "note: 0 containment signals — blue investigated but never confirmed a"
		log "note: containment action, or red hit DA before blue escalated. Inspect:"
		log "note:   task ec2:exec EC2_NAME=${EC2_NAME} CMD='ares blue techniques --latest'"
	fi
elif [[ "$BLUE" == "1" ]]; then
	log "BLUE=1 but no OP_ID parsed — skipping blue fetch"
fi

step "done"
log "op id:      ${OP_ID:-unknown}"
log "reports in: ${OUTPUT_DIR}/red/"
if [[ "$BLUE" == "1" ]]; then
	log "blue report: ${OUTPUT_DIR}/blue/"
	log "blue status:  task ec2:exec EC2_NAME=${EC2_NAME} CMD='ares blue operation-status ${OP_ID:-<op>}'"
fi
