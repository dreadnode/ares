#!/usr/bin/env bash
#
# Fails on real DreadGOAD lab tokens (character names, account passwords, lab
# IPs) and generic test placeholders in repo code, tests, templates and docs.
#
# Those names and passwords are live loot in the range. When they reach a
# fixture or a prompt template the LLM copies them into real tool calls, which
# creates phantom entries in dreadgoad's scoreboard. Use contoso.local /
# fabrikam.local, 192.168.58.x, dc01/dc02/sql01/web01/ws01/ca01,
# alice/bob/carol/admin/svc_*, and P@ssw0rd! instead.
#
# Usage:
#   scripts/goad-token-sweep.sh              # sweep the whole tree
#   scripts/goad-token-sweep.sh FILE...      # sweep specific files (pre-commit)
#
# The regex below is kept in sync with .claude/CLAUDE.md and
# .claude/hooks/check-banned-strings.sh. Generic-word passwords ("Needle",
# "horse") are deliberately omitted: case-insensitively they collide with
# ordinary identifiers such as the `needle` variables in the tree.

set -uo pipefail

names='sevenkingdoms|essos\.|braavos|meereen|kingslanding|castelblack|winterfell|arya\.|eddard|sansa|jon\.snow|catelyn|robb\.stark|brandon\.stark|rickon\.stark|hodor|samwell|jeor|jorah|robert\.baratheon|cersei|tywin|tyron|jaime|joffrey|renly|stannis|petyer|lord\.varys|pycelle|daenerys|viserys|khal\.drogo|drogon|missandei'
leaks='59hv\.local|win-mvbxbx7jbs6'
placeholders='test\.local|example\.com|corp\.local|domain\.local|contoso\.com'
ips='10\.1\.[0-9]{1,3}\.[0-9]{1,3}|10\.0\.[0-9]{1,3}\.[0-9]{1,3}|172\.16\.[0-9]{1,3}\.[0-9]{1,3}'
ips_underscore='10_1_[0-9]{1,3}_[0-9]{1,3}|10_0_[0-9]{1,3}_[0-9]{1,3}|172_16_[0-9]{1,3}_[0-9]{1,3}'
passwords='Heartsbane|iseedeadpeople|iknownothing|sexywolfy|s3xywolfy|FightP3aceAndH[0o]nor|L0ngCl@w|H0nnor|fr3edom|BurnThemAll|dracarys|Drag0nst0ne|iamthekingoftheworld|il0vejaime|lorastyrell|littlefinger|MaesterOfMaesters|powerkingftw135|robbsansabradonaryarickon|1killerlion|345ertdfg|Alc00L|W1sper|GoldCrown|Winter2022|YouWillNotKerboroast'

banned="${names}|${leaks}|${placeholders}|${ips}|${ips_underscore}|${passwords}"

# Paths that may legitimately carry real lab tokens: CLI wrappers that drive the
# range, the lab spec itself, operator-facing config comments, local agent
# tooling, the gitignored demo viewer, and scratch space. docs/DEMO-PLAN.md is
# exempt for the same reason as the other planning docs: it narrates real ops,
# and its own text requires the GOAD names verbatim for the recording.
exempt='(^|/)(\.git|target|node_modules|\.claude|\.gemini|\.taskfiles|demo|safe)/|(^|/)Taskfile\.yaml$|(^|/)CLAUDE\.md$|(^|/)docs/goad-checklist\.md$|(^|/)docs/(plan-.*|DEMO-PLAN)\.md$|(^|/)config/ares\.yaml$|(^|/)scripts/goad-token-sweep\.sh$|(^|/)FINDINGS(-.*)?\.md$'

extensions='\.(rs|tera|py|md|ya?ml|toml|json|sh)$'

files=()
if [ "$#" -gt 0 ]; then
	files=("$@")
else
	while IFS= read -r line; do
		files+=("$line")
	done < <(git ls-files)
fi

candidates=()
for f in "${files[@]}"; do
	[ -f "$f" ] || continue
	printf '%s\n' "$f" | grep -qE "$exempt" && continue
	printf '%s\n' "$f" | grep -qE "$extensions" || continue
	candidates+=("$f")
done

[ "${#candidates[@]}" -eq 0 ] && exit 0

hits=$(grep -HniE "$banned" "${candidates[@]}" 2>/dev/null)

if [ -n "$hits" ]; then
	{
		echo "BLOCKED: DreadGOAD lab tokens or test placeholders found."
		echo
		printf '%s\n' "$hits"
		echo
		echo "Allowed instead: contoso.local / fabrikam.local, 192.168.58.x,"
		echo "dc01|dc02|sql01|web01|ws01|ca01, alice|bob|carol|admin|svc_*, P@ssw0rd!"
		echo
		echo "If the file genuinely drives the real lab, add it to the exempt"
		echo "pattern in scripts/goad-token-sweep.sh and keep .claude/CLAUDE.md and"
		echo ".claude/hooks/check-banned-strings.sh in sync."
	} >&2
	exit 1
fi

exit 0
