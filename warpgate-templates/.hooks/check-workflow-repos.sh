#!/bin/bash
set -eo pipefail

# Check that GitHub App token repository lists are consistent across workflow files
# This prevents issues where one workflow has access to a repo but another doesn't

WORKFLOWS_DIR=".github/workflows"
BUILD_WORKFLOW="$WORKFLOWS_DIR/build-and-push-templates.yaml"
TEST_WORKFLOW="$WORKFLOWS_DIR/test-template-builds.yaml"

# Extract unique sorted repository list from a workflow file
extract_repos() {
	local file="$1"
	# Find all 'repositories: |' blocks and extract the repo names
	# Uses awk to find the block and extract indented lines that follow
	awk '
		/repositories: \|/ { in_block=1; next }
		in_block && /^[[:space:]]*$/ { in_block=0 }
		in_block && /^[[:space:]]+[a-zA-Z]/ { gsub(/^[[:space:]]+/, ""); print }
		in_block && /^[[:space:]]*-/ { in_block=0 }
	' "$file" | sort -u
}

# Check if either workflow file is being modified
STAGED_FILES=$(git diff --cached --name-only --diff-filter=d || true)
if ! echo "$STAGED_FILES" | grep -qE "(build-and-push-templates|test-template-builds)\.yaml$"; then
	exit 0
fi

# Ensure both files exist
if [[ ! -f "$BUILD_WORKFLOW" ]] || [[ ! -f "$TEST_WORKFLOW" ]]; then
	echo "Warning: One or both workflow files not found, skipping check"
	exit 0
fi

BUILD_REPOS=$(extract_repos "$BUILD_WORKFLOW")
TEST_REPOS=$(extract_repos "$TEST_WORKFLOW")

indent() {
	while IFS= read -r line; do
		printf '  %s\n' "$line"
	done
}

if [[ "$BUILD_REPOS" != "$TEST_REPOS" ]]; then
	echo "Error: GitHub App token repository lists are inconsistent!" >&2
	echo "" >&2
	echo "Repositories in $BUILD_WORKFLOW:" >&2
	echo "$BUILD_REPOS" | indent >&2
	echo "" >&2
	echo "Repositories in $TEST_WORKFLOW:" >&2
	echo "$TEST_REPOS" | indent >&2
	echo "" >&2
	echo "Missing from build workflow:" >&2
	comm -13 <(echo "$BUILD_REPOS") <(echo "$TEST_REPOS") | indent >&2
	echo "" >&2
	echo "Missing from test workflow:" >&2
	comm -23 <(echo "$BUILD_REPOS") <(echo "$TEST_REPOS") | indent >&2
	exit 1
fi

# Verify all repos are accessible via GitHub CLI
# This catches renamed/deleted repos before they break CI
if ! command -v gh &>/dev/null; then
	echo "Warning: gh CLI not installed, skipping repository accessibility check"
	echo "Install gh CLI to enable this check: https://cli.github.com/"
	echo "Workflow repository lists are consistent."
	exit 0
fi

if ! gh auth status &>/dev/null; then
	echo "Warning: gh CLI not authenticated, skipping repository accessibility check"
	echo "Run 'gh auth login' to enable this check"
	echo "Workflow repository lists are consistent."
	exit 0
fi

echo "Checking repository accessibility..."
FAILED_REPOS=()
while IFS= read -r repo; do
	[[ -z "$repo" ]] && continue
	if ! gh repo view "dreadnode/$repo" --json name >/dev/null 2>&1; then
		FAILED_REPOS+=("$repo")
	fi
done <<<"$BUILD_REPOS"

if [[ ${#FAILED_REPOS[@]} -gt 0 ]]; then
	echo "Error: The following repositories are not accessible:" >&2
	for repo in "${FAILED_REPOS[@]}"; do
		echo "  - dreadnode/$repo" >&2
	done
	echo "" >&2
	echo "These repos may have been renamed, deleted, or you don't have access." >&2
	echo "Update the workflow files to use the correct repository names." >&2
	exit 1
fi

echo "Workflow repository lists are consistent and all repos are accessible."
exit 0
