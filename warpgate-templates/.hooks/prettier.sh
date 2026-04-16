#!/bin/bash
set -eo pipefail

# Check if prettier is installed
if ! command -v prettier &>/dev/null; then
	echo 'Error: prettier is not installed.' >&2
	echo 'Please install it with: npm install -g prettier' >&2
	exit 1
fi

# Get list of staged files
STAGED_FILES=$(git diff --cached --name-only --diff-filter=d | grep -E '\.(json|ya?ml)$' || true)

# Exit early if no files to format
if [ -z "$STAGED_FILES" ]; then
	exit 0
fi

# Run Prettier on staged files
echo "Running Prettier on staged files..."
echo "$STAGED_FILES" | xargs prettier --write

# Add formatted files back to staging area
echo "$STAGED_FILES" | xargs git add

echo "Prettier formatting completed."

exit 0
