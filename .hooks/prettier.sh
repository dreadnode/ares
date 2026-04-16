#!/bin/bash
set -eo pipefail

# Check if npm is installed
if ! [ -x "$(command -v npm)" ]; then
	echo 'Error: npm is not installed.' >&2
	exit 1
else
	# Check if Prettier is installed
	if ! [ -x "$(command -v prettier)" ]; then
		echo 'Error: Prettier is not installed.' >&2
		echo 'Installing Prettier...'
		npm install -g prettier
	fi
fi

# Check if Prettier is installed
if ! [ -x "$(command -v prettier)" ]; then
	echo 'Error: Prettier is not installed.' >&2
	exit 1
fi

# If no files passed, exit successfully
if [ $# -eq 0 ]; then
	echo "No files to format."
	exit 0
fi

echo "Running Prettier on staged files..."

prettier --write "$@"

echo "Prettier formatting completed."
exit 0
