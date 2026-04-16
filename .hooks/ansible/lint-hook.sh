#!/bin/bash
set -eo pipefail

# Use offline mode locally to prevent git index corruption from concurrent
# galaxy collection installs during pre-commit hooks. In CI (GitHub Actions),
# run in online mode to allow collection installation.
if [ -z "${GITHUB_ACTIONS}" ]; then
	# Local pre-commit: use offline mode
	exec ansible-lint -v --force-color --offline -c .hooks/ansible/ansible-lint.yaml "$@"
else
	# CI: allow collection installation
	exec ansible-lint -v --force-color -c .hooks/ansible/ansible-lint.yaml "$@"
fi
