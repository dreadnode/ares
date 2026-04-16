#!/usr/bin/env bash
set -euo pipefail

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Get repo root
REPO_ROOT=$(git rev-parse --show-toplevel)
cd "$REPO_ROOT/ansible"

# Check if docsible is installed
if ! command -v docsible &>/dev/null; then
	echo -e "${RED}Error: docsible is not installed${NC}"
	echo "Please install docsible: pip3 install docsible==0.8.0"
	exit 1
fi

# Check if template exists
TEMPLATE_PATH="$REPO_ROOT/.hooks/ansible/templates/docsible-template.md.j2"
if [ ! -f "$TEMPLATE_PATH" ]; then
	echo -e "${RED}Error: Template file not found at $TEMPLATE_PATH${NC}"
	echo "Please ensure the template file exists before running this hook."
	exit 1
fi

FILES_MODIFIED=0

# Process roles
for role_dir in roles/*/; do
	[ -d "$role_dir" ] || continue

	role_name=$(basename "$role_dir")
	readme="${role_dir}README.md"

	echo "Processing role: $role_name"

	# Save original for comparison
	if [ -f "$readme" ]; then
		cp "$readme" "$readme.bak"
	fi

	# Generate documentation for role
	if output=$(docsible --role "$role_dir" --no-docsible --no-backup --comments --md-role-template "$TEMPLATE_PATH" 2>&1); then

		# Check if changed
		if [ -f "$readme.bak" ]; then
			if ! cmp -s "$readme.bak" "$readme"; then
				echo "  Updated with custom template"
				FILES_MODIFIED=1
			else
				echo "  No changes"
			fi
			rm -f "$readme.bak"
		else
			echo "  Created with custom template"
			FILES_MODIFIED=1
		fi
	else
		echo -e "${RED}  Failed to generate docs for $role_name${NC}"
		echo -e "${RED}  Error: $output${NC}"
		# Restore original if it existed
		if [ -f "$readme.bak" ]; then
			mv "$readme.bak" "$readme"
		fi
		# Clean up any backup files before failing
		find . -name "README_backup_*.md" -type f -delete 2>/dev/null || true
		find . -name ".docsible" -type f -delete 2>/dev/null || true
		exit 1
	fi
done

# Clean up any docsible backup files
find . -name "README_backup_*.md" -type f -delete 2>/dev/null || true
find . -name ".docsible" -type f -delete 2>/dev/null || true

# Exit
if [ $FILES_MODIFIED -eq 1 ]; then
	echo -e "${YELLOW}Documentation updated with custom template. Review and commit.${NC}"
	exit 1
else
	echo -e "${GREEN}All documentation up to date${NC}"
	exit 0
fi
