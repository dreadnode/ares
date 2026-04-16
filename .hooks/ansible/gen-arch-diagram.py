#!/usr/bin/env python3
"""
Ansible Collection Mermaid Diagram Generator Pre-commit Hook

Generates a Mermaid diagram from an Ansible collection structure
and updates the ansible/README.md in the ares repo.
"""

from pathlib import Path
import sys
import re
import subprocess


class AnsibleCollectionAnalyzer:
    def __init__(self, collection_path: str):
        self.collection_path = Path(collection_path)
        self.structure = {
            'roles': [],
            'plugins': [],
            'playbooks': []
        }

    def analyze(self):
        """Analyze the Ansible collection structure"""
        # Analyze roles
        roles_path = self.collection_path / 'roles'
        if roles_path.exists():
            for role_dir in sorted(roles_path.iterdir(), key=lambda p: p.name):
                if role_dir.is_dir() and not role_dir.name.startswith('.'):
                    self.structure['roles'].append({
                        'name': role_dir.name,
                        'has_molecule': (role_dir / 'molecule').exists()
                    })

        # Analyze plugins
        plugins_path = self.collection_path / 'plugins' / 'modules'
        if plugins_path.exists():
            for plugin_file in sorted(plugins_path.glob('*.py'), key=lambda p: p.name):
                if not plugin_file.name.startswith('__'):
                    self.structure['plugins'].append(plugin_file.stem)

        # Analyze playbooks
        playbooks_path = self.collection_path / 'playbooks'
        if playbooks_path.exists():
            for item in sorted(playbooks_path.iterdir(), key=lambda p: p.name):
                if item.is_dir() and not item.name.startswith('.'):
                    self.structure['playbooks'].append({
                        'name': item.name,
                        'has_molecule': (item / 'molecule').exists()
                    })

        return self.structure


def generate_mermaid(structure):
    """Generate Mermaid diagram"""
    lines = ["```mermaid", "graph TD"]
    lines.append("    Collection[Ansible Collection]")

    # Add plugins
    if structure['plugins']:
        lines.append("    Collection --> Plugins[Plugins]")
        for i, plugin in enumerate(structure['plugins']):
            lines.append(f"    Plugins --> P{i}[{plugin}]")

    # Add roles
    if structure['roles']:
        lines.append("    Collection --> Roles[Roles]")
        for i, role in enumerate(structure['roles']):
            role_label = role['name']
            if role['has_molecule']:
                role_label += " *"
            lines.append(f"    Roles --> R{i}[{role_label}]")

    # Add playbooks
    if structure['playbooks']:
        lines.append("    Collection --> Playbooks[Playbooks]")
        for i, playbook in enumerate(structure['playbooks']):
            pb_label = playbook['name']
            if playbook['has_molecule']:
                pb_label += " *"
            lines.append(f"    Playbooks --> PB{i}[{pb_label}]")

    lines.append("```")
    return '\n'.join(lines)


def update_readme(mermaid_content, readme_path):
    """Update README.md with the generated Mermaid diagram"""
    if not readme_path.exists():
        print(f"README.md not found at {readme_path}")
        return False

    readme_content = readme_path.read_text()

    # Define markers for the architecture section
    start_marker = "## Architecture Diagram"
    end_marker = "## Requirements"

    # Find the start and end positions
    start_pos = readme_content.find(start_marker)
    if start_pos == -1:
        print("Could not find '## Architecture Diagram' section in README.md")
        return False

    end_pos = readme_content.find(end_marker, start_pos)
    if end_pos == -1:
        next_section_pattern = re.compile(r'\n## (?!Architecture Diagram)')
        match = next_section_pattern.search(readme_content, start_pos + len(start_marker))
        if match:
            end_pos = match.start() + 1
        else:
            print("Could not find the end of the Architecture Diagram section")
            return False

    # Build the new architecture section
    new_section = f"{start_marker}\n\n{mermaid_content}\n\n"

    # Replace the section
    new_readme = readme_content[:start_pos] + new_section + readme_content[end_pos:]

    # Write back to README
    readme_path.write_text(new_readme)

    return True


def main():
    """Main function for pre-commit hook"""
    # Analyze collection from ansible/ subdirectory
    analyzer = AnsibleCollectionAnalyzer('ansible')
    structure = analyzer.analyze()

    # Generate Mermaid diagram
    mermaid_content = generate_mermaid(structure)

    # Update ansible/README.md
    readme_path = Path('ansible/README.md')
    if update_readme(mermaid_content, readme_path):
        print("Architecture diagram updated in ansible/README.md")
        print(f"\nCollection summary:")
        print(f"  Roles: {len(structure['roles'])}")
        print(f"  Plugins: {len(structure['plugins'])}")
        print(f"  Playbooks: {len(structure['playbooks'])}")

        # Check if the README was actually modified (unstaged changes)
        result = subprocess.run(
            ['git', 'diff', '--name-only', 'ansible/README.md'],
            capture_output=True, text=True
        )
        if result.stdout.strip():
            print("ansible/README.md was updated. Please stage and re-commit.")
            return 1

        return 0
    else:
        print("Failed to update ansible/README.md")
        return 1


if __name__ == "__main__":
    sys.exit(main())
