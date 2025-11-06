#!/usr/bin/env python3
"""
Fix indentation issues in plugins after sed command
"""

import re
from pathlib import Path

plugins = [
    'plugins/interactive-testing/selenium_interactive/selenium_interactive.py',
    'plugins/web-testing/selenium_fuzzer/selenium_fuzzer.py',
    'plugins/server-testing/webapp_scanner/webapp_scanner.py',
    'plugins/server-testing/nikto_integration/nikto_integration.py',
    'plugins/server-testing/nuclei_integration/nuclei_integration.py',
    'plugins/server-testing/zap_integration/zap_integration.py',
]

def fix_plugin(filepath):
    """Fix a single plugin file"""
    print(f"[*] Fixing: {filepath}")

    with open(filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    fixed_lines = []
    in_class = False
    skip_until_next_method = False
    class_indent_level = 0

    for i, line in enumerate(lines):
        # Detect class definition
        if line.strip().startswith('class ') and '(PluginInterface)' in line:
            in_class = True
            fixed_lines.append(line)
            # Calculate indent level
            class_indent_level = len(line) - len(line.lstrip())
            continue

        if in_class:
            # Check if we're at a class-level attribute (name, version, etc)
            stripped = line.strip()
            if stripped.startswith(('name =', 'version =', 'author =', 'description =', 'category =', 'requires =')):
                fixed_lines.append(line)
                continue

            # Check if we're at __init__ method
            if 'def __init__(self, config=None):' in line:
                fixed_lines.append(line)
                # Add super().__init__(config) if next line doesn't have it
                if i + 1 < len(lines) and 'super().__init__' not in lines[i + 1]:
                    indent = ' ' * (class_indent_level + 4)
                    fixed_lines.append(f'{indent}    super().__init__(config)\n')
                skip_until_next_method = True
                continue

            # Skip orphaned code between __init__ and next method
            if skip_until_next_method:
                # Check if we hit another method or the run method
                if line.strip().startswith('def '):
                    skip_until_next_method = False

                    # Fix run() signature if needed
                    if 'def run(self):' in line:
                        indent = ' ' * (class_indent_level + 4)
                        fixed_lines.append(f'{indent}def run(self, target, **kwargs):\n')
                        continue

                    fixed_lines.append(line)
                    continue
                else:
                    # Skip this line (orphaned code)
                    continue

            fixed_lines.append(line)
        else:
            fixed_lines.append(line)

    # Write back
    with open(filepath, 'w', encoding='utf-8') as f:
        f.writelines(fixed_lines)

    print(f"[✓] Fixed: {filepath}")

def main():
    for plugin_path in plugins:
        full_path = Path(plugin_path)
        if full_path.exists():
            fix_plugin(full_path)
        else:
            print(f"[!] Not found: {plugin_path}")

    print("\n[✓] All plugins fixed!")

if __name__ == '__main__':
    main()
