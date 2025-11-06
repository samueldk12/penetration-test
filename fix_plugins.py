#!/usr/bin/env python3
"""
Script to automatically fix plugins to inherit from PluginInterface
"""

import os
import re
from pathlib import Path

# Plugin files to fix
plugins_to_fix = [
    'plugins/authentication-testing/brute_force/brute_force.py',
    'plugins/interactive-testing/selenium_interactive/selenium_interactive.py',
    'plugins/web-testing/selenium_fuzzer/selenium_fuzzer.py',
    'plugins/server-testing/webapp_scanner/webapp_scanner.py',
    'plugins/server-testing/nikto_integration/nikto_integration.py',
    'plugins/server-testing/nuclei_integration/nuclei_integration.py',
    'plugins/server-testing/zap_integration/zap_integration.py',
]

def add_plugin_interface_import(content):
    """Add PluginInterface import if not present"""
    if 'from tools.plugin_system import PluginInterface' in content or 'from plugin_system import PluginInterface' in content:
        return content

    # Find first import
    import_pattern = r'^(import |from )'
    lines = content.split('\n')

    import_block = []
    import_block.append("# Add project root to path")
    import_block.append("from pathlib import Path")
    import_block.append("import sys")
    import_block.append("project_root = Path(__file__).parent.parent.parent.parent")
    import_block.append("sys.path.insert(0, str(project_root))")
    import_block.append("sys.path.insert(0, str(project_root / 'tools'))")
    import_block.append("")
    import_block.append("try:")
    import_block.append("    from tools.plugin_system import PluginInterface")
    import_block.append("except ImportError:")
    import_block.append("    from plugin_system import PluginInterface")
    import_block.append("")

    # Find where to insert (after docstring, before first import)
    insert_idx = 0
    in_docstring = False
    docstring_char = None

    for i, line in enumerate(lines):
        stripped = line.strip()

        # Handle docstrings
        if stripped.startswith('"""') or stripped.startswith("'''"):
            if not in_docstring:
                in_docstring = True
                docstring_char = '"""' if stripped.startswith('"""') else "'''"
                if stripped.count(docstring_char) >= 2:  # Single line docstring
                    in_docstring = False
                    insert_idx = i + 1
            else:
                if docstring_char in stripped:
                    in_docstring = False
                    insert_idx = i + 1
        elif not in_docstring and re.match(import_pattern, stripped):
            insert_idx = i
            break

    # Insert the import block
    lines[insert_idx:insert_idx] = import_block

    return '\n'.join(lines)

def fix_class_inheritance(content, class_name):
    """Add PluginInterface as base class"""
    # Pattern: class ClassName: or class ClassName():
    pattern = rf'class {class_name}(\(\s*\))?:'
    replacement = f'class {class_name}(PluginInterface):'

    content = re.sub(pattern, replacement, content)

    return content

def add_plugin_metadata(content, class_name, plugin_info):
    """Add plugin metadata after class declaration"""
    # Check if metadata already exists
    if 'name =' in content and 'version =' in content:
        return content

    # Find class declaration
    class_pattern = rf'class {class_name}\(PluginInterface\):'
    match = re.search(class_pattern, content)

    if not match:
        return content

    lines = content.split('\n')
    class_line_idx = None

    for i, line in enumerate(lines):
        if f'class {class_name}(PluginInterface):' in line:
            class_line_idx = i
            break

    if class_line_idx is None:
        return content

    # Find the next non-empty, non-comment line after class declaration
    insert_idx = class_line_idx + 1
    while insert_idx < len(lines):
        stripped = lines[insert_idx].strip()
        if stripped and not stripped.startswith('#') and not stripped.startswith('"""') and not stripped.startswith("'''"):
            if not stripped.startswith('name =') and not stripped.startswith('def '):
                break
        insert_idx += 1

    # Add metadata
    metadata = [
        '',
        f'    name = "{plugin_info["name"]}"',
        f'    version = "{plugin_info.get("version", "1.0.0")}"',
        f'    author = "{plugin_info.get("author", "Penetration Test Suite")}"',
        f'    description = "{plugin_info.get("description", "Plugin description")}"',
        f'    category = "{plugin_info["category"]}"',
        f'    requires = {plugin_info.get("dependencies", [])}',
    ]

    lines[insert_idx:insert_idx] = metadata

    return '\n'.join(lines)

def fix_init_method(content, class_name):
    """Fix __init__ to call super().__init__"""
    # Pattern: def __init__(self, ...):
    pattern = r'def __init__\(self,([^)]*)\):'

    def replacement(match):
        params = match.group(1).strip()
        if params:
            # Has parameters
            return f'def __init__(self, config=None, {params}):\n        super().__init__(config)'
        else:
            return 'def __init__(self, config=None):\n        super().__init__(config)'

    content = re.sub(pattern, replacement, content)

    return content

def main():
    for plugin_path in plugins_to_fix:
        full_path = Path(plugin_path)

        if not full_path.exists():
            print(f"[!] File not found: {plugin_path}")
            continue

        print(f"[*] Processing: {plugin_path}")

        # Read plugin.json for metadata
        plugin_json_path = full_path.parent / 'plugin.json'
        plugin_info = {}

        if plugin_json_path.exists():
            import json
            with open(plugin_json_path, 'r') as f:
                plugin_info = json.load(f)

        # Read content
        with open(full_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # Get class name from filename
        class_name = None
        # Try to find class definition
        class_match = re.search(r'class\s+(\w+)(\(.*?\))?:', content)
        if class_match:
            class_name = class_match.group(1)

        if not class_name:
            print(f"  [!] Could not find class name")
            continue

        print(f"  [+] Found class: {class_name}")

        # Apply fixes
        content = add_plugin_interface_import(content)
        content = fix_class_inheritance(content, class_name)

        if plugin_info:
            content = add_plugin_metadata(content, class_name, plugin_info)

        content = fix_init_method(content, class_name)

        # Write back
        with open(full_path, 'w', encoding='utf-8') as f:
            f.write(content)

        print(f"  [✓] Fixed: {plugin_path}")

if __name__ == '__main__':
    main()
    print("\n[✓] All plugins fixed!")
