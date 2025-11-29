#!/usr/bin/env python3
"""
version_and_script_detector.py
Usage: python3 version_and_script_detector.py [path-to-project]
Scans package.json and package-lock.json and prints suspicious entries.
"""
import json
import sys
from pathlib import Path

SUSPECT_NAMES = ["setup-bun", "setup_bun", "bun-environment", "node-setup", "secure-install"]

def load_json(path):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Failed to load {path}: {e}")
        return None

def scan_project(root):
    root = Path(root)
    pkg = load_json(root / 'package.json')
    lock = load_json(root / 'package-lock.json') or load_json(root / 'npm-shrinkwrap.json')

    if not pkg and not lock:
        print("No package.json or lockfile found.")
        return

    print("\n=== Top-level scripts in package.json ===")
    if pkg and 'scripts' in pkg:
        for name, cmd in pkg['scripts'].items():
            if 'install' in name or 'post' in name or 'pre' in name:
                print(f"[WARN] script: {name} -> {cmd}")
    else:
        print("No scripts in package.json")

    deps = {}
    if lock and 'dependencies' in lock:
        deps = lock['dependencies']
    elif pkg and 'dependencies' in pkg:
        deps = pkg.get('dependencies', {})

    print('\n=== Dependency summary ===')
    for name, meta in deps.items():
        version = meta.get('version') if isinstance(meta, dict) else meta
        print(f"{name} @ {version}")
        # quick heuristic: suspicious name
        for s in SUSPECT_NAMES:
            if s in name:
                print(f"  [SUSPECT-NAME] {name} matches {s}")
        # check if package has "scripts" field in lockfile metadata
        if isinstance(meta, dict):
            scripts = meta.get('scripts') or meta.get('script')
            if scripts:
                print(f"  [SCRIPTS] {name} declares scripts: {scripts}")

    print('\nDone. Review the WARN/SUSPECT lines; if anything looks odd, run IOC scanner on node_modules and revoke tokens if found.')

if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else '.'
    scan_project(target)
