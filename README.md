# NPM Supply-Chain Attacks: Detection & Defense ⚠️

Modern JavaScript development moves fast — and so do attackers. Over 2024–2025, the npm ecosystem witnessed one of the most aggressive waves of supply‑chain compromises ever seen. Malicious actors weaponized maintainer accounts, trojanized popular packages, and slipped payloads into install‑time hooks to steal credentials, spread laterally, and quietly backdoor development environments.

This article breaks down **what’s happening**, **how these attacks work**, and — most importantly — **how to detect & mitigate them using practical scripts, IOCs, and CI guards**. The tone here is semi‑formal: technical enough for professionals, clear enough for fast decision‑making. Let’s dive in. 🚀

![npm_Cover (2)](https://github.com/user-attachments/assets/7390836b-f4a5-44ff-924c-f46f80b74f2a) <br/>

---

## 🔥 The New Reality of npm Supply‑Chain Attacks

The past year has fundamentally changed how we trust and consume npm packages. Recent attacks introduced capabilities such as:

* **Install‑time malware** embedded in `preinstall`, `install`, or `postinstall` scripts
* **Obfuscated payloads** using Base64, eval chains, and transpiled JS
* **Credential harvesting** from environment variables, `.npmrc` files, cloud tokens, and GitHub secrets
* **Propagation across dependency graphs**, compromising projects indirectly
* **Worm‑like behavior**, where infected systems publish backdoored packages automatically 😬

In short: **if you run `npm install`, you’re executing untrusted code unless you actively defend against it.**

---

## 🧨 Why These Attacks Are Dangerous

The danger isn’t just that a malicious script runs once — it’s what it can access:

* Developer machines (personal tokens, SSH keys, cloud access)
* CI/CD environments with privileged deploy credentials
* Internal registries and organizational packages
* Production build pipelines

A single malicious dependency can escalate from *"developer inconvenience"* to *"organizational compromise"* within minutes.

---

## 🕵️ Indicators of Compromise (Must‑Know IOCs)

These are the common signatures seen across major 2024–2025 npm attacks:

### Suspicious filenames

* `setup_bun.js`
* `bun_environment.js`
* `postinstall.js` with obfuscated code
* Any newly appearing `install.js`, `setup_*.js`, or similar files

### Suspicious JS patterns

* `eval(` or `eval(atob(...))`
* `Buffer.from(<base64>, 'base64')`
* `child_process.exec()` used for shell commands
* `fetch/curl/wget` inside JS (downloader patterns)
* `process.env.NPM_TOKEN`, `GITHUB_TOKEN`, etc.
* `unlinkSync(` or `rm -rf` (destructive behavior)

### Suspicious config artifacts

* `.npmrc` files *inside node_modules* (huge red flag)
* Unexpected auth tokens in project root or CI logs

If you see **any** of these, treat them as high‑risk.

---

## 🧰 Practical Detection Toolkit (Ready‑to‑Use)

Below is the detection toolkit designed for quick triage and continuous monitoring.

### 1️⃣ Dependency Version & Script Detector (Python)

This script:

* Reads `package.json` and `package-lock.json`
* Flags packages containing install‑time scripts
* Flags suspicious dependency names
* Lists all dependency versions for auditing

👉 Great for local triage or PR validation.

**Script (version_and_script_detector.py):**
```
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
```

### 2️⃣ IOC Scanner (Shell)

This is your **fast threat sweep**:

* Searches for malicious filenames
* Flags eval/base64/exec patterns
* Looks for `.npmrc` tokens
* Extracts sha256 hashes for suspect files

👉 Use this in CI or after a suspected compromise.

**Script (ioc_scanner.sh):**
```
#!/usr/bin/env bash
# ioc_scanner.sh
ROOT=${1:-.}
cd "$ROOT" || exit 1

echo "Scanning for suspicious filenames..."
# suspicious filenames commonly observed
find node_modules -type f -iname "*setup*bun*.js" -o -iname "*bun_environment*.js" -o -iname "*setup_*.js" | sed -n '1,200p'

echo ""
echo "Scanning JS for obfuscation, eval, base64 encodings or child process usage..."
# patterns to search for
PATTERNS=("eval(" "atob(" "Buffer.from(" "child_process.exec" "child_process.spawn" "process.env.NPM_TOKEN" "process.env.GITHUB_TOKEN" "\.npmrc" "unlinkSync(" "rm -rf")
for p in "${PATTERNS[@]}"; do
  echo ""
  echo "-- pattern: $p --"
  grep -RIn --binary-files=without-match -E "$p" node_modules | sed -n '1,200p'
done

# scan .npmrcs in project tree (look for auth tokens)
echo ""
echo "Searching for .npmrc files containing auth tokens..."
grep -RIn --include=".npmrc" "_authToken\|//registry.npmjs.org/:_authToken\|//registry.yarnpkg.com/:_authToken" || true

# quick checksum of suspect files to allow offline whitelist
echo ""
echo "Generating sha256s of top suspicious JS files (first 20 matches)"
grep -RIl --binary-files=without-match -E "eval\(|Buffer.from\(|child_process.exec|atob\(|rm -rf|unlinkSync\(" node_modules | head -n 20 | xargs -r -n1 sha256sum

echo ""
echo "IOC scan complete. Investigate any positive hits. If you find tokens, rotate them immediately."
```

### 3️⃣ YARA Rule for Malicious JavaScript

This rule identifies:

* Obfuscation patterns
* Credential harvesting
* Destructive commands
* Execution of arbitrary shell commands

👉 Works well with large repo scans or node_modules snapshots.

**Script (malicious_js.yara):**
```
rule js_malicious_patterns {
  meta:
    author = "Aditya Bhatt"
    description = "Detect suspicious JS install-time payloads: base64 evals, child_process, token reads"
    version = "1.0"

  strings:
    $eval = /eval\s*\(/
    $atob = /atob\s*\(/
    $buffer = /Buffer\.from\s*\(/
    $child = /child_process\.(exec|spawn|execSync)/
    $npmrc = /_authToken\s*=|:\/_authToken/ 
    $envtoken = /process\.env\.(NPM_TOKEN|NPM_AUTH_TOKEN|GITHUB_TOKEN|GH_TOKEN)/
    $rmrf = /rm\s+-rf|unlinkSync\s*\(/

  condition:
    (any of ($eval, $atob, $buffer) and ($child or $envtoken)) or $npmrc or $rmrf
}
```

### 4️⃣ CI Guardrail (GitHub Actions)

Adds:

* `npm ci --ignore-scripts` (safe mode) ✨
* Automated IOC scanning
* Build blocking on positive hits

👉 Turns insecure dependency installs into a **controlled, observable pipeline.**

**Script (scan-npm.yml):**
```
name: npm-supplychain-scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install minimal Node (no scripts)
        run: |
          curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
          sudo apt-get install -y nodejs
      - name: Install deps without running scripts
        run: npm ci --ignore-scripts
      - name: Run IOC scanner
        run: |
          chmod +x ioc_scanner.sh
          ./ioc_scanner.sh . | tee scanner_output.txt
      - name: Fail on detections
        run: |
          if grep -Ei "SUSPECT|pattern|_authToken|eval\(|child_process\.|rm -rf|unlinkSync\(" scanner_output.txt; then
            echo "Malicious indicators found - failing build"
            exit 1
          else
            echo "No obvious indicators found"
          fi
```

---

## 🛡️ Mitigation Strategy (What You *Must* Do Now)

To survive modern npm attacks:

### 1. **Harden CI/CD**

* Run installs with `--ignore-scripts` unless absolutely necessary
* Use ephemeral CI runners
* Store secrets in dedicated vaults only

### 2. **Enforce Dependency Trust**

* Use lockfiles (`package-lock.json`) religiously
* Prefer minimal dependency trees
* Avoid random GitHub repos as dependencies

### 3. **Protect Tokens & Credentials** 🔐

* Rotate exposed tokens *immediately*
* Use short‑lived, scoped tokens where possible
* Re-publish packages only from clean machines

### 4. **Monitor & Detect Early**

* Run scheduled IOC scans
* Add file‑integrity monitoring (FIM)
* Track new/unknown dependencies after every merge

---

## 🧩 Example Attack Flow (Simplified)

Here’s how most recent npm compromises spread:

1. Attacker phishes or steals maintainer’s npm/GitHub token
2. Publishes a malicious update to a trusted package
3. The update includes a `preinstall` or obfuscated payload
4. Dev & CI machines run `npm install` → malware instantly executes
5. Malware steals tokens → pushes backdoored versions of *other* packages
6. Attack accelerates across organizations ⚠️

This is why we now treat **every package install as untrusted execution.**

---

## 🧭 Final Thoughts

Software supply‑chain security isn’t a "nice to have" anymore — it’s a foundational requirement. With npm attacks becoming more sophisticated, combining obfuscation, credential theft, and lateral propagation, security teams must:

* **Assume compromise is possible**
* **Automate detection**
* **Minimize trust**
* **Respond fast**

A secure pipeline isn’t built on blind trust — it’s built on layered defenses, visibility, and continuous scanning. Stay alert, stay patched, and treat every dependency as a potential attacker until proven safe. 🔥🛡️

---

### 🐾 Follow Me

If you enjoyed this analysis, check out more of my work:

🔗 [GitHub](https://github.com/AdityaBhatt3010) <br/>
💼 [LinkedIn](https://www.linkedin.com/in/adityabhatt3010/) <br/>
✍️ [Medium](https://medium.com/@adityabhatt3010) <br/>

---

### 👋 **Goodbye Note**

Thanks for sticking with me through the article! If you found this analysis helpful or learned something new, do consider following my work — I regularly publish deep-dive writeups, malware analysis breakdowns, and cybersecurity research.
Stay safe, stay curious, stay sharp, and keep hacking *ethically*.
See you in the next one! 🔥 <br/>
~ Aditya Bhatt

---
