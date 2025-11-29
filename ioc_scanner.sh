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
