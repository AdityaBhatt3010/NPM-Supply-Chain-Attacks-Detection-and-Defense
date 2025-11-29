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
