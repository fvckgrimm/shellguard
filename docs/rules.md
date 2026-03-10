# shellguard Rule Pack Reference

Rule packs are YAML files that define patterns shellguard looks for when scanning scripts and commands. The format is inspired by [Nuclei templates](https://docs.projectdiscovery.io/templates/) and [semgrep rules](https://semgrep.dev/docs/writing-rules/rule-syntax/).

---

## File Structure

```yaml
# Required metadata
id: my-rules                     # Unique identifier for this pack (no spaces)
name: "My Rules"                 # Human-readable name
version: "1.0.0"                 # Semantic version
description: "What this detects" # Brief description
author: "your-name"              # Author

# Optional: pack-level tags
tags:
  - custom
  - my-org

rules:
  - ...
```

---

## Rule Fields

```yaml
rules:
  - id: my-001             # Required. Unique within pack. Conventional: <pack>-<NNN>
    name: "Rule Name"      # Required. Short human-readable name
    description: "..."     # Required. What this detects
    severity: high         # Required. critical | high | medium | low | info
    tags:                  # Required. At least one tag
      - my_category
    enabled: true          # Optional. Set false to disable without deleting

    match:                 # Required. How to match
      ...

    context:               # Optional. Additional match conditions
      ...

    remediation: "..."     # Optional. How to fix or avoid this
    references:            # Optional. Links to CVEs, writeups, docs
      - https://...
```

---

## Match Modes

### `regex` — Single regular expression

```yaml
match:
  mode: regex
  pattern: 'bash\s+-i\s+>&\s*/dev/tcp/'
```

Tested against each line of the content. Line number is reported.

### `multi_regex` — Multiple patterns

```yaml
match:
  mode: multi_regex
  logic: all    # "all" = AND (all must match), "any" = OR (any match triggers)
  patterns:
    - 'kubectl'
    - 'privileged.*true'
```

With `logic: all`, the rule fires only if all patterns match (anywhere in the content).
With `logic: any`, the rule fires if any pattern matches.

### `keyword` — Case-insensitive substring search

```yaml
match:
  mode: keyword
  keywords:
    - "DROP TABLE"
    - "TRUNCATE"
```

Fires if any keyword is found anywhere in the content.

### `keywords_any` — Same as `keyword`

```yaml
match:
  mode: keywords_any
  keywords:
    - "DAN mode"
    - "jailbreak mode"
```

### `keywords_all` — All keywords must appear

```yaml
match:
  mode: keywords_all
  keywords:
    - "kubectl"
    - "cluster-admin"
    - "ClusterRoleBinding"
```

All keywords must appear somewhere in the content for the rule to fire.

---

## Regex Flags

```yaml
match:
  mode: regex
  pattern: 'password\s*=\s*\S+'
  flags:
    - case_insensitive   # (?i) — default for most patterns
    - multiline          # (?m) — ^ and $ match line boundaries
    - dotall             # (?s) — . matches newlines
```

---

## Negate

Fire when the pattern does NOT match (useful for enforcing required patterns):

```yaml
- id: best-001
  name: "Missing set -e"
  description: "Bash scripts should use set -e for error handling"
  severity: info
  tags: [best_practice]
  match:
    mode: regex
    pattern: 'set\s+-e'
    negate: true
```

---

## Context Conditions

Optional guards that must also be satisfied for the rule to fire:

```yaml
match:
  mode: regex
  pattern: 'eval\s+'

context:
  require_any:    # At least one of these must also match (anywhere in content)
    - '\$\('
    - '\$\{'

  require_all:    # All of these must match
    - 'bash'

  exclude_any:    # Do NOT fire if any of these match
    - '^\s*#'     # Skip comment lines
    - 'eval\s+"[^"]*"\s*$'  # Skip simple string evals
```

---

## Severity Levels

| Level | When to use |
|-------|-------------|
| `critical` | Guaranteed malicious or destructive: reverse shells, disk wipes, fork bombs |
| `high` | Strongly suspicious: supply chain attacks, credential theft, obfuscation |
| `medium` | Worth reviewing: world-writable permissions, downloading to /tmp |
| `low` | Noteworthy but common in legitimate scripts: sudo usage, firewall changes |
| `info` | Best practice violations, style issues |

---

## Tagging Convention

Use standard tag names for consistency:

| Tag | Used for |
|-----|---------|
| `reverse_shell` | Reverse/bind shell patterns |
| `destructive` | Commands that destroy data |
| `priv_esc` | Privilege escalation |
| `credential_theft` | Stealing credentials |
| `credential_exposure` | Hardcoded or leaked credentials |
| `obfuscation` | Encoded/obfuscated payloads |
| `supply_chain` | Remote script execution |
| `persistence` | Surviving reboots/logouts |
| `anti_forensics` | Covering tracks |
| `network_scan` | Reconnaissance |
| `data_exfiltration` | Sending data out |
| `c2` | Command & control |
| `prompt_injection` | AI manipulation |
| `cloud` | Cloud provider patterns |
| `kubernetes` | K8s-specific |
| `containers` | Container security |
| `best_practice` | Non-security quality issues |

---

## Complete Example

```yaml
id: github-actions
name: "GitHub Actions Security Rules"
version: "0.2.0"
description: "Detects dangerous patterns in GitHub Actions workflows"
author: "your-org"
tags:
  - custom
  - ci_cd
  - github

rules:
  - id: gha-001
    name: "Untrusted Input in run: step"
    description: "Using github.event.* inputs directly in run: steps enables script injection"
    severity: critical
    tags: [supply_chain, script_injection]
    match:
      mode: regex
      pattern: 'run:\s*.*\$\{\{\s*github\.event\.(issue\.title|pull_request\.title|head_commit\.message)'
    remediation: |
      Never use untrusted GitHub context values directly in run: steps.
      Use an intermediate environment variable:
        env:
          TITLE: ${{ github.event.issue.title }}
        run: echo "$TITLE"
    references:
      - https://securitylab.github.com/research/github-actions-untrusted-input/

  - id: gha-002
    name: "pull_request_target with Checkout"
    description: "Checking out code from a fork in pull_request_target gives it access to secrets"
    severity: high
    tags: [supply_chain]
    match:
      mode: multi_regex
      logic: all
      patterns:
        - 'pull_request_target'
        - 'actions/checkout'
    references:
      - https://securitylab.github.com/research/github-actions-preventing-pwn-requests/

  - id: gha-003
    name: "Hardcoded Secret in env:"
    description: "A secret value appears to be hardcoded in a workflow env: block"
    severity: critical
    tags: [credential_exposure]
    match:
      mode: regex
      pattern: '(API_KEY|SECRET|TOKEN|PASSWORD|PASSWD)\s*:\s*[A-Za-z0-9/+=_-]{16,}'
      flags: [case_insensitive]
    remediation: "Use ${{ secrets.MY_SECRET }} instead of hardcoding values."
```

---

## Validation

```bash
# Validate a single file
shellguard rules validate my-rules.yaml

# Validate a directory
shellguard rules validate ./rules/

# Scaffold a new pack
shellguard rules new my-pack --dir ./rules/custom/
```

---

## Loading Custom Packs

Add to your config (`shellguard config set rules.custom_dirs ...`):

```yaml
rules:
  custom_dirs:
    - ~/my-org-rules
    - /etc/shellguard/rules
```

Or load for a single scan:

```bash
shellguard scan -f script.sh --rule-packs my-rules,another-pack
```
