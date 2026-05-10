<!-- markdownlint-disable MD013 -->

# Attack Strategy Configuration

Controls which attack techniques the operator prioritises, how it handles
Domain Admin achievement, and whether alternative paths are explored or
ignored.

## Quick Reference

| Goal | Config |
|------|--------|
| Reproduce the fast deterministic path (default) | `strategy: fast` or omit entirely |
| Explore all discovered attack paths | `strategy: comprehensive` |
| Avoid noisy techniques (spray, secretsdump) | `strategy: stealth` |
| Force ADCS-only path | `exclude_techniques: [secretsdump, dc_secretsdump]` + `technique_weights: {esc1: 1}` |
| Force ACL chain path | `exclude_techniques: [secretsdump, dc_secretsdump, mssql_access]` + `technique_weights: {acl_abuse: 1}` |
| Keep exploiting after DA | `continue_after_da: true` |

## How It Works

Every attack technique has a **weight** (1-10, lower = higher priority). When
multiple vulnerabilities are discovered simultaneously, the one with the lowest
weight gets exploited first. This is what makes the operator deterministic --
the same weight ordering produces the same attack path every time, given the
same environment.

Weights are set in three layers, each overriding the previous:

```text
Preset defaults  (fast / comprehensive / stealth)
       ↑ overridden by
YAML config      (config/ares.yaml → operation.technique_weights)
       ↑ overridden by
JSON payload     (per-operation technique_weights in ARES_OPERATION_ID)
       ↑ overridden by
Env vars         (ARES_STRATEGY, ARES_EXCLUDE_TECHNIQUES, etc.)
```

For most use cases, the YAML config is the only layer you need.

## Configuration

All strategy settings live under `operation:` in `config/ares.yaml`:

```yaml
operation:
  # Named preset -- sets default weights for all techniques.
  # Options: fast (default), comprehensive, stealth
  strategy: fast

  # Keep exploiting after Domain Admin is achieved.
  # comprehensive preset sets this automatically.
  continue_after_da: false

  # Techniques to completely exclude (never dispatch).
  exclude_techniques: []

  # If non-empty, ONLY these techniques are allowed (allowlist mode).
  # Everything else is suppressed.
  include_techniques: []

  # Per-technique priority overrides (1 = highest, 10 = lowest).
  # Merged on top of the preset defaults.
  technique_weights:
    # secretsdump: 2
    # esc1: 5
```

### Strategy Presets

#### `fast` (default)

Shortest path to Domain Admin. Prioritises secretsdump and trust escalation.
This is what produces the deterministic kerberoast → secretsdump → trust key →
MSSQL → Golden Ticket chain. (For the concrete chain shape against the GOAD
lab, see `docs/goad-checklist.md`.)

| Technique | Weight | Effect |
|-----------|--------|--------|
| dc_secretsdump | 1 | Fires immediately when DA hash is available |
| golden_ticket | 1 | Forged as soon as krbtgt is extracted |
| forest_trust_escalation | 1 | Cross-forest via trust key |
| child_to_parent | 1 | ExtraSid escalation |
| secretsdump | 2 | Hash dump on any host with admin creds |
| credential_reuse | 3 | Cross-domain hash reuse |
| mssql_access | 4 | MSSQL linked server pivots |
| password_spray | 4 | Username-as-password + common passwords |
| kerberoast | 5 | SPN-based hash extraction |
| asrep_roast | 5 | No-preauth account hash extraction |
| esc1 / esc4 / esc8 | 5 | ADCS certificate abuse |
| constrained_delegation | 5 | S4U2Self/S4U2Proxy |
| unconstrained_delegation | 5 | TGT capture via coercion |
| rbcd | 6 | Resource-based constrained delegation |
| acl_abuse | 6 | AD ACL chain exploitation |
| smb_signing_disabled | 7 | NTLM relay via unsigned SMB |

Because secretsdump (weight 2) fires before ADCS (weight 5) or delegation
(weight 5), the fast path always wins the priority race. ADCS and delegation
vulns are *discovered* but never *exploited* because DA is achieved first.

#### `comprehensive`

All techniques have equal weight (3). The operator exploits everything it
finds, in whatever order discoveries arrive. `continue_after_da` is
automatically set to `true`.

Use this when you want to:

- Validate that all attack paths work end-to-end
- Maximise coverage for a security assessment report
- Test defenses against techniques that the fast path skips

Per-cycle dispatch limits are also raised (2 -> 10 per technique category)
so multiple domains get work in parallel.

#### `stealth`

Suppresses noisy techniques. Prefers ADCS and ACL paths over secretsdump and
password spraying.

| Technique | Weight | Rationale |
|-----------|--------|-----------|
| esc1 / esc4 | 1 | Certificate abuse is quiet |
| acl_abuse | 1 | ACL changes don't trigger most alerts |
| constrained_delegation | 2 | Kerberos-only, low noise |
| unconstrained_delegation | 2 | Coercion is brief |
| credential_reuse | 3 | Single auth attempt per target |
| dc_secretsdump | 6 | Secretsdump is loud |
| secretsdump | 7 | Very loud -- deprioritised |
| password_spray | 8 | Lockout risk, high log volume |
| smb_signing_disabled | 8 | Relay is noisy on the wire |

## Technique Filtering

### Exclude List

Completely blocks listed techniques from being dispatched. Useful for forcing
the operator down alternative paths or honouring rules of engagement.

```yaml
operation:
  exclude_techniques:
    - secretsdump
    - dc_secretsdump
    - password_spray
```

With secretsdump excluded, the operator is forced to find DA through ADCS,
delegation, ACL abuse, or MSSQL paths instead.

### Include List (Allowlist Mode)

If non-empty, **only** the listed techniques are allowed. Everything else is
suppressed. More restrictive than exclude.

```yaml
operation:
  include_techniques:
    - esc1
    - esc4
    - esc8
    - acl_abuse
```

This would restrict the operator to ADCS and ACL paths only.

### Available Technique Names

These are the `vuln_type` strings used in exclude/include lists and weight
keys:

| Technique | Description |
|-----------|-------------|
| `secretsdump` | Hash dump on member servers |
| `dc_secretsdump` | Hash dump on domain controllers |
| `golden_ticket` | Kerberos golden ticket forgery |
| `forest_trust_escalation` | Cross-forest trust key exploitation |
| `child_to_parent` | ExtraSid child-to-parent escalation |
| `credential_reuse` | Cross-domain hash reuse |
| `mssql_access` | MSSQL service exploitation |
| `mssql_linked_server` | MSSQL linked server pivoting |
| `mssql_impersonation` | MSSQL EXECUTE AS escalation |
| `constrained_delegation` | S4U2Self/S4U2Proxy abuse |
| `unconstrained_delegation` | TGT capture via coercion |
| `rbcd` | Resource-based constrained delegation |
| `esc1` | ADCS ESC1 (enrollee supplies SAN) |
| `esc4` | ADCS ESC4 (template owner can modify) |
| `esc8` | ADCS ESC8 (HTTP enrollment + relay) |
| `acl_abuse` | AD ACL chain exploitation |
| `kerberoast` | SPN-based hash extraction |
| `asrep_roast` | AS-REP roasting (no-preauth accounts) |
| `password_spray` | Password spraying / username-as-password |
| `gmsa` | Group Managed Service Account extraction |
| `smb_signing_disabled` | NTLM relay via unsigned SMB |

## Completion Modes

These interact with strategy but are configured separately:

```yaml
operation:
  # Stop immediately when Domain Admin is achieved (any domain).
  # stop_on_domain_admin: true

  # Stop after golden ticket is forged AND all forests are dominated.
  # This is stricter -- requires full trust chain completion.
  stop_on_golden_ticket: true

  # Keep exploiting after DA. Overrides the above.
  # comprehensive preset enables this automatically.
  # continue_after_da: true
```

`stop_on_domain_admin` and `stop_on_golden_ticket` are mutually exclusive.
If both are false (default), the operation runs until all forest root DCs are
secretsdumped.

`continue_after_da` overrides both stop conditions. When true, the operator
keeps discovering and exploiting vulnerabilities even after DA is achieved.

## Examples

### Default (deterministic fast path)

```yaml
operation:
  # strategy: fast is the default -- you can omit it entirely
```

### Full coverage assessment

```yaml
operation:
  strategy: comprehensive
  # continue_after_da is automatically true
```

### ADCS-focused assessment

```yaml
operation:
  strategy: fast
  exclude_techniques:
    - secretsdump
    - dc_secretsdump
    - mssql_access
    - mssql_linked_server
  technique_weights:
    esc1: 1
    esc4: 1
    esc8: 2
    acl_abuse: 2
```

### Stealth engagement

```yaml
operation:
  strategy: stealth
  exclude_techniques:
    - password_spray
    - smb_signing_disabled
```

### Delegation-only path

```yaml
operation:
  include_techniques:
    - constrained_delegation
    - unconstrained_delegation
    - rbcd
    - kerberoast
    - asrep_roast
  technique_weights:
    constrained_delegation: 1
    unconstrained_delegation: 1
    rbcd: 2
```

## LLM Temperature

Controls how creative the LLM is when selecting techniques. Higher values
make the agent more likely to try unusual approaches.

```yaml
operation:
  llm_temperature: 1.2   # more creative (default: provider default, ~1.0)
```

This is passed directly to the LLM provider. The strategy weights still
control what the automation modules dispatch -- temperature only affects
the LLM's own reasoning about which tools to call within a task.

## LLM System Prompt

The strategy weight table is rendered dynamically into the LLM system prompt.
When weights are configured, the "ATTACK FALLBACK CHAINS" section shows the
active priority ordering instead of the hardcoded default table. This ensures
the LLM's technique selection reasoning aligns with the operator's strategy.

## Environment Variable Overrides

For per-operation overrides without changing the YAML config:

| Variable | Purpose |
|----------|---------|
| `ARES_STRATEGY` | Preset name (fast / comprehensive / stealth) |
| `ARES_EXCLUDE_TECHNIQUES` | Comma-separated technique blocklist |
| `ARES_INCLUDE_TECHNIQUES` | Comma-separated technique allowlist |
| `ARES_CONTINUE_AFTER_DA` | `1` or `true` to keep exploiting after DA |
| `ARES_LLM_TEMPERATURE` | LLM temperature (0.0-2.0) |

Env vars take highest precedence, overriding both JSON payload and YAML config.

These can also be passed in the JSON operation payload:

```json
{
  "operation_id": "op-20260421",
  "target_domain": "contoso.local",
  "target_ips": ["192.168.58.10"],
  "strategy": "comprehensive",
  "technique_weights": {"esc1": 1, "secretsdump": 8},
  "exclude_techniques": ["password_spray"],
  "continue_after_da": true
}
```

## Relationship to vulnerability_priorities

The YAML config has a legacy `vulnerability_priorities` section that predates
the strategy system. These priorities are still read and merged into the
strategy weights as the lowest-precedence layer:

```text
Preset defaults
  ↑ vulnerability_priorities (legacy YAML section)
  ↑ operation.technique_weights (new YAML section)
  ↑ JSON payload
  ↑ env vars
```

For new deployments, use `operation.technique_weights` instead.
`vulnerability_priorities` is kept for backwards compatibility.
