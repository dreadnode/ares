# Branch Review: `fix/blue-detection-gaps`

## Blocking

### B1. `ares-tools` unconditionally forces `ares-core/blue` -- FIXED

`ares-tools/Cargo.toml` had `ares-core = { path = "../ares-core", features = ["blue"] }` — unconditional.
Since `ares-worker` and `ares-orchestrator` both depend on `ares-tools`, Cargo feature unification
meant they got `blue` forced on regardless of their own feature flags.

Fixed: removed unconditional features, wired `blue = ["ares-core/blue"]` in `[features]`.

---

## Significant

### S1. Unnecessary `Box::leak` — data is already `'static` -- FIXED

Both `detection/mod.rs` (`leak_str()`) and `lateral/patterns.rs` (`Box::leak(conn_type.clone()...)`)
leaked heap-allocated strings unnecessarily. The underlying data lives inside `OnceLock<DetectionConfig>`
which is already `'static`.

Fixed: eliminated `leak_str()` function and all `Box::leak` calls, use `.as_str()` instead.

### S2. `templates_for_connection_type()` has 43 lines of hardcoded match arms -- FIXED

Adding a new connection type to YAML required updating Rust match arms. Defeated YAML-driven goal.

Fixed: added `connection_types: Vec<String>` field to `TemplateEntry`, annotated 20 templates in YAML,
rewrote function to a 5-line filter.

### S3. Dual source of truth for MITRE technique IDs -- FIXED

`mitre_for_connection_type()` inserted hardcoded values before YAML enrichment, so YAML could never
override.

Fixed: YAML templates iterated first (authoritative), hardcoded values are fallbacks only via `or_insert`.

### S4. Wrong MITRE IDs on new templates -- FIXED

| Template | Was | Now |
|---|---|---|
| `detect_mssql_linked_server` | T1021.006 (WinRM) | T1210 (Exploitation of Remote Services) |
| `detect_mssql_xp_cmdshell` | T1059.001 (PowerShell) | T1059 (Command and Scripting Interpreter) |
| `detect_delegation_abuse` | T1134.001 (Token Theft) | T1098 (Account Manipulation) |

### S5. `detect_s4u_delegation` exclude pattern overly broad -- FIXED

`'TransmittedServices.{0,20}-'` false-excluded events with hyphenated SPNs.

Fixed: narrowed to `'TransmittedServices\s*:\s*-\s*$'` (only matches empty/placeholder field).

### S6. `detect_brute_force` refactor: `host_as_filter` may cause false negatives -- FIXED

Windows 4625 events don't reliably embed source computer name in log body. The `computer=~` label
selector already handles host filtering.

Fixed: set `host_as_filter: false`.

---

## Minor

### M1. Loki retry doc comment wrong -- FIXED

Said "(1s, 2s, 4s)" implying 4 attempts. Actually 3 attempts, 2 retries, delays 1s and 2s.

Fixed: corrected doc comment.

### M2. Retry on 429 without `Retry-After` -- FIXED

Fixed: extract `Retry-After` header before consuming response body. When present, use it as the
retry delay instead of exponential backoff. Falls back to normal backoff when header is absent.

### M3. `resp.text().await?` on retryable status -- FIXED

Body read failure now treated as retryable (continues retry loop instead of propagating).

### M4. `detect_mass_share_enumeration` overlaps with `detect_share_enumeration` -- FIXED

No rate/count threshold means a single `smbclient` invocation fires both.

Fixed: set `auto_pivot: false` on `detect_mass_share_enumeration` to prevent noise flooding. The
template still fires for detection, but won't auto-trigger pivot investigations without the LLM
explicitly choosing to investigate.

### M5. `investigation/write.rs` still uses `{job="windows"}` and hostname-as-line-filter -- FIXED

Pre-existing inconsistency: suggested queries used wrong job label and hostname as line filter.

Fixed: `track_host_investigation()` now uses `{job="windows-security", computer=~"{hostname}"}` (and
`windows-system` for service installation events 7045/4697). `track_user_investigation()` now uses
`{job="windows-security"}` with username as line filter (correct — usernames appear in event body).

### M6. `[build-dependencies]` pins `serde_yaml = "0.9"` inline -- FIXED

Changed to `{ workspace = true }`.

### M7. No test coverage for retry logic, lateral_patterns YAML loading, or brute_force query -- FIXED

Added `lateral_patterns_load_from_yaml` and `brute_force_no_host_line_filter` tests.
Retry logic test skipped (requires mocking HTTP client, out of scope for this fix).
