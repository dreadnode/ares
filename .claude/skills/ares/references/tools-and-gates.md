# Tool catalog + quality gates

Two halves. **Part 1:** which external binary each red tool actually spawns, how the executor kills it, and how to tell "binary missing" from "tool ran and errored". **Part 2:** the exact local commands that reproduce every required CI check, and which gates are vacuously green.

## Read this first

1. **The binary named in a spawn error is frequently not the tool's namesake.** `crack_with_hashcat` reports `failed to spawn 'nice'` (`ares-tools/src/cracker.rs:101`); `sharpgpoabuse` reports `mono` (`acl.rs:482`); `pth_wmic` reports `pth-wmis` (`lateral/pth.rs:98`); `petitpotam` reports `coercer` (`coercion.rs:101`). None of `nice`/`mono`/`bash`/`python3`/`openssl` is in `tools.yaml`, so worker startup never warns about them.
2. **A missing binary invoked *indirectly* produces no ENOENT and no visible output.** `nice` spawns fine, so a missing `hashcat` yields `nice: 'hashcat': No such file or directory` on stderr and coreutils' command-not-found exit status (127) — and `filter::filter_output` **deletes** any line whose lowercase form contains a `NOISE_MARKERS` entry, including `no such file or directory` and `command not found` (`ares-tools/src/filter.rs:36-41`, `is_noise_line` at `:101-104`, applied at `:114`), so `ToolOutput::combined()` hands the LLM an empty string. Diagnose by exit code 127 + empty output, never by grepping for a spawn error.
3. **Only ENOENT prunes — but the signal is typed, not textual.** `classify_dispatch_error` prefers the `SpawnErrorKind` marker downcast (`tool_executor.rs:401-415`); only `BinaryNotFound` caches and prunes. The string fallback requires **both** `failed to spawn` AND `is it installed?` (`tool_executor.rs:388-390`, `runner.rs:137`), so the hand-rolled `failed to spawn impacket-ntlmrelayx (is it installed?)` (`coercion.rs:604`) caches and prunes too. `transient spawn error for ...` (`executor.rs:381`) must never be "fixed" by installing anything.
4. **A timed-out tool with partial output returns `Ok`, not `Err`** — `exit_code: None`, `success: false`, marker appended to stderr (`executor.rs:444-469`). Code checking `is_err()` misses every partial-output timeout.
5. **Only two status checks block a merge on `main`: `Pre-commit` and `Validate PR title`** — and the required `Pre-commit` job sets `SKIP: cargo-fmt,cargo-clippy,cargo-check,cargo-test`. **No required check compiles, lints, formats, or tests Rust.**
6. **Neither `config/ares.yaml` nor `tools.yaml` is validated by any *required* check, and they fail differently.** `tools.yaml` is read by two `build.rs` scripts that `panic!`, so a malformed edit breaks `cargo build`. `config/ares.yaml` is `include_str!`'d **only inside `#[cfg(test)]`** (`ares-cli/src/orchestrator/strategy.rs:595` opens the test mod, `:858` is the `include_str!`), so a malformed edit breaks `cargo test` / `cargo check --all-targets` but **not** `cargo build` / `cargo check --workspace`. Neither path matches `rust.yaml`'s `paths:` filter nor the cargo hooks' `files: '\.rs$'`.

Routing map: `SKILL.md`. Nearest neighbours: live-op triage → skill `ares-debug`; post-deploy worker restart semantics → `references/deployment.md`.

This file is the authority for the banned-token rule (`#the-banned-token-sweep`, `#test-conventions`) and for the add-a-tool gate list. Other reference files point here rather than restating.

---

## Part 1 — Tool catalog

### How a tool call reaches a binary

`ares_tools::dispatch(tool_name, arguments)` is the single funnel — **122 dispatch names, 123 match arms** including the `_` fallback at `lib.rs:236` (`match tool_name` opens at `ares-tools/src/lib.rs:93`; verified by extraction). Three gates run **before any subprocess**, in this order (`lib.rs:79-81`):

| Gate | Verbatim refusal | Source |
|---|---|---|
| Placeholder credential | `tool '<t>' argument '<k>' has placeholder value <v> — credentials must be resolved from operation state, not invented by the LLM. Check the worker credential resolver and prompt templates.` | `credentials.rs:58-62` |
| Operation scope | `tool '<t>' rejected: target <ip> is not in operation scope (<csv>)` | `scope.rs:133` |
| Irreversible mutation | `refusing to run '<t>': it mutates the target irreversibly and ARES_ALLOW_IRREVERSIBLE_MUTATION is not set.` (message continues — this is the greppable prefix, not the full string) | `mutation.rs:119` |

Scope fires **only on a literal IPv4** in `target`/`target_ip`; CIDRs, comma lists, hostnames and `127.0.0.1` pass through (`scope.rs:115-137`), and an empty `target_ips` is unrestricted (`:66`). No exit code accompanies these — they are `Err` before spawn.

`bloodyad_set_password` is the **only** irreversible tool (`mutation.rs:38`). 26 tools are classified reversible/teardown-eligible (`mutation.rs:45-71`); unknown names classify ReadOnly by design (`mutation.rs:74-78`).

### `tools.yaml` is a build-time manifest, not a runtime table

`tools.yaml` lives at the **workspace root** and is located by both build scripts via `CARGO_MANIFEST_DIR.parent()` (`ares-cli/build.rs:31-34`, `ares-core/build.rs:68-71`). In-repo comments calling it `ares-cli/tools.yaml` (e.g. `ansible/roles/redis/defaults/main.yml:64-65`) are wrong.

- `ares-cli/build.rs` → `$OUT_DIR/tool_tables.rs`, `include!`d by `worker/tool_check.rs:17`. It emits `fn tools_for_role(role: &str) -> &'static [&'static str]` (one match arm per role) plus a `#[cfg(test)]`-gated `WORKER_ROLES` slice — so `WORKER_ROLES` exists only in test builds. This is the worker's startup `which` probe.
- `ares-core/build.rs` → `tool_meta()`, OTel span enrichment (`$OUT_DIR/tool_meta.rs`).
- Both `panic!` on read/parse failure (`ares-cli/build.rs:39`, `:43`; `ares-core/build.rs:76`, `:80`), so a malformed `tools.yaml` breaks the workspace build.
- Editing it changes nothing until you rebuild: `cargo build -p ares-cli -p ares-core`.
- **It installs nothing.** All seven `provisioned_by:` paths resolve to real files in `ansible/playbooks/ares/`, but tool installation in each is delegated to an external `l50.arsenal.<role>_tools` collection role (alongside `dreadnode.nimbus_range.base` and a container-only `cowdogmoo.workstation.build_cleanup`, e.g. `recon.yml:12,16,20`). The manifest therefore drifts from reality with no build failure.
- Its header claim that "docs/red.md will follow automatically" is **false** — the only consumers of `tools.yaml` in the tree are the two `build.rs` scripts and `ares-core/src/telemetry/mitre.rs`; no generator writes `docs/red.md`.

### Roles → playbook → probed binaries (verbatim from `tools.yaml`)

| role | provisioned_by | declared binaries |
|---|---|---|
| `recon` | `ansible/playbooks/ares/recon.yml` | `nmap`, `netexec`, `enum4linux`, `enum4linux-ng`, `rpcclient`, `ldapsearch`, `dig`, `nslookup`, `whois`, `adidnsdump`, `bloodhound-python`, `certipy`, `impacket-GetNPUsers`, `impacket-GetUserSPNs` |
| `credential_access` | `credential_access.yml` | `smbclient`, `rpcclient`, `sprayhound`, `targetedKerberoast`, `lsassy`, `gMSADumper`, `impacket-secretsdump`, `impacket-GetNPUsers`, `impacket-GetUserSPNs` |
| `cracker` | `cracker.yml` | `hashcat`, `john` |
| `acl` | `acl_abuse.yml` | `bloodyAD`, `pywhisker`, `targetedKerberoast`, `rpcclient`, `impacket-dacledit`, `dacledit.py` |
| `privesc` | `privesc.yml` | `certipy`, `lsassy`, `nopac`, `printnightmare`, `printerbug`, `addspn`, `dnstool`, `KrbRelayUp`, `pygpoabuse`, `raiseChild.py`, `impacket-findDelegation`, `impacket-getST`, `impacket-getTGT`, `impacket-rbcd`, `impacket-addcomputer`, `impacket-lookupsid`, `impacket-mssqlclient`, `impacket-ticketer`, `impacket-secretsdump`, `impacket-psexec` |
| `lateral` | `lateral_movement.yml` | `evil-winrm`, `xfreerdp`, `sshpass`, `smbclient`, `rpcclient`, `proxychains4`, `impacket-psexec`, `impacket-wmiexec`, `impacket-smbexec`, `impacket-secretsdump` |
| `coercion` | `coercion.yml` | `responder`, `mitm6`, `coercer`, `petitpotam`, `dfscoerce`, `printerbug`, `addspn`, `dnstool`, `impacket-ntlmrelayx` |

`recon` is the only role with `netexec` — `tools.yaml:39` says so in the `credential_access` notes. The Pass-the-Hash (`tools.yaml:139`) and MSSQL (`:145`) groups under `lateral` declare `binaries: []`, so `tool_check` never probes `impacket-mssqlclient` or the `pth-*` binaries on that image.

**`fn_names` is not the LLM authorization list.** `ares-llm/src/tool_registry/mod.rs:282 tools_for_role` is. Verified divergence: `sharpgpoabuse` and `pygpoabuse_immediate_task` are `tools.yaml` **acl** entries but are offered only to **privesc** (`tool_registry/acl.rs:354-355` carries explicit `NOTE: … not in ACL container` removals).

### Manifest ↔ dispatch drift (computed, not asserted)

- **20 dispatchable tools have no `fn_names` entry**, so `mitre::get_tool_binary` returns `None` (`ares-core/src/telemetry/mitre.rs:332`) and the span records the empty string — `"tool.binary" = tool_binary.unwrap_or("")` (`telemetry/spans/builder.rs:203`, `:260`): `bloodyad_get_object`, `bloodyad_set_object_attr`, `certipy_account_update`, `certipy_ca`, `certipy_esc1_full_chain`, `certipy_esc3_full_chain`, `certipy_esc7_full_chain`, `certipy_esc13_full_chain`, `certipy_find_anon`, `certipy_forge`, `certipy_relay`, `certipy_retrieve`, `esc8_relay_probe`, `forge_inter_realm_and_dump`, `ldap_acl_enumeration`, `mssql_far_host_secretsdump`, `mssql_openquery`, `netexec_auth_check`, `relay_and_coerce`, `smb_login_check`.
- **`raise_child` is the only `fn_name` with no dispatch arm** (`tools.yaml:100`) — calling it returns `unknown tool: raise_child` (`lib.rs:236`).
- `ares-core/build.rs:45-64 select_binary` picks the manifest binary by longest-substring match on the fn name and **falls back to `binaries[0]`**, so `tool_meta()` mislabels several tools (e.g. `kerberoast`/`asrep_roast` report `targetedKerberoast`; the netexec-backed spray tools report `sprayhound`). Never trust `tool.binary` as ground truth.

**Ground truth for what a tool spawns is one grep, not the manifest:**

```bash
rg -n 'CommandBuilder::new\("' ares-tools/src/ -g '!blue' -g '!redact.rs'
```

### Namesake mismatches (verified call sites)

| dispatch tool | binary actually spawned | site |
|---|---|---|
| `crack_with_hashcat` | `nice` (`hashcat` is argv[3]) | `cracker.rs:101` |
| `sharpgpoabuse` | `mono` | `acl.rs:482` |
| `dacl_edit` | `dacledit.py` (manifest declares `impacket-dacledit`) | `acl.rs:587` |
| `targeted_kerberoast` | `targetedKerberoast.py`, or `impacket-GetUserSPNs` when `etype_hint` is given | `acl.rs:399` / `:367` |
| `pth_wmic` | `pth-wmis` | `lateral/pth.rs:98` |
| `petitpotam` | `coercer` | `coercion.rs:101` |
| `smbclient_kerberos_shares` | `smbclient.py` (not the bare `smbclient` in the manifest) | `recon.rs:790` |
| `addspn`, `adminsd_holder_add_ace`, every `bloodyad_*`, `gmsa_read_password_bloodyad` | `bloodyAD` via the shared `credentials::bloodyad_base` helper (3 spawn sites, one per auth branch) | `credentials.rs:261` (`:265`, `:277`, `:287`); callers `acl.rs:52,138,170,205,225,250,552`, `privesc/delegation.rs:422` |
| `gmsa_dump_passwords` | `netexec` | `privesc/gmsa.rs:26` |
| `unconstrained_tgt_dump` | `lsassy` | `privesc/gmsa.rs:45` |
| `unconstrained_coerce_and_capture` | `printerbug` | `privesc/gmsa.rs:68` |
| `forge_inter_realm_and_dump` | `impacket-ticketer`, `python3`, then `nxc` | `privesc/trust.rs:369,418,479` |
| `certipy_esc7_full_chain` | `certipy` ×5 (`:452,468,518,531,569`) plus `openssl` (`:554`) | `privesc/adcs.rs:429` |
| `esc8_relay_probe` | **none** — a reqwest HTTP HEAD to `/certsrv/certfnsh.asp`; `success: ntlm_offered`, i.e. only when `WWW-Authenticate` offers NTLM | `privesc/adcs.rs:1263`, `:1286`, `:1324` |
| `ldap_acl_enumeration`, `enumerate_domain_trusts` | `ldapsearch` on the password/ticket branch, `bash -c 'python3 -c "…impacket…"'` on the NT-hash branch | `enumerate_domain_trusts` `recon.rs:528` (bash `:644`, ldapsearch `:568,649`); `ldap_acl_enumeration` `:816` (bash `:919`, ldapsearch `:843,926`) |

**Declared but never spawned** (installing them fixes nothing; their absence in the startup warning is a red herring): `enum4linux`, `enum4linux-ng`, `nslookup`, `whois`, `sprayhound`, `gMSADumper`, `proxychains4`, `impacket-dacledit`, `raiseChild.py`, `addspn` (the binary), bare `smbclient`, bare `targetedKerberoast`, and `hashcat` (only ever `nice`'s argv).

**Spawned but never declared** (no startup warning, runtime ENOENT only): `bash` (`recon.rs:644,919`), `mono` (`acl.rs:482`), `nice` (`cracker.rs:101`), `nxc` (`privesc/trust.rs:479`), `openssl` (`privesc/adcs.rs:554`), `pkill` (`coercion.rs:545`), `python3` (`privesc/trust.rs:194,418`), `smbclient.py` (`recon.rs:790`), `targetedKerberoast.py` (`acl.rs:399`), `pth-winexe`/`pth-smbclient`/`pth-rpcclient`/`pth-wmis` (`lateral/pth.rs:31,54,76,98`). (`sh`, `cat`, `ls`, `echo` also appear in `CommandBuilder::new` but only inside `executor.rs`'s test module.)

### Binary → what breaks when it is absent

| binary | tools that die | where it must exist |
|---|---|---|
| `netexec` (aliases `nxc` / `NetExec` / `crackmapexec` / `/opt/pipx/venvs/netexec/bin/*`) | `smb_sweep`, `enumerate_users`, `enumerate_shares`, `zerologon_check`, `save_users_to_file`, `password_spray`, `username_as_password`, `password_policy`, `laps_dump`, `gpp_password_finder`, `sysvol_script_search`, `smbclient_spider`, `check_credman_entries`, `check_autologon_registry`, `smb_login_check`, `domain_admin_checker`, `netexec_auth_check`, `gmsa_dump_passwords`, `kerberoast` (fallback path `credential_access/kerberos.rs:87,119`), `forge_inter_realm_and_dump` (as `nxc`) | **recon only** — 13 of these are cross-routed there (the 14th `RECON_ROUTED_TOOLS` entry, `ldap_search_descriptions`, is `ldapsearch`-backed, not netexec) |
| `certipy` | all 16 `certipy_*` tools incl. every ESC full chain (15 spawn `certipy` directly; `certipy_esc4_full_chain` composes three of them) | privesc |
| `bloodyAD` | `addspn`, `adminsd_holder_add_ace`, all `bloodyad_*`, `gmsa_read_password_bloodyad` | acl |
| `impacket-secretsdump` | exactly 7: `secretsdump` (`credential_access/secretsdump.rs:41`), `ntds_dit_extract` (`credential_access/misc.rs:468`), `secretsdump_kerberos` (`lateral/execution.rs:334`), `mssql_far_host_secretsdump` (`lateral/mssql.rs:572`), `certipy_esc13_full_chain` (`privesc/adcs.rs:1001`), `certipy_esc1_full_chain` (`:1178`), `extract_trust_key` (`privesc/trust.rs:76`) | credential_access, lateral, privesc |
| `impacket-ticketer` | `generate_golden_ticket` (`privesc/delegation.rs:113`), `generate_silver_ticket` (via `build_silver_ticket_command` `:198`), `create_inter_realm_ticket` (`privesc/trust.rs:148`), `forge_inter_realm_and_dump` (`:369`) | privesc |
| `impacket-mssqlclient` | all 11 `mssql_*` tools — one shared `mssql_base` helper (`lateral/mssql.rs:28`) | privesc (declared); lateral declares `binaries: []` |
| `impacket-ntlmrelayx` | `ntlmrelayx_to_ldaps`/`_adcs`/`_smb` (`coercion.rs:170,192,214`), `ntlmrelayx_multirelay` (`:1190`), `relay_and_coerce` (raw `TokioCommand` at `:604`) | coercion |
| `coercer` | `coercer` **and** `petitpotam` | coercion |
| `nice` | `crack_with_hashcat` | cracker — not in `tools.yaml` |
| `mono` | `sharpgpoabuse` | not in `tools.yaml` for any role |
| `python3` + importable `impacket` **package** | `create_inter_realm_ticket`, `forge_inter_realm_and_dump`, NT-hash branches of `ldap_acl_enumeration` / `enumerate_domain_trusts` | not declared; a pipx-only impacket fails here with `ModuleNotFoundError`, not ENOENT |
| `pth-winexe` / `pth-smbclient` / `pth-rpcclient` / `pth-wmis` | the four `pth_*` tools | **nowhere** — deliberately omitted (`passing-the-hash` is gone on Debian trixie); these tools are expected to fail |
| `which` | **everything** — startup inventory probes with `which <binary>` (`ares-cli/src/worker/tool_check.rs:89-97`) | every worker image |

`netexec` is the **only** program with alias fallback: `netexec`, `nxc`, `NetExec`, `/opt/pipx/venvs/netexec/bin/NetExec`, `/opt/pipx/venvs/netexec/bin/netexec`, `crackmapexec`, tried in order (`resolve_program_alias`, `executor.rs:73-87`). Every other program is spawned verbatim — `resolve_program_alias` returns `None` and the OS does the resolving (`executor.rs:267-273`).

`first_resolvable` (`executor.rs:90-117`) walks `$PATH` per bare candidate and accepts only what `std::fs::metadata()` resolves; metadata follows symlinks, so a self-referential/broken `netexec` symlink is skipped in favour of the next alias. If **no** candidate resolves it falls back to `self.program` and the spawn ENOENTs normally. The OTel span is named after the **resolved** program: `exec.<resolved>` (`executor.rs:282`).

### Cross-role routing

14 tools are forced onto the **recon** queue regardless of the calling agent's role (`RECON_ROUTED_TOOLS`, `ares-cli/src/orchestrator/tool_dispatcher/mod.rs:72-86`; `resolve_queue_role` at `:328-334`): `ldap_search_descriptions`, `password_spray`, `username_as_password`, `gpp_password_finder`, `sysvol_script_search`, `password_policy`, `laps_dump`, `smbclient_spider`, `check_credman_entries`, `check_autologon_registry`, `smb_login_check`, `domain_admin_checker`, `gmsa_dump_passwords`, `netexec_auth_check`.

**Symptom: a credential_access spray is nowhere in `credential_access.log`.** Cause: it ran on the recon worker. Fix: read `/var/log/ares/recon.log`. If the recon worker is down these calls hang on `ares.tools.exec.recon` rather than failing with a missing binary.

### Executor lifecycle, timeouts, kill semantics

| Property | Value | Source |
|---|---|---|
| Default timeout | **120 s** — a tool that never calls `.timeout_secs()` inherits it | `executor.rs:13` (`DEFAULT_TIMEOUT`) |
| On timeout | `child.kill()` (SIGKILL), then `join_readers` gives **each** reader up to 2 s to hit EOF before aborting it — two readers, so the worst-case post-kill tail is ~4 s, not 2 | `executor.rs:18` (`READER_DRAIN_GRACE`), `:445`, `:558-568` |
| Backstop | `cmd.kill_on_drop(true)` on every child (tokio's default leaves it running) | `executor.rs:361` |
| Child stdin | `Stdio::null()` unless `.stdin(data)` — prompting tools see EOF instead of blocking to the deadline | `executor.rs:351-355` |
| Pipes | drained by two spawned tasks into `Arc<Mutex<Vec<u8>>>` so a full pipe never stalls the deadline | `executor.rs:408-416` |
| Output sanitation | all C0 controls except `\n \t \r` stripped (null bytes break OpenAI-compatible JSON) | `executor.rs:614-623` |
| Global spawn cap | 20, `ARES_MAX_CONCURRENT_TOOLS`; permit taken in `execute()` and held for the whole spawn+wait | `concurrency.rs:73-86`, acquired at `executor.rs:263` |
| spider_plus cap | 4, `ARES_SPIDER_PLUS_CONCURRENCY`; acquired in `dispatch()` **outside** the global permit | `concurrency.rs:31-43`, `lib.rs:87-92` |
| hashcat job pool | 2, `ARES_MAX_CONCURRENT_HASHCAT` | `concurrency.rs:118-130` |
| AES-Kerberoast permit | **1, hardcoded, no env override** | `concurrency.rs:152` |
| Per-worker in-flight cap | 3, `ARES_WORKER_CONCURRENCY` | `ares-cli/src/worker/tool_executor.rs:87` |
| Orchestrator reply wait | **95 min** (`DEFAULT_TOOL_TIMEOUT_SECS = 95 * 60`) | `tool_dispatcher/mod.rs:68` |

Redaction is fail-closed (`ares-tools/src/redact.rs`). Twelve `SECRET_FLAGS` (`:17-29`, incl. `-hashes`, `-nthash`, `-aesKey`, `-password`, `-pfx`, `-computer-pass`, `-U`, `-w`) plus two `AMBIGUOUS_FLAGS` (`:32`: `-p`, `-H` — treated as secret because `-p` is a password to netexec and a port spec to nmap) mask the following argument wholesale, unless the call site declared the arg index visible via `flag_visible`. `-U` is the sole `IDENTITY_BEARING_FLAGS` entry (`:99`) and keeps the identity while masking the secret half. A missing value in a logged command line is policy, not corruption.

### Missing binary vs tool ran and errored — decision table

| Failure | Verbatim string | Result shape | Caches? Prunes? |
|---|---|---|---|
| ENOENT | `failed to spawn '<prog>' — is it installed?` (**em-dash U+2014**; `<prog>` is the *requested* name, not the alias-resolved one) | `Err` + typed `SpawnErrorKind{NotFound}` | **yes / yes** |
| Any other spawn errno (EAGAIN/ENOMEM/EMFILE/EACCES) | `transient spawn error for '<prog>' (<ErrorKind>): <e>` | `Err` + `SpawnErrorKind{other}` | no / no |
| ntlmrelayx spawn (raw `TokioCommand`, no typed marker) | `failed to spawn impacket-ntlmrelayx (is it installed?)` — **parens, no quotes, no em-dash** | `Err` | yes / yes, via the string fallback — and it poisons the tool name `relay_and_coerce` |
| Timeout, zero stdout **and** stderr | `command timed out after <Duration:?>: <redacted cmd>` (renders like `120s`) | `Err` | no / no |
| Timeout, partial output | stderr gains `ARES_TOOL_TIMED_OUT_AFTER_SECS=<n>`; `failure_message()` renders `tool timed out after <n>s — partial output was preserved and parsed` | **`Ok`**, `exit_code: None`, `success: false` | no / no |
| Non-zero exit | `tool exited with code <Option<i32>>` | `Ok`, `success: false` | no / no |
| `child.wait()` itself errored | `command execution failed: <e>` | `Err` | no / no |
| No dispatch arm | `unknown tool: <name>` | `Err` | no / no |

Sources: `executor.rs:378` (ENOENT), `:381` (transient), `:443` (`command execution failed`), `:451-453` (`command timed out after`), `:482` (`TIMEOUT_MARKER_PREFIX`), `:513` (`tool timed out after`), `:515` (`tool exited with code`); `coercion.rs:604`; `lib.rs:236`.

```bash
# Genuine ENOENT — the ONLY wording that caches and prunes
grep -a "is it installed?" /var/log/ares/*.log

# NOT a missing binary. Do not install anything.
grep -a 'transient spawn error for' /var/log/ares/*.log

# Killed at the deadline but still returned parseable output (Ok, success:false)
grep -a 'ARES_TOOL_TIMED_OUT_AFTER_SECS=' /var/log/ares/*.log

# Silent hang — the Err variant of a timeout
grep -a 'command timed out after' /var/log/ares/*.log

# Worker-startup which-probe result (fields: role, missing)
grep -a 'Some tools are not installed' /var/log/ares/*.log
```

The typed marker is attached **before** the human-readable context and must be recovered with `downcast_ref` (which walks contexts), never `err.chain()` (which only walks `source()`):

```rust
// ares-tools/src/executor.rs:388-392
.context(SpawnErrorKind { io_kind }).context(msg)
```

The string fallback deliberately requires **both** substrings so tool output merely mentioning "failed to spawn" cannot prune a working tool (`ares-llm/src/agent_loop/runner.rs:130-137`; regression tests `legacy_worker_string_fallback_still_prunes_enoent` `:1263`, `string_fallback_requires_both_substrings` `:1277`, `typed_kind_authoritative_over_error_string` `:1295`).

### The worker's ENOENT cache

Not a permanent `HashSet` — a `HashMap<String, UnavailableEntry>` with exponential re-probe backoff **60 s → 300 s → 1800 s → 4 h** (final rung is a cap), because "Deploys don't restart workers" (`ares-cli/src/worker/tool_executor.rs:351-372`). One successful spawn removes the entry outright (`:592-601`).

```bash
grep -a 'Skipping tool cached as ENOENT'  /var/log/ares/*.log   # fields: failures=, remaining_secs=
grep -a 'Tool binary not found (ENOENT)'  /var/log/ares/*.log   # fields: failures=, cooldown_secs=
grep -a 'Tool spawn succeeded'            /var/log/ares/*.log   # the self-heal event
redis-cli get ares:tools:ares-recon-agent                        # published AVAILABLE-only inventory, TTL 3600s
```

Key format is `ares:tools:{agent_name}` where `agent_name = format!("ares-{}-agent", role.replace('_', "-"))` (`worker/tool_check.rs:70`, `worker/config.rs:108`). An absent key is indistinguishable from a dead worker.

**Cache keying traps.** The skip-check reads `request.tool_name` (pre-rename) while mark/clear use `effective_tool_name` (post credential-resolver `*_kerberos` rename), so `psexec` and `psexec_kerberos` hold independent entries (`tool_executor.rs:520` vs `:596`/`:664`). The cache is keyed per **tool name**, not per binary — one missing `bloodyAD` poisons four `bloodyad_*` entries with four separate backoff clocks.

**Symptom: `preflight_tool_check` always reports lateral's critical tools missing plus `No tool inventory found — worker may not be running`.** Cause: `CRITICAL_TOOLS` uses the role string `lateral_movement` (`ares-cli/src/orchestrator/monitoring.rs:445`) and builds `ares:tools:ares-lateral-movement-agent` (`:492`), but workers publish under `lateral` (`ansible/roles/redis/defaults/main.yml:66-73`). Nothing writes that key. Treat lateral preflight output as noise.

**Symptom: startup's `which` probe reports a binary present but calls still ENOENT.** The startup inventory and the executor use different resolvers: `tool_check::is_in_path` shells out to `which` (`tool_check.rs:89-97`), while the executor's netexec alias walk accepts a bare name only if `std::fs::metadata` on the `$PATH`-joined path succeeds (`executor.rs:104-113`). They can disagree on a symlink one of them refuses to follow. This asymmetry exists **only for the netexec alias set** — every other program is handed to `Command::spawn` verbatim.

### Other verbatim strings worth grepping

| String | Meaning | Source |
|---|---|---|
| `Tool '<t>' is not installed on this worker. Do not call this tool again — it failed to spawn previously.` | cached skip; the binary was never probed on this call | `tool_executor.rs:334-337` |
| `[SYSTEM] The following tools have been removed and are no longer available: …` | runner pruned tools mid-task (ENOENT or per-tool call-limit) | `runner.rs:685-688` |
| `Tool binary not found (ENOENT from worker) — removing from available tools for the rest of this task` | orchestrator-side prune | `runner.rs:608` |
| `RELAY_BIND_BUSY` | loopback lock port `RELAY_LOCK_PORT` = 41445 (`coercion.rs:683`) held, or TCP 445 still occupied after `pkill` | `coercion.rs:145` (single-tool path), `:748`, `:787` |
| `RELAY_BIND_FAILED` | ntlmrelayx died inside the 3 s settle window | `coercion.rs:818` |
| `CERT_CAPTURED_VIA=` / `PFX_FILE=` / `RELAYED_USER=` | ESC8 capture success markers | `coercion.rs:959-963` |
| `missing required argument: <field>` | field absent **or** present with the wrong JSON type — an LLM passing `port: 445` as a number gets this | `args.rs:4-8` |
| `malformed NTLM hash argument (<n> chars)` | guard against a bad hash being bound as cleartext | `credentials.rs:236-240` |

### Execution env vars

| Var | Default | Effect |
|---|---|---|
| `ARES_WORKER_ROLE` (fallback `ARES_ROLE`) | **required** — worker exits `ARES_WORKER_ROLE (or ARES_ROLE) is required` | sets the NATS queue, the per-role log file, and `agent_name = format!("ares-{}-agent", role.replace('_', "-"))` → the `ares:tools:{agent_name}` key (`worker/config.rs:100-102`, `:108`) |
| `ARES_TOOL_DISPATCH` | unset (remote) | `local` makes `preflight_tool_check` probe the local `$PATH` with `which` instead of reading `ares:tools:*` from Redis (`orchestrator/monitoring.rs:476`, `:480-486`) |
| `ARES_MAX_CONCURRENT_TOOLS` | 20 | global spawn cap; values <1 ignored |
| `ARES_SPIDER_PLUS_CONCURRENCY` | 4 | `smbclient_spider` + `sysvol_script_search` only |
| `ARES_MAX_CONCURRENT_HASHCAT` | 2 | hashcat crack-job pool |
| `ARES_WORKER_CONCURRENCY` | 3 | per-worker in-flight tool cap |
| `ARES_ALLOW_IRREVERSIBLE_MUTATION` | unset (off) | `1\|true\|yes\|on` (trimmed, lowercased) permits `bloodyad_set_password` (`mutation.rs:94-103`) |
| `ARES_OPERATION_ID` | unset | JSON envelope's `target_ips[]` becomes the scope allowlist; unset/plain-string = unrestricted (`scope.rs:40`) |
| `ARES_HASHCAT_WORKLOAD` | `3` (`cracker.rs:85`) | hashcat `-w`; the cracker box sets 4 |
| `ARES_HASHCAT_NICE` | `-15` (`cracker.rs:70`) | `nice -n` adjustment |
| `ARES_KEEP_POTFILE` | unset | exactly `1\|true\|TRUE` opts out of cross-op potfile truncation (`cracker.rs:433-438`) |
| `ARES_KEEP_WORKSPACE` | unset | exactly `1\|true\|TRUE` skips **all** workspace sanitation (`sanitize.rs:37-42`) |
| `HASHCAT_SERVICE_URL` / `HASHCAT_TOKEN` | unset | non-empty URL delegates to remote crackd; the token then becomes mandatory — `HASHCAT_SERVICE_URL is set but HASHCAT_TOKEN is missing` (`cracker/remote.rs:38`, `:44-45`) |
| `ARES_KERBEROS_TIME_OFFSET_SECS` | n/a | **INERT** — `ares-tools/src/kerberos_skew.rs` exists (`SKEW_ENV_VAR` at `:31`) but is never declared as a module in `lib.rs:7-27`, and nothing else in the tree references it. Fix the range clock, not the env var. |

### Tests that gate tool-catalog edits

```bash
cargo test -p ares-cli   --bin ares worker::tool_check   # per-role tool tables
cargo test -p ares-tools --lib      mutation             # every_classified_tool_is_dispatchable
```

**`cargo test -p ares-cli --lib …` does not work.** `ares-cli` has no library target — `Cargo.toml` declares only `[[bin]] name = "ares"` and there is no `src/lib.rs`, so the command dies with `error: no library targets found in package 'ares-cli'` before compiling anything. Use `--bin ares`. (`cargo metadata` target kinds: `ares-core` lib, `ares-cli` **bin only**, `ares-llm` lib + 1 example + 2 integration tests, `ares-tools` lib + 1 integration test.)

`every_classified_tool_is_dispatchable` (`mutation.rs:240-247`) is a unit test, not a build-time check: it `include_str!("lib.rs")`s the dispatcher and asserts `"<tool>" =>` appears for every name in `IRREVERSIBLE_TOOLS` + `REVERSIBLE_TOOLS`. It fails `cargo test` (and the `cargo-test` pre-commit hook) — **which CI skips** — never `cargo build`.

### Adding a tool — the full gate list

Those two commands are necessary and **not sufficient**. Four requirements have no test at all; a green PR can still ship a tool that is unchoosable by the LLM, never torn down, or permanently uncreditable to blue.

| # | Requirement | Failure if skipped | Where |
|---|---|---|---|
| 1 | Dispatch arm in `ares_tools::dispatch` **and** an entry in `ares_llm::tool_registry` | Dispatchable but never advertised ⇒ the LLM cannot choose it. Live today: `addspn`, `bloodyad_get_object`, `certipy_find_anon`, `dnstool`, `esc8_relay_probe`, `forge_inter_realm_and_dump`, `netexec_auth_check`. Inverse: `tools.yaml:100` advertises `raise_child` with no dispatch arm. Only `certipy_*_full_chain` is auto-guarded | `references/hard-won-lessons.md` |
| 2 | `tools.yaml` `fn_names` entry if the role expects the binary | two `build.rs` scripts `panic!` on malformed YAML ⇒ `cargo build` breaks | Part 1 above |
| 3 | If it mutates the target: **all three** of `mutation.rs` `REVERSIBLE_TOOLS` (26), `journal.rs` `MUTATING_TOOLS` (18), `registry.rs` match arms (18) | nine tools are currently gated reversible but never journalled ⇒ teardown silently never happens. **No test asserts parity** | `references/hard-won-lessons.md` |
| 4 | If it stamps a MITRE ID via `TOOL_TO_TECHNIQUE` (`ares-core/src/telemetry/mitre.rs:73`): confirm `detections.yaml` carries that ID or its parent | a stamped ID with no matching `mitre_id` is a **permanent blue miss** — the scorecard is an exact-or-parent/child ID join. Zero occurrences in `ares-core/src/detection/detections.yaml` today for `T1187`, `T1068`, `T1222.001`, `T1484.001`, `T1518.001`, `T1556.006`, `T1136.002` (all stamped at `mitre.rs:138-148`) | `references/blue-team.md` |

Then run:

```bash
cargo test -p ares-cli   --bin ares worker::tool_check
cargo test -p ares-tools --lib      mutation
cargo test -p ares-cli   --bin ares result_processing::timeline   # every_emitted_technique_is_coverable_by_the_blue_catalog
```

The third is `ares-cli/src/orchestrator/result_processing/timeline.rs:478`. **None of these three is a required check** — only `Pre-commit` and `Validate PR title` block a merge, and the `Pre-commit` job SKIPs `cargo-test`.

---

## Part 2 — Quality gates

### What actually blocks a merge

Ruleset `main: required checks` (id `17234731`), enforcement `active`. Verified live against `l50/ares`:

```
required_status_checks:
  - context: Pre-commit
  - context: Validate PR title
strict_required_status_checks_policy: false
+ non_fast_forward
```

Classic branch protection is absent (`branches/main/protection` → 404). **Never infer required checks from workflow files:**

```bash
gh api repos/l50/ares/rulesets && gh api repos/l50/ares/rulesets/17234731
```

The one required code-quality job **skips every Rust check**:

```yaml
# .github/workflows/pre-commit.yaml:137
SKIP: cargo-fmt,cargo-clippy,cargo-check,cargo-test
```

A PR can therefore merge with broken clippy, unformatted code, or failing tests.

### Reproduce every required check locally

```bash
# Byte-for-byte what the required job scopes and skips
SKIP=cargo-fmt,cargo-clippy,cargo-check,cargo-test \
  pre-commit run --all-files --show-diff-on-failure

# The full hook set, without CI's autoupdate side effects
pre-commit run --all-files --show-diff-on-failure

# One hook
pre-commit run goad-token-sweep --all-files
pre-commit run actionlint --all-files
```

Both mutate the working tree — `markdownlint --fix`, `shfmt -w`, `prettier --write`, `end-of-file-fixer`, `trailing-whitespace`, `docsible` all rewrite in place. A "failed" run usually means "files were rewritten"; re-run and it passes.

**Do not run `task -y --timeout=60s run-pre-commit` locally** (the literal CI command, `pre-commit.yaml:138`) unless you are debugging the wrapper. The root `Taskfile.yaml:271-277` chains `pre-commit:update-hooks` → `pre-commit:clear-cache` → `pre-commit:run-hooks`. Those three live in the remote CowDogMoo `pre-commit/Taskfile.yaml` include (`Taskfile.yaml:13-15`) and are, verbatim: `pre-commit autoupdate` (`:33` — rewrites every `rev:` pin), `pre-commit clean` (`:14` — wipes `~/.cache/pre-commit`, so the next run re-downloads every env), and `pre-commit run --all-files --show-diff-on-failure` (`:19`). CI therefore never validates the pinned revs renovate maintains, and a fresh upstream hook release can turn the required check red with zero repo changes.

**`--timeout=60s` is go-task's remote-Taskfile *download* timeout, not a run cap** — `task --help`: `--timeout duration   Timeout for downloading remote Taskfiles. (default 10s)`.

### The Rust gate: CI vs hook

| Check | CI (`.github/workflows/rust.yaml`) | pre-commit hook (`.pre-commit-config.yaml`) | Same? | Required? |
|---|---|---|---|---|
| format | `cargo fmt --all -- --check` (`:131`) | same (`:89`) | identical | no (SKIPped) |
| clippy | `cargo clippy --workspace --all-targets -- -D warnings` (`:159`) | same (`:96`) | **identical** — unified 2026-06-28; any note claiming a split is stale | no (SKIPped) |
| compile | `cargo check --workspace` (`:66`) | `cargo check --all-targets` (`:103`) | **DIFFERENT** — hook is the superset. Root manifest is virtual with no `default-members`, so all 4 members are selected either way; `--all-targets` additionally builds `ares-llm`'s `smoke_test` example and `integration_agent_loop` / `span_regressions` tests, `ares-tools`' `loki_retry_budget` test, and every `#[cfg(test)]` unit-test target | no (SKIPped) |
| tests | `cargo llvm-cov --workspace --lcov --output-path lcov.info` (`:99`) — the only failing form; the second `cargo test --workspace 2>&1 \|\| true` summary step (`:114`) can never fail | `cargo test` (`:110`) | same **scope** (virtual manifest ⇒ `cargo test` selects all 4 members), different runner and different failure surface | no (SKIPped) |
| toolchain | `dtolnay/rust-toolchain@…# stable` (floats) | whatever `cargo` resolves; `mise.toml` pins `rust = "1.94.0"` | **DIFFERENT** — there is no `rust-toolchain.toml` | — |

Gate with the strongest form plus the toolchain CI actually uses:

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo +stable clippy --workspace --all-targets -- -D warnings   # toolchain parity
cargo check --workspace && cargo check --all-targets
cargo test --workspace
```

Five workspace clippy lints are hard-`deny` in `[workspace.lints.clippy]` (`Cargo.toml:5-22`): `too_many_arguments`, `manual_let_else`, `needless_collect`, `redundant_clone`, `derive_partial_eq_without_eq`. All four members opt in with `[lints] workspace = true` (`ares-core/Cargo.toml:56`, `ares-cli:56`, `ares-llm:34`, `ares-tools:33`), so these fire as errors even without `-D warnings`.

### Path filters and gates that can go vacuously green

- **`rust.yaml`'s `paths:` filter is `['ares-*/**', 'Cargo.toml', 'Cargo.lock', '.github/workflows/rust.yaml']`** (identical on `pull_request` and `push`). It omits both `config/ares.yaml` and `tools.yaml`, and both also miss the cargo hooks' `files: '\.rs$'`. The two break differently:
  - **A `tools.yaml`-only change gets a green PR and can break `cargo build` on main** — both `build.rs` scripts `panic!` on read/parse.
  - **A `config/ares.yaml`-only change gets a green PR and can break `cargo test` / `cargo check --all-targets`** — it is `include_str!`'d only inside `#[cfg(test)]` (`strategy.rs:595` opens the mod, `:858` is the `include_str!`), so `cargo build` / `cargo check --workspace` still pass.
- **Every `pull_request`-triggered workflow gates on `branches: [main, feat/more-attack-cov]`** (pre-commit, rust, semgrep, semantic-prs, validate-templates, test-template-builds). A stacked PR based on any other branch runs zero checks and still reads mergeable, because `strict_required_status_checks_policy` is `false`. (`meta-labeler.yaml` uses `pull_request_target` on `main` only and is not a check.)
- **`test-template-builds.yaml` has only a `pull_request` trigger** (no `push:`, no `merge_group:`) and its `paths:` filter is `warpgate-templates/**` / `ansible/**` / `.github/workflows/test-template-builds.yaml` (`:13-16`), while its matrix comes from `git diff --name-only origin/$base...HEAD -- warpgate-templates/templates/` (`:51`). Touching only `warpgate-templates/README.md` fires the workflow, yields no changed templates, and emits `base_matrix={"include":[]}` (`:104`) — a green run that builds nothing.
- **`Validate PR title` is required but has no `merge_group:` trigger** (`semantic-prs.yaml` is `pull_request` + `workflow_dispatch` only), unlike `pre-commit`/`rust`/`semgrep`/`validate-templates`. Enabling a merge queue on `main` would deadlock on that context. No `merge_queue` rule exists in the ruleset today.
- **The JSON-schema step of Validate Templates is `continue-on-error: true`** (`validate-templates.yaml:183`) — cosmetic.
- **`detect-secrets` scans zero files.** `pass_filenames: false` with only `--baseline` (`.pre-commit-config.yaml:68-70`), and `main()` iterates `args.filenames` (`Yelp/detect-secrets@v1.5.0`, `detect_secrets/pre_commit_hook.py:28-30`) — an empty list. It can never flag a new secret.
- **`prettier` selects nothing.** `types: [json, yaml]` is an **AND** in pre-commit and no file is both. Observed: `pre-commit run prettier --all-files` → `Run prettier ... (no files to check) Skipped`.
- **`codespell` skips `README.md`, but NOT `.github/`.** Empirically tested with the repo's exact flag string: an explicitly-passed `.github/workflows/x.yaml` containing a common misspelling **is** flagged; `README.md` is not. Cause: `--skip` entries are `fnmatch`ed against the whole passed path (`codespell_lib/_codespell.py:168`, file-list branch `:1327`), and `.github` never matches `.github/workflows/x.yaml`. The dir-skip only works in walk mode (`:1289`), which pre-commit never uses — it passes explicit filenames. Net: workflow typos **are** caught; only the top-level `README.md` is structurally uncatchable.
- **Semgrep is advisory, not required.** Its `SEMGREP_RULES` is a `>-` folded scalar (`semgrep.yaml:51-58`) collapsed into a single space-separated string and interpolated as one `--config="${SEMGREP_RULES}"` argument (`:63`). Never cite a green Semgrep run as security evidence.
- **`go install mvdan.cc/sh/v3/cmd/shfmt@latest`** (`pre-commit.yaml:78`) is the one unpinned tool in the required job — audited: every `uses:` in that workflow is 40-hex SHA-pinned and `@latest` appears exactly once. A new shfmt release can reformat the tree and turn the required check red with zero repo changes.

### Pre-commit hook catalog (26 hooks, execution order)

| id | effective command / args | selector | mutates? |
|---|---|---|---|
| `check-added-large-files` | `--maxkb=10240` | all | no |
| `check-case-conflict`, `check-merge-conflict`, `check-json`, `check-symlinks`, `check-yaml`, `detect-private-key` | defaults | per type | no |
| `end-of-file-fixer`, `trailing-whitespace` | defaults | all | **YES** |
| `yamllint` | `yamllint --strict -c .hooks/linters/yamllint.yaml` (`:21`) | yaml | no |
| `actionlint` | upstream `entry: actionlint`, no repo args (runner labels come from `.github/actionlint.yaml`) | upstream `types: ["yaml"]` + `files: ^\.github/workflows/` | no |
| `codespell` | `codespell -q 3 -f --skip=".git,.github,README.md,target,Cargo.lock" --ignore-words-list="astroid,braket,unstall,infinit,sems,te,hel"` (`:32`) | text | no |
| `script-must-have-extension` | this repo overrides the upstream `types: [shell, non-executable]` with `types: [shell]` (`.pre-commit-config.yaml:39`), so **executable shell scripts are checked too — `chmod +x` does not bypass it** | shell, `exclude: '\.tmpl$'` | no |
| `shellcheck` | `shellcheck -e SC1091 <files>` — the `-e SC1091` comes from the **upstream** manifest (`args: [-e, SC1091]`), not this repo's config | shell, `exclude: '\.tmpl$'` (`:42`) | no |
| `shfmt` | upstream wrapper runs `shfmt -w $*` — it rewrites, never diff-checks; it "fails" only because pre-commit then sees modified files | shell, `exclude: '\.tmpl$'` (`:44`) | **YES** |
| `markdownlint` | upstream `entry: markdownlint` + repo `args: ['--fix', '--config', '.hooks/linters/markdownlint.json']` (`:50`) | upstream `types: [markdown]` | **YES** |
| `ansible-lint` | `env -u GIT_INDEX_FILE ansible-lint -v --force-color -c .hooks/ansible/ansible-lint.yaml` — the `env -u` prefix is load-bearing (ansible-galaxy otherwise corrupts the commit-time index) | `^ansible/` | no |
| `detect-secrets` | `--baseline .secrets.baseline`, `pass_filenames: false` | — | **VACUOUS** |
| `goad-token-sweep` | `scripts/goad-token-sweep.sh <files>`, `types: [text]` | all text | no |
| `cargo-fmt` / `cargo-clippy` / `cargo-check` / `cargo-test` | see the Rust-gate table | `\.rs$`, `pass_filenames: false` | no — **all four SKIPped in CI** |
| `prettier` | `.hooks/prettier.sh` → `prettier --write` | `types: [json, yaml]` | **VACUOUS** |
| `docsible` | `.hooks/ansible/docsible-hook.sh` | `^ansible/` | **YES** |
| `update-architecture-diagram` | `python .hooks/ansible/gen-arch-diagram.py` | `^ansible/(roles/\|plugins/\|playbooks/).*` | **YES** |

Reproduce the two whose real args are not in this repo's config:

```bash
shellcheck -e SC1091 <files>
shfmt -d <files>          # -d diffs; the hook uses -w and rewrites
```

### The banned-token sweep

```bash
scripts/goad-token-sweep.sh                       # whole tree — enumerates `git ls-files`
scripts/goad-token-sweep.sh path/a.rs path/b.md   # specific files — the form pre-commit uses
```

Exit 0 clean; exit 1 prints `BLOCKED: DreadGOAD lab tokens or test placeholders found.` plus `file:line:match` on stderr. Runs `set -uo pipefail` **without `-e`** (`:21`) — load-bearing, so grep's exit 1 on no-match does not abort the script. Matching is a single case-insensitive `grep -HniE` (`:59`), which is why the generic-word lab passwords are deliberately omitted: they collide with ordinary identifiers such as the `needle` variables in the tree (`:17-19`).

Five regex vars (`names`, `leaks`, `placeholders`, `ips`, `passwords`, `:23-27`) OR'd into one `banned` pattern (`:29`): GOAD character/domain names, the kali workgroup leak, generic test placeholders, three non-lab private-range IP patterns (each anchored to a **full four-octet address**, `:26`), and real GOAD account passwords. Exempt paths at `:36`, extension filter at `:38`. Read the script for the literals — do not copy them anywhere else.

**Three enforcers, three regexes, three exempt lists. They are out of sync:**

| | `scripts/goad-token-sweep.sh` (commit hook) | `.claude/hooks/check-banned-strings.sh` (PreToolUse on Write/Edit) |
|---|---|---|
| IP patterns | all three anchored to a full four-octet address (`:26`) — no false-positive on a three-part version string | `10\.1\.` is four-octet anchored, but `10\.0\.` and `172\.16\.` are **bare prefixes** (`:50`) — those two **do** false-positive on three-part version strings that begin with those octets (the sweep script's own `:26` comment is the reference; do not reproduce the literal here — this file is itself scanned) |
| Extensions | only `.rs .tera .py .md .yaml .yml .toml .json .sh` (`:38`) | any path; greps the payload being written, not the file on disk (`:52`) |
| Trigger | staged files at commit time; `git ls-files` in whole-tree mode | `Write` and `Edit` only — every other tool exits 0 at `:15-25` |
| `.claude/` | exempt as a whole directory (`:36`) | **NOT exempt** — bypass is a hardcoded path-literal `case` list (`:34`) naming only `.claude/hooks/check-banned-strings.sh` and `.claude/agents/dreadgoad-expert.md` |

A third copy lives in `.claude/CLAUDE.md`'s self-check grep, which matches the Write hook's unanchored IPs and excludes `*.sh`.

**The Write hook is operator-local and untracked.** `.gitignore:31-35` ignores `.claude/*` and un-ignores only `agents/` and `skills/**`, so `.claude/hooks/` is excluded — `git ls-files .claude` confirms it is not tracked. It is wired at `.claude/settings.json:10` as a bare command path, which requires the exec bit; at HEAD the file is mode 644. **Verify before treating it as live enforcement:** `test -x .claude/hooks/check-banned-strings.sh`. On a checkout without it, the *only* enforcement is the commit-time sweep.

**Symptom: a Write into `.claude/skills/**` is blocked even though the commit sweep exempts all of `.claude/`.** Cause: the PreToolUse hook's bypass list is path-literal, not directory-wide. Fix: use only the allowed example values below.

**This skill directory is doubly unswept.** `scripts/goad-token-sweep.sh:36` exempts all of `.claude/`, *and* whole-tree mode enumerates `git ls-files` (`:41-47`) while `.claude/skills/ares/**` is untracked at HEAD (`git ls-files .claude` lists only the three agents and the `ares-debug` / `attack-path-diversity-sweep` skills). Only the PreToolUse hook has ever looked at these files, so anything arriving by `cp`/`mv`/`rsync` was never scanned at all.

**Passing the paths explicitly does not help** — the exempt filter at `:52` runs on `"$@"` too, so the candidate list empties and the script exits **0 vacuously** (verified). Borrow its regex instead:

```bash
bash -c 'eval "$(sed -n "23,29p" scripts/goad-token-sweep.sh)"; grep -rHniE "$banned" .claude/skills/ares/'
# no output = clean (grep exits 1); any output = a token to fix
```

**Coverage holes.** A token in a `.j2`, `.tmpl`, `.txt`, Dockerfile or extensionless file passes both enforcers — the ansible jinja templates are a live blind spot. Whole-tree mode uses `git ls-files` (`:41-47`), so **untracked files are never scanned**; at commit time pre-commit passes only **staged** files.

### Test conventions

Allowed values only. Anything else is a violation and the PreToolUse hook blocks the write.

| Kind | Allowed |
|---|---|
| Domains | `contoso.local`, `fabrikam.local` (and `child.*` subdomains) |
| IPs | `192.168.58.x` only |
| Hostnames | `dc01`, `dc02`, `sql01`, `web01`, `ws01`, `ca01` |
| Users | `alice`, `bob`, `carol`, `admin`, `svc_*` |
| Password | `P@ssw0rd!` |

```rust
Target { ip: "192.168.58.10".into(), domain: "contoso.local".into(), ..Default::default() }
Host { ip: "192.168.58.240".into(), hostname: "dc01.contoso.local".into(), is_dc: true, ..Default::default() }
Credential { username: "alice".into(), password: "P@ssw0rd!".into(), domain: "contoso.local".into(), ..Default::default() }
```

The literal lab name `dreadgoad` is allowed — it is the `TARGET=` value, not a loot token.

### PR title gate

The `pull_request` path uses `amannn/action-semantic-pull-request`; the `workflow_dispatch` path is a hand-rolled grep (`semantic-prs.yaml:41`). Reproduce the second:

```bash
echo "<pr title>" | grep -Eq '^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)(\([^)]+\))?!?: .+' \
  && echo OK || echo FAIL
```

### Deploy-side gotchas that masquerade as gate failures

- **`ec2:deploy` bounces only `--state=active` `ares@*` units; `ec2:restart` bounces none** — full semantics in `references/deployment.md`. The gate-relevant part: `SKIP_RESTART` matches the literal string `true` (`.taskfiles/ec2/Taskfile.yaml:250`, `:447`; default `"false"` at `:134`) — `SKIP_RESTART=1` does **not** match. Any note telling you to follow a deploy with `ec2:restart` to clear the per-process ENOENT cache is inverted.
- **`task init` fails**: `Taskfile.yaml:267` calls `pre-commit:install`, but the remote taskfile exposes only `install-pc-hooks`, `clear-cache`, `run-hooks`, `run-pre-commit`, `update-hooks` — there is no `install`.

### UNVERIFIED

- Whether Semgrep's folded `--config` string actually causes a no-op scan in practice. The YAML shape (`semgrep.yaml:51-63`) was read; **the CI run logs were not**. Treat "Semgrep is vacuous" as plausible-but-unconfirmed; what *is* confirmed is that Semgrep is not a required check.
- Per-tool timeouts were extracted mechanically for ~100 of the 122 dispatch arms; tools whose `CommandBuilder` is built in a helper (all `mssql_*`, all `bloodyad_*`, `secretsdump*`, `certipy_request`/`_find`/`_shadow`/`_ca`) were not individually confirmed. Read the impl fn before relying on one number. The 120 s default (`executor.rs:13`) always applies when `.timeout_secs()` is absent.
- The `codespell` skip result was reproduced against a locally installed codespell **2.4.2**; the pinned hook rev is **v2.4.3**. The `GlobMatch`/`fnmatch` logic is identical in the cached upstream source, so the conclusion should hold, but it was not re-run under the exact pinned env.
- Per-hook mutation flags (`markdownlint --fix`, `shfmt -w`, `prettier --write`, `end-of-file-fixer`, `trailing-whitespace`, `docsible`) are read from each hook's entry/wrapper. A full `pre-commit run --all-files` was **not** executed, so the claim "a failed run usually means files were rewritten" is mechanism-derived, not observed.
