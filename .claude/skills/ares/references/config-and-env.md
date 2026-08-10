# Config + environment

Two config surfaces exist and they do not agree: `config/ares.yaml` (12 sections deserialized into `AresConfig`) and ~120 distinct `ARES_*` env vars (134 distinct `"ARES_*"` literals in the Rust tree, minus the 5 JetStream stream names and 9 `ARES_TEST_*` fixtures — `rg --no-filename -o '"(ARES_[A-Z0-9_]+)"' -r '$1' -g '*.rs' -g '!target' . | sort -u | wc -l`). Most of the YAML is parsed and never read; the env vars carry different defaults than the YAML values they look like they shadow. Know which is which before you change anything.

## The seven things that cost the most

1. **Most of `config/ares.yaml` is dead.** Only `operation.*` (partly), `agents.<role>.{model,max_steps}`, `timeouts.operation_timeout`, `vulnerability_priorities`, and `observability.*` reach the runtime. `recovery` and `context_management` are parsed and then only printed; `phase_detection`, `resources`, `security`, `logging` and `grafana.{base_url,api_key}` are parsed and never read *or* printed — `config show` emits only `grafana.enabled` and `grafana.dashboard_uid` (`ares-cli/src/config.rs:139-143`). Editing any of them changes nothing.

2. **There is no `deny_unknown_fields` anywhere in the config module** (`rg deny_unknown_fields ares-core/src/config/` → zero hits). A misspelled key parses clean and silently no-ops. The crate's own fixture ships a bogus `capabilities:` key under an agent block to prove it (`ares-core/src/config/mod.rs:169`; `AgentConfig` has no such field, `sections.rs:100-106`).

3. **One bad field disables the whole YAML layer, silently — but not models.** `AresConfig::from_env()` failure is non-fatal: `Err(e) => { info!("No YAML config loaded (using env vars only): {e}"); None }` (`ares-cli/src/orchestrator/mod.rs:94-97`). Strategy preset, technique weights, all four diversity knobs, `acl_publish_cap` and `operation_timeout` revert to code defaults — while per-role models keep working, because they come from a *second, independent* raw parse. Grep startup for `Loaded YAML config` vs `No YAML config loaded` to tell which happened.

4. **`ARES_LLM_MODEL` does NOT change worker models.** It only supplies the orchestrator/fallback spec. Per role: `read_role_model(yaml_doc.as_ref(), yaml_key).unwrap_or_else(|| orch_spec.clone())` (`mod.rs:521-522`). Every one of the 7 worker roles has a `model:` in the shipped YAML, so `ARES_LLM_MODEL` alone leaves them untouched. **The YAML is the only per-role model lever.**

5. **Model resolution reads the YAML a second time, with a different path fallback.** `std::env::var("ARES_CONFIG").unwrap_or_else(|_| "/ares/config/ares.yaml".to_string())` (`mod.rs:481-487`) — it never consults `DEFAULT_PATHS`. On a box where the config sits at `./config/ares.yaml` with `ARES_CONFIG` unset, `AresConfig` loads fine (max_steps, acl cap, timeouts apply) but every role collapses onto one model — or the op aborts with `No LLM model configured — set ARES_LLM_MODEL or agents.orchestrator.model in config YAML`.

6. **The shipped `vulnerability_priorities` block DEMOTES work the `comprehensive` preset ranked urgent**, because every merged weight is `.clamp(1, 10)` (`strategy.rs:136,140`). The tiers above 10 (11/12/13/14/15/20/21/50) all collapse to a single tie at 10. `kerberoast` 2→10, `password_spray` 2→10, `shadow_credentials` 1→10, `gpo_abuse` 1→10.

7. **`timeouts.operation_timeout: 3600` halves the built-in fallback.** It is the only live timeout key; absent or `0`, the code uses 7200s (`mod.rs:903-907`).

## Where the config file lives

Resolution order (`ares-core/src/config/mod.rs:20-24, 84-105`):

| # | Path | Notes |
|---|---|---|
| 1 | `$ARES_CONFIG` | If set and the file **does not exist**, load hard-fails with `ARES_CONFIG points to {path} but the file does not exist` — it does not fall through (`mod.rs:86-92`) |
| 2 | `./config/ares.yaml` | Repo checkout / local CLI |
| 3 | `/ares/config/ares.yaml` | K8s pods |
| 4 | `/etc/ares/config.yaml` | EC2 box |

The doc comment above `from_env` (`mod.rs:70-75`) lists only three paths and omits `/ares/config/ares.yaml` — it is stale.

| Deployment | Path on box | How it gets there | `ARES_CONFIG` exported? |
|---|---|---|---|
| local CLI | `./config/ares.yaml` | in repo | root Taskfile var `ARES_CONFIG: ./config/ares.yaml` (`Taskfile.yaml:120`) — but see the trap below |
| K8s orch + red workers | `/ares/config/ares.yaml` | `task k8s:sync:config` (`kubectl cp`, `.taskfiles/k8s/Taskfile.yaml:100,110`) | **Not set by anything in this repo** — there are no in-tree manifests (`fd -t d -H 'k8s\|kubernetes\|manifests' --max-depth 2` → only `.taskfiles/k8s/`; `rg --hidden ARES_CONFIG -g '*.yaml'` hits only Taskfiles), so the pod falls back to default path #3, which is also the model-lookup fallback. Confirm on a live pod before relying on it |
| K8s ConfigMap | key `config.yaml` in cm `ares-config` | `task remote:rust:deploy:config` (`.taskfiles/remote/Taskfile.yaml:800-812`) | n/a |
| EC2 (`kali-ares`) | `/etc/ares/config.yaml` | `task ec2:deploy:config` via S3 (`.taskfiles/ec2/Taskfile.yaml:465-497`; `ARES_REMOTE_CONFIG` at `:66`) | Yes — `export ARES_CONFIG=/etc/ares/config.yaml` (`launch-orchestrator.sh.tmpl:41`, `.taskfiles/ec2/Taskfile.yaml:1329`) |

**Trap: the root Taskfile has no `env:` block** (`rg '^env:' Taskfile.yaml` → no match) and the `config:*` tasks pass no `--config` flag (`Taskfile.yaml:433-449`). Setting `ARES_CONFIG` as a *task var* therefore does nothing to `task config:models` / `config:set-model`. Use a real shell export instead — the CLI flag is env-bound (`#[arg(long, env = "ARES_CONFIG")]`, `ares-cli/src/cli/config.rs:12`):

```bash
ARES_CONFIG=/path/to/ares.yaml task config:models
```

`task k8s:sync:config` exits 0 with only a `WARN` if the file is missing or a `cp` fails — a partial sync looks like a success.

## Precedence

Global rule: **env > operation-request JSON payload > YAML > code default.** Per-knob, with sources:

| Knob | Chain (highest first) | Source |
|---|---|---|
| strategy preset | `ARES_STRATEGY` > json `strategy` > yaml `operation.strategy` > `"fast"` | `strategy.rs:113-126` |
| technique weights | json `technique_weights` > yaml `operation.technique_weights` > yaml `vulnerability_priorities` > preset | `strategy.rs:130-156` |
| `exclude_techniques` | `ARES_EXCLUDE_TECHNIQUES` ∪ json; **if that union is empty** → yaml | `strategy.rs:158-175` |
| `include_techniques` | `ARES_INCLUDE_TECHNIQUES` ∪ json; if empty → yaml | `strategy.rs:177-194` |
| `continue_after_da` | `ARES_CONTINUE_AFTER_DA` > json > yaml (**only when true**) > preset | `strategy.rs:194-208` |
| `llm_temperature` | `ARES_LLM_TEMPERATURE` > json > yaml > `None` | `strategy.rs:210-219` |
| `selection_temperature` | `ARES_SELECTION_TEMPERATURE` > json > yaml, then `.max(0.0)` | `strategy.rs:221-234` |
| `novelty.enabled` | yaml applied **unconditionally**, then `ARES_NOVELTY_ENABLED` overwrites | `strategy.rs:236-246` |
| `emit_path_records` | yaml unconditionally, then `ARES_EMIT_PATH_RECORDS` overwrites | `strategy.rs:236-249` |
| `novelty.scope` | **yaml ONLY** (empty string ignored) | `strategy.rs:238-240` |
| `randomize_entry_foothold` | **yaml ONLY** — no env, no json | `strategy.rs:241` |
| per-role model | yaml `agents.<role>.model` > orchestrator spec (itself `ARES_LLM_MODEL` > yaml) | `mod.rs:481-522` |
| per-role `max_steps` | `ARES_AGENT_MAX_STEPS` > yaml `agents.<role>.max_steps` > 75 | `ares-llm/src/agent_loop/config.rs:90-99`, default at `:39` |
| operation wall clock | yaml `timeouts.operation_timeout` (if > 0) > 7200s | `mod.rs:903-907` |

**Exclude/include lists do not merge across layers** — a non-empty env/JSON list *replaces* the YAML list wholesale (`strategy.rs:163-175`).

**Knobs with NO env layer at all** — the global rule simply does not apply to these; editing YAML (or the JSON payload) is the only way to move them: `technique_weights` (json > yaml only), `novelty.scope` and `randomize_entry_foothold` (yaml only, `strategy.rs:238-241`), `acl_publish_cap`, `timeouts.operation_timeout`.

`AresConfig::load` does **zero env interpolation** (`mod.rs:49-56`). `${GRAFANA_URL}` / `${GRAFANA_SERVICE_ACCOUNT_TOKEN}` in the grafana block (`config/ares.yaml:294-295`) are stored as those literal strings — and nothing reads `grafana.base_url` / `api_key` anyway.

Preset matching is loose and silently permissive: `"comprehensive"|"full"|"all"` → Comprehensive, `"stealth"|"quiet"` → Stealth, **anything else including a typo → Fast** (`strategy.rs:27-33`). A typo'd `strategy:` also flips `continue_after_da` off and re-tiers the whole weight map.

The only validated invariant in the entire config is `stop_on_domain_admin && stop_on_golden_ticket` — both true is a hard load error (`mod.rs:59-67`).

## Per-role models — the only lever

`agents.<role>.model` is read as raw YAML (`read_role_model`, `mod.rs:1278-1287`). A bare name is auto-prefixed `openai/`; a value containing `/` passes through verbatim.

| Role (YAML key) | Shipped model | Resolved spec | `max_steps` | applied? | `AgentRole` variant |
|---|---|---|---|---|---|
| `orchestrator` | `gpt-5.2` | `openai/gpt-5.2` | 200 | **No** — fallback provider skips `with_config_max_steps` (`mod.rs:513-518`), stays 75 | none |
| `recon` | `gpt-5-mini` | `openai/gpt-5-mini` | 100 | yes | `Recon` |
| `credential_access` | `gpt-5` | `openai/gpt-5` | 100 | yes | `CredentialAccess` |
| `cracker` | `gpt-5-mini` | `openai/gpt-5-mini` | 150 | yes | `Cracker` |
| `acl` | `gpt-5.2` | `openai/gpt-5.2` | 150 | yes | `Acl` |
| `privesc` | `gpt-5.2` | `openai/gpt-5.2` | 100 | yes | `Privesc` |
| `lateral` | `gpt-5` | `openai/gpt-5` | 300 | yes | `Lateral` |
| `coercion` | `gpt-5-mini` | `openai/gpt-5-mini` | 30 | yes | `Coercion` |

`AgentRole` has no `Orchestrator` variant (`ares-llm/src/tool_registry/mod.rs:25-33`) — the red orchestrator is not an LLM tool loop, so `agents.orchestrator.tools:` (18 entries, `config/ares.yaml:127-149`) is documentation only. `ares config show` prints just their count (`ares-cli/src/config.rs:91-92`).

Provider routing from the resolved spec (`ares-llm/src/provider/mod.rs:275-311`):

| Spec | Provider | Key / URL |
|---|---|---|
| `anthropic/<m>` | Anthropic | `ANTHROPIC_API_KEY` (hard error if unset) |
| `claude-cli/<m>` | local `claude` binary | none; `ARES_CLAUDE_CLI_BIN` overrides path |
| `openai/<m>` | OpenAI | `OPENAI_API_KEY` |
| `ollama/<m>` | OpenAI-compat shim | `OLLAMA_BASE_URL` (default `http://localhost:11434`) |
| `gpt-*` \| `o1*` \| `o3*` \| `o4*` | OpenAI (auto-detect) | `OPENAI_API_KEY` |
| anything else | **Anthropic, silently** | `ANTHROPIC_API_KEY` |

**Trap:** a typo'd model never errors on provider selection, but *where* it lands depends on how it arrived.

- **From YAML** (`agents.<role>.model`): `read_role_model` auto-prefixes any value with no `/` (`mod.rs:1281-1285`), so `gtp-5.2` becomes the spec `openai/gtp-5.2`, takes the `openai/` branch (`provider/mod.rs:284-288`) and 4xx's from **OpenAI** as an unknown model. The Anthropic default branch is unreachable from YAML. Same mechanism bites a bare Anthropic name: `model: "claude-sonnet-4-6"` becomes `openai/claude-sonnet-4-6` and is sent to OpenAI. **Always write the provider prefix in YAML.**
- **From `ARES_LLM_MODEL` / `ARES_BLUE_LLM_MODEL` / `ops submit --model`**: the spec is used verbatim, so a bare name with no `gpt-`/`o1`/`o3`/`o4` prefix falls into the Anthropic default (`provider/mod.rs:305-309`) and demands `ANTHROPIC_API_KEY`.

The blue *worker* has its own hardcoded default: with `ARES_LLM_MODEL` unset it uses `anthropic/claude-sonnet-4-6` regardless of `config/ares.yaml` (`ares-cli/src/worker/mod.rs:124-126`), so a blue worker can silently bill Anthropic while the orchestrator runs an OpenAI model.

### Change models in one place

```bash
task config:models                            # ares config show --models
task config:set-model -- lateral gpt-5        # one role, edits config/ares.yaml in place
ares config set-model --all orchestrator gpt-5.2   # DESTRUCTIVE: rewrites all 8 roles in config/ares.yaml IN PLACE (note the dummy ROLE arg)
                                                   # pass --config <copy> to try it without touching the repo
```

**`task config:set-model-all -- gpt-5.2` is BROKEN as documented.** `SetModel` declares positionals `role: Option<String>` then `model: String` (`ares-cli/src/cli/config.rs:24-33`); with one value clap binds it to `<ROLE>` and errors. Verified against `target/release/ares`:

```
$ ares config set-model --all gpt-5.2 --config <copy>
error: the following required arguments were not provided:
  <MODEL>
Usage: ares config set-model --all --config <CONFIG> <ROLE> <MODEL>            # exit 2

$ ares config set-model --all orchestrator gpt-5.2 --config <copy>
Set all 8 roles to model 'gpt-5.2'                                             # exit 0
```

The `<ROLE>` positional is discarded — `config.rs:214-224` returns from the `if all` branch before `role` is ever read (`let role = role.context(...)` is at `:227`). `Taskfile.yaml:446` and `README.md:625` both document the failing form.

The `--` separator is mandatory on the task wrappers — they interpolate `{{.CLI_ARGS}}` (`Taskfile.yaml:439-449`). After editing, ship it: `task ec2:deploy:config` (EC2) or `task k8s:sync:config` (K8s). Templates and binaries are compile-time embedded; the config file is not, so a config-only change needs no rebuild.

**Then prove it — a config push has no restart step and no output that says it took.** Two checks, in order:

```bash
# 1. On-box file: did the new value actually land in /etc/ares/config.yaml?
task ec2:exec EC2_NAME=<pinned> CMD='grep -A2 "^  privesc:" /etc/ares/config.yaml'

# 2. Runtime tell, AFTER the next launch — the orchestrator logs one line per role at startup
task ec2:exec EC2_NAME=<pinned> CMD='sudo grep -a "Per-role model" /var/log/ares/orchestrator.log | tail -8'
```

`info!(role = %yaml_key, model = %spec, max_steps = cfg.max_steps, "Per-role model")` fires once per role in the provider-build loop (`ares-cli/src/orchestrator/mod.rs:532`); `"Orchestrator model"` (`:495`) covers the fallback spec. **Match the message text, never `role=privesc`** — `/var/log/ares/*.log` is ANSI-painted and the field names and their `=` are inside escape runs, so a `field=value` anchor matches nothing.

**No worker reads this file.** `ares-cli/src/worker/mod.rs:23` loads `WorkerConfig::from_env()` only; `AresConfig::from_env` appears at `ares-cli/src/orchestrator/mod.rs:85`/`:1392` and `read_role_model` at `:491`/`:522` — nowhere else. A model change therefore activates on the **next op launch** (each launch execs a fresh orchestrator), with no `ares@*.service` bounce and no orchestrator restart needed.

**`config set-model` ignores its old-model argument** and rewrites whichever `model:` line follows the role header (`fn replace_model_in_yaml(yaml, role, _old_model, new_model)`, `ares-cli/src/config.rs:251`; the test `replace_model_ignores_old_model_param` pins this). A hand-edited file with an unexpected layout can be mangled. `--all` iterates a `HashMap`, so ordering is arbitrary and the orchestrator is included — it flattens the deliberate cost tiering. Both forms write `config/ares.yaml` back in place with no backup and no diff (`config.rs:214-224` for `--all`); the model values themselves are not pinned by any test, so a wrong `--all` ships silently rather than failing CI.

**YAML indentation is load-bearing for the shell tooling.** `.taskfiles/proxmox/Taskfile.yaml:51-52` awk-scrapes `agents.orchestrator.model` anchored on `/^  orchestrator:/`, and the diversity-sweep preflight greps `^  selection_temperature:` on the deployed file (`.taskfiles/benchmark/Taskfile.yaml:595-604`). Re-indenting `operation:` or `agents:` breaks both without touching the Rust.

## config/ares.yaml block by block

`AresConfig` has 12 top-level sections (`ares-core/src/config/mod.rs:31-45`). Ten are **required keys** — an empty map `{}` satisfies them because nearly every field carries a `#[serde(default)]`, but the key must be present. Deleting a dead section to tidy up breaks config loading. `grafana` and `observability` are `Option`.

| Section | Rust type | Required | Live consumer | Verdict |
|---|---|---|---|---|
| `operation` | `OperationConfig` | yes (`name`+`namespace` have no default) | `strategy.rs:108-266`, `completion.rs:455-464`, `bootstrap.rs:400` | PARTLY LIVE |
| `agents` | `HashMap<String, AgentConfig>` | yes | `mod.rs:481-540` | LIVE |
| `timeouts` | `TimeoutConfig` | yes | `mod.rs:903-907` — `operation_timeout` ONLY | 1 of 6 keys |
| `recovery` | `RecoveryConfig` | yes | `config.rs:111-113` (print) | DEAD |
| `phase_detection` | `PhaseDetectionConfig` | yes | none — not even printed | DEAD |
| `context_management` | `ContextManagementConfig` | yes | `config.rs:124-135` (print) | DEAD (env wins) |
| `vulnerability_priorities` | `HashMap<String,i32>` | yes | `strategy.rs:134-137`, clamped 1..10 | LIVE (clamped) |
| `logging` | `LoggingConfig` | yes | none | DEAD |
| `resources` | `ResourceConfig` | yes | none | DEAD |
| `security` | `SecurityConfig` | yes | none | DEAD |
| `grafana` | `Option<GrafanaConfig>` | no | `config.rs:139-143` (prints `enabled` + `dashboard_uid`) | DEAD |
| `observability` | `Option<ObservabilityConfig>` | no | `mod.rs:757-771`, `:1392-1404` (env injection, `blue` feature) | LIVE |

`AgentConfig.model` has **no serde default** (`sections.rs:100-101`), so a role block without `model:` fails the whole `AresConfig` parse — which the orchestrator then swallows (see item 3 above). `logging.format` defaults to a Python logging format string (`defaults.rs:42-44`), a fossil of the pre-Rust implementation.

### `operation.*` — every key

| Key | Type | Shipped | Default when absent | Consumer / effect |
|---|---|---|---|---|
| `name` | String | `ares-multi-agent` | **required, no default** | log line only |
| `namespace` | String | `attack-simulation` | **required** | printed at `config.rs:53`. The YAML comment claiming `redis_url` derives from it is **false** — Redis comes from `ARES_REDIS_URL`/`REDIS_URL` (`orchestrator/config.rs:96-98`) |
| `checkpoint_interval` | u64 | 60 | 60 | print only |
| `max_concurrent_tasks` | u32 | 8 | 8 | print only — live value is `ARES_MAX_CONCURRENT_TASKS` (default **12**) |
| `task_dispatch_delay` | f64 | 1.0 | 0.0 | print only — live is `ARES_DISPATCH_DELAY_MS` (200) |
| `rate_limit_backoff` | f64 | 15.0 | 0.0 | print only |
| `rate_limit_threshold` | u32 | 2 | 0 | print only |
| `stop_on_domain_admin` | bool | false | false | `completion.rs:423, 455-464`; **mutually exclusive** with the next key — both true fails the load (`mod.rs:59-67`) |
| `stop_on_golden_ticket` | bool | false | false | `completion.rs:427` |
| `strategy` | String | `comprehensive` | `""` → `fast` preset | `strategy.rs:113-126`; also lifts per-cycle dispatch limits (below) |
| `continue_after_da` | bool | true | preset default | `strategy.rs:194-208` — **yaml can only turn it ON**. Redundant here: `comprehensive` already implies it (`strategy.rs:45-48`) |
| `exclude_techniques` | Vec\<String\> | `[]` | `[]` | lowercased; env/json replaces wholesale if non-empty |
| `include_techniques` | Vec\<String\> | **commented out** (`:68`) | `[]` = allowlist off | `strategy.rs:177-194` |
| `technique_weights` | HashMap | 9 entries (`:81-90`) | `{}` | highest-precedence YAML layer, `clamp(1,10)` |
| `llm_temperature` | Option\<f32\> | **commented out** (`:94`) | `None` = provider default | `strategy.rs:210-219` |
| `selection_temperature` | f32 | 0.7 | 0.0 = deterministic argmin | `deferred.rs:386`, `exploitation.rs:323` |
| `novelty.enabled` | bool | true | false | `exploitation.rs:323` switches the pop path |
| `novelty.scope` | String | `per-campaign` | `per-campaign` (`defaults.rs:69`) | literal in the Redis key; **no env override** |
| `randomize_entry_foothold` | bool | true | false | `bootstrap.rs:399-403` shuffles `entry_ips`; **no env override** |
| `emit_path_records` | bool | true | false | `state/dedup.rs:54-57` |
| `acl_publish_cap` | u32 | 200 | 200 (`defaults.rs:72`) | `entities.rs:185-196, 247-259` |

**`acl_publish_cap` keys on the vuln_id PREFIX, not vuln_type** — `v.starts_with("acl_") || v.starts_with("gpo_")` (`result_processing/mod.rs:1149`). Once the cap is hit the rest are silently dropped for the whole op after a single WARN: `ACL publish cap reached; further ACL/GPO vulnerabilities dropped this op`. **A cap of `0` means UNLIMITED**, not zero (`entities.rs:252`).

### `strategy: comprehensive` does more than reweight

`is_comprehensive()` lifts hardcoded per-cycle `.take()` limits in six automation drivers:

| Driver | comprehensive | fast / stealth | Source |
|---|---|---|---|
| kerberoast work select | 10 | 2 | `automation/credential_access.rs:922` |
| kerberoast vuln work select | 10 | 2 | `automation/credential_access.rs:966` |
| username spray work | 20 | 5 | `automation/credential_access.rs:1042` |
| low-hanging-fruit work | 10 | 2 | `automation/credential_access.rs:1095` |
| credential secretsdump work | 20 | 5 | `automation/credential_access.rs:1146` |
| LAPS hash sweep | 10 | 3 | `automation/laps.rs:285` |

## Priority merge: what the shipped config resolves to

The merged weight map is consulted two ways at runtime:

- **Automation drivers** call `dispatcher.effective_priority("<hardcoded name>")`, plus the dynamic `format!("adcs_{}", item.esc_type)` in `adcs_exploitation.rs:492`.
- **Every published vulnerability** has its priority overwritten by `effective_priority(&vuln.vuln_type)` at `state/publishing/entities.rs:200`.

A YAML priority key only bites if its string matches one of those. Unknown keys return **5** (`strategy.rs:294-304`, `.unwrap_or(5)`).

`AresConfig::vulnerability_priority()` and `AresConfig::model_for_role()` (`ares-core/src/config/mod.rs:111,124`) have **zero callers outside their own unit tests and `config set-model`**. Do not reason from them.

Effective priorities for the shipped config (preset → `vulnerability_priorities` → `technique_weights`, all `clamp(1,10)`):

| Key | preset | vuln_priorities (clamped) | technique_weights | EFFECTIVE | Note |
|---|---|---|---|---|---|
| `esc1` | 1 | — | 1 | **1** | |
| `esc4` | 1 | — | 1 | **1** | |
| `esc8` | 1 | — | — | **1** | yaml only sets `adcs_esc8` |
| `adcs_esc1` | 1 | 1 | — | **1** | queried as `format!("adcs_{esc_type}")` |
| `adcs_esc4` | 1 | 2 | — | **2** | demoted by yaml |
| `adcs_esc8` | 1 | 3 | — | **3** | demoted by yaml |
| `constrained_delegation` | 1 | 4 | 2 | **2** | demoted |
| `unconstrained_delegation` | 1 | 5 | 2 | **2** | demoted |
| `rbcd` | 1 | 6 | 2 | **2** | demoted |
| `acl_abuse` | 1 | 9 | 3 | **3** | the de-domination that was intended |
| `dacl_abuse` | 1 | — | — | **1** | **alias NOT applied** — exact key wins over the alias group |
| `mssql_access` | 2 | — | 3 | **3** | demoted (the YAML comment claims a *lift*) |
| `mssql_impersonation` | 2 | 10 | 3 | **3** | demoted |
| `mssql_linked_server` | 2 | — | — | **2** | live name, untouched by yaml |
| `kerberoast` | 2 | 10 (from 20) | — | **10** | demoted hard |
| `password_spray` | 2 | 10 (from 50) | — | **10** | demoted hard |
| `shadow_credentials` | 1 | 10 (from 15) | — | **10** | demoted hard |
| `gpo_abuse` | 1 | 10 (from 12) | — | **10** | demoted hard |
| `asrep_roast` | 2 | — | — | **2** | yaml spells it `asreproast` → dead key |
| `laps` | 2 | — | — | **2** | driver asks `laps`; yaml `laps_abuse` only bites published vulns of that vuln_type |
| anything unlisted | — | — | — | **5** | `strategy.rs:303` |

**Misspelled / dead priority keys in the shipped YAML:**

| YAML key | What code asks for | Result |
|---|---|---|
| `asreproast: 21` | `asrep_roast` (`credential_access.rs:772`) | inert as a priority; `asreproast` exists only as a *hash type* label (`dedup/hashes.rs:12`) |
| `mssql_linked: 11` (+ `technique_weights: mssql_linked: 3`) | `mssql_linked_server` (`mssql_link_pivot.rs:154`) | **zero occurrences of the exact string `"mssql_linked"` in any `*.rs`** — fully dead |
| `domain_admin_hash: 8` | — | zero occurrences in `*.rs` — fully dead |
| `krbtgt_hash: 7` | — | appears only as a tool *argument* / secret-key name (`worker/credential_resolver.rs:57`), never a vuln_type |

**The alias trap:** `TECHNIQUE_ALIAS_GROUPS = &[&["acl_abuse", "dacl_abuse"]]` (`strategy.rs:328`), but `effective_priority` returns on an exact hit **before** consulting the alias group (`strategy.rs:294-304`). The comprehensive preset seeds `dacl_abuse` separately, so `technique_weights: acl_abuse: 3` leaves any caller asking for `dacl_abuse` at 1. In practice `automation/dacl_abuse.rs` asks for `"acl_abuse"`, so the intended de-domination does apply on that path — but a published vuln whose `vuln_type` is literally `dacl_abuse` gets 1. The alias **is** bidirectional for `exclude_techniques` / `include_techniques` (`strategy.rs:273-288`): excluding either spelling kills the ACL driver.

## Diversity knobs

| Knob | Shipped | Effect when on |
|---|---|---|
| `selection_temperature: 0.7` | on | **Changes the deferred-queue ordering metric.** At 0 selection uses `DeferredTask::score()` (priority + enqueue-time tiebreak); above 0 it softmaxes over **raw `priority` only** and the age component is dropped (`deferred.rs:386-405`) |
| `novelty.enabled: true` | on | Switches vuln popping off atomic `ZPOPMIN` onto peek-top-K + `ZREM` (`exploitation.rs:322-337`) and adds `NOVELTY_PENALTY = 4.0` to already-walked steps (`diversity.rs:31`, `CANDIDATE_LIMIT = 24` at `:34`). The penalty can flip the choice **even at temperature 0** |
| `novelty.scope: per-campaign` | on | Opaque literal, not a template |
| `randomize_entry_foothold: true` | on | Shuffles `entry_ips` before the opening recon fan-out (`bootstrap.rs:399-403`) |
| `emit_path_records: true` | on | Writes the per-op path record + coverage set |

Redis keys the knobs produce (`ares-cli/src/orchestrator/diversity.rs:49-67`; `KEY_PREFIX = "ares:op"` from `ares-core/src/state/keys.rs:4`):

| Key | Type | Written when | Notes |
|---|---|---|---|
| `ares:novelty:per-campaign:steps` | SET of `{vuln_type}:{target}` | `novelty.enabled=true` | **Shared by every op in the scope, forever.** `DEL` it to reset diversity memory |
| `ares:op:{operation_id}:path_record` | LIST of `PathStep` JSON | `emit_path_records=true` | `{foothold, technique, target}` |
| `ares:op:{operation_id}:coverage` | SET of distinct step keys | `emit_path_records=true` | |

On-box preflight the sweep uses to prove the deployed config is non-deterministic (`.taskfiles/benchmark/Taskfile.yaml:595-604`):

```bash
grep -E "^  (selection_temperature|randomize_entry_foothold|emit_path_records):" /etc/ares/config.yaml
```

Running the sweep itself → skill `attack-path-diversity-sweep`.

## Env var catalog

### Orchestrator loop (`ares-cli/src/orchestrator/config.rs:192-206`)

| Env var | Code default | YAML key it shadows / effect |
|---|---|---|
| `ARES_MAX_CONCURRENT_TASKS` | **12** | `operation.max_concurrent_tasks: 8` (inert). EC2 exports `8` (`launch-orchestrator.sh.tmpl:42`), so those numbers agree only by accident |
| `ARES_MAX_TASKS_PER_ROLE` | 3 | — |
| `ARES_DISPATCH_DELAY_MS` | 200 | `operation.task_dispatch_delay: 1.0` (inert) |
| `ARES_HEARTBEAT_INTERVAL_SECS` | 30 | — |
| `ARES_HEARTBEAT_TIMEOUT_SECS` | 120 | `timeouts.agent_heartbeat: 180` (inert) |
| `ARES_STALE_TASK_TIMEOUT_SECS` | 300 | `timeouts.task_timeout: 300` (inert) |
| `ARES_NON_LLM_TASK_TIMEOUT_SECS` | 6000 | `timeouts.hash_cracking: 600` (inert) |
| `ARES_RESULT_POLL_INTERVAL_MS` | 500 | — |
| `ARES_LOCK_TTL_SECS` | 300 | — |
| `ARES_DEFERRED_POLL_INTERVAL_SECS` | 10 | — |
| `ARES_DEFERRED_TASK_MAX_AGE_SECS` | 300 | — |
| `ARES_MAX_DEFERRED_PER_TYPE` / `_TOTAL` | 50 / 200 | — |
| `ARES_SHUTDOWN_TIMEOUT_SECS` | 120 red-only / **600** when blue is enabled (`mod.rs:1307-1322`) | values < 1 ignored |
| `ARES_AUTH_THROTTLE_MAX_ATTEMPTS` | 3 (`mod.rs:557`) | per-credential lockout guard |
| `ARES_AUTH_THROTTLE_WINDOW_SECS` | 30 (`mod.rs:558`) | raise toward the domain's real lockout observation window before spraying |
| `ARES_SPRAY_WINDOW_SECS` | 1800 | spray-attempt accumulator window — the other half of the lockout guard. A `lockout_observation_window_mins` tool argument (from `password_policy`) **overrides it** (`tool_dispatcher/mod.rs:185-193`) |
| `ARES_PRINTNIGHTMARE_DLL` | unset | Unset or empty → the printnightmare automation driver `continue`s past **every** candidate with no warning (`automation/print_nightmare.rs:110-113`). Silent capability loss, not an error |
| `ARES_MAX_ACTIVE_CRACK_TASKS` | 2 (`automation/crack.rs:108-117`) | in-flight crack dispatch cap; values ≤ 0 ignored |
| `ARES_SCOPE_EXPAND_SUBNETS` | unset; must equal `"1"` | Fans `target_ips` to the full /24 of any 2+-host cluster (`config.rs:245-283`) — widens engagement scope |
| `ARES_LOCK_TAKEOVER` | unset; `"1"` | Force-steals a wedged op lock (`task_queue.rs:44`) |
| `ARES_USE_EVENT_LOG_REPLAY` | unset; `"1"` | Rehydrate state from JetStream instead of Redis (`mod.rs:263`) |

**Unparsable numerics fall back silently.** `parse_env` is `.ok().and_then(|v| v.parse().ok()).unwrap_or(default)` (`config.rs:342-347`) — `ARES_MAX_CONCURRENT_TASKS=twelve` yields 12 with no warning.

### Required / operation identity

| Env var | Behaviour when unset |
|---|---|
| `ARES_OPERATION_ID` | **Orchestrator refuses to start** (`config.rs:103`). May be a bare id OR the whole operation-request JSON payload; the parser searches for the first `{` (`config.rs:111-116`) |
| `ARES_REDIS_URL` → `REDIS_URL` | `redis://127.0.0.1:6379/0` (`orchestrator/config.rs:96-98`) — **orchestrator only**; the worker has a third tier and no localhost default (see Worker table) |
| `ARES_NATS_URL` → `NATS_URL` | `nats://127.0.0.1:4222` (`ares-core/src/nats.rs:176-180`) |
| `ARES_TARGET_DOMAIN` / `ARES_TARGET_IPS` | empty — only consulted when `ARES_OPERATION_ID` is a bare id, not a JSON payload |
| `ARES_INITIAL_CREDENTIAL` | no seeded credential; format `user:pass@domain` |
| `ARES_LISTENER_IP` | auto-detected from the first target IP (`config.rs:186-190`) |
| `ARES_TOOL_DISPATCH` | tools route to the worker queue; **only the literal `local`** runs them in-process (`mod.rs:565`, `monitoring.rs:476`). **Second accepted literal with inverted polarity:** `spawn_inprocess_blue_consumer` (the `benchmark run` path) defaults to *in-process* and opts out only on the exact value `redis` (`mod.rs:1353-1367`) |
| `ARES_REPORT_DIR` | red: `/tmp/reports`, written to `{dir}/red/{op}.md` (`mod.rs:1085-1090`). blue: request `report_dir` > `ARES_REPORT_DIR` > `~/.ares/reports/` (`blue/investigation.rs:502-511`). Set nothing and red lands in `/tmp/reports/red` while blue lands in `~/.ares/reports`. `README.md:696` documents a third, stale value (`$HOME/ares_reports`) |
| `ARES_AUTO_TEARDOWN` | **ON unless explicitly falsy** (`0`/`false`/`no`/`off`, trimmed + lowercased) — `cleanup/mod.rs:68-76` |

### Agent loop (`ares-llm/src/agent_loop/config.rs`) — red path only

| Env var | Code default | YAML key it shadows |
|---|---|---|
| `ARES_AGENT_MAX_STEPS` | 75 (`:39`) | `agents.<role>.max_steps` — **env presence alone short-circuits, even if unparsable** (`:92-95` returns early on `is_ok()`) |
| `ARES_AGENT_MAX_TOKENS` | 4096 | — |
| `ARES_AGENT_MAX_TOOL_CALLS_PER_NAME` | 10 | — |
| `ARES_AGENT_ENABLE_PROMPT_CACHE` | true | Anthropic-only effect |
| `ARES_LLM_SEED` | unset | Forwarded by OpenAI/Ollama only; Anthropic's request struct has no `seed` field |
| `ARES_CONTEXT_MAX_TOKENS` | **180000** (`:128`) | `context_management.max_context_tokens: 50000` (inert — 3.6× off). `0` disables compaction entirely |
| `ARES_CONTEXT_MAX_TOOL_OUTPUT_CHARS` | 30000 | `context_management.max_output_chars: 3000` (inert) |
| `ARES_CONTEXT_MIN_RECENT_MESSAGES` | 10 | `context_management.min_messages_to_keep: 15` (inert) |
| `ARES_CONTEXT_COMPACTION_THRESHOLD` | 0.6, clamped `[0.1, 1.0]` | — |
| `ARES_CONTEXT_COMPACTION_CHECK_EVERY` | 5, forced `.max(1)` — `0` means *every step*, not off | — |
| `ARES_BUDGET_MAX_INPUT_TOKENS` / `_OUTPUT_TOKENS` / `_TOTAL_TOKENS` | 0 = off (`:196-199`) | cumulative circuit breaker |
| `ARES_SESSION_LOG_DIR` | `$HOME/.ares/sessions` — **logging is ON by default**; `ARES_SESSION_LOG_ENABLED=0` disables (`:263-297`) | — |
| `ARES_SESSION_TEAM` / `ARES_SESSION_OP_ID` | `red` / unset | stamped on every JSONL record |
| `ARES_CLAUDE_CLI_BIN` | `claude` | — |

**These are all inert for blue.** All three blue call sites build `AgentLoopConfig` with a struct literal + `..AgentLoopConfig::default()`, so `ContextConfig::default()` / `BudgetConfig::default()` are used and `ARES_CONTEXT_*` / `ARES_BUDGET_*` / `ARES_AGENT_MAX_STEPS` never apply.

### Worker + tool execution

| Env var | Code default | Effect when unset |
|---|---|---|
| `ARES_REDIS_URL` → `REDIS_URL` → `REDIS_HOST` | **none** | Third tier builds the URL from `REDIS_HOST` (+ `REDIS_PORT` 6379 / `REDIS_DB` 0 / optional `REDIS_PASSWORD`) — this is how K8s pods get theirs. **The worker has NO localhost default**: all three unset and it refuses to start with `Redis URL required: set ARES_REDIS_URL, REDIS_URL, or REDIS_HOST` (`worker/config.rs:82-96`) |
| `ARES_WORKER_ROLE` → `ARES_ROLE` | none | **Worker refuses to start** (`worker/config.rs:100-102`) |
| `ARES_POD_NAME` → `HOSTNAME` | `unknown` | Worker identity stamped on heartbeat/registry records (`worker/config.rs:104-106`). Unset on both and every worker registers as the literal `unknown`, making per-pod heartbeat and status output ambiguous |
| `ARES_WORKER_MODE` | `task`; accepts `tool_exec`, `blue_task` (`worker/config.rs:112-117`) | full LLM task loop. The shipped systemd unit sets `tool_exec` |
| `ARES_WORKER_CONCURRENCY` | 3 (`worker/tool_executor.rs`) | — |
| `ARES_MAX_CONCURRENT_TOOLS` | 20 (`ares-tools/src/concurrency.rs:73`) | global subprocess semaphore |
| `ARES_MAX_CONCURRENT_HASHCAT` | 2 (`concurrency.rs:118`) | — |
| `ARES_SPIDER_PLUS_CONCURRENCY` | 4 (`concurrency.rs:31`) | — |
| `ARES_AGENT_TASK_TIMEOUT` | 600s (`worker/config.rs:120-124`) | — |
| `ARES_HEARTBEAT_INTERVAL` / `ARES_HEARTBEAT_TTL` / `ARES_POLL_TIMEOUT` | 15 / 60 / 5 | worker-side; **distinct names** from the orchestrator's `*_SECS` variants |
| `ARES_HASHCAT_WORKLOAD` | `"3"` (`ares-tools/src/cracker.rs:85`) | EC2 pins `4` for the dedicated T4 box |
| `ARES_HASHCAT_NICE` | `"-15"` (`cracker.rs:70`) | — |
| `ARES_AES_KERBEROAST_MAX_TIME_MINUTES` | 45 (`cracker.rs:114`) | — |
| `ARES_ALLOW_IRREVERSIBLE_MUTATION` | off | gates `bloodyad_set_password` (`ares-tools/src/mutation.rs:35-38`) |
| `ARES_KEEP_WORKSPACE` | off (workspace wiped pre-op) | `ares-tools/src/sanitize.rs:36-42` |
| `ARES_KEEP_POTFILE` | off (potfile truncated on op change) | `1\|true\|TRUE` opts out of the per-op wipe (`cracker.rs:433-440`). Set it and cracked plaintexts carry across ops — which silently inflates compromise counts in a benchmark |
| `ARES_HASHCAT_POTFILE` | unset | Explicit potfile path. **Short-circuits the whole resolver** when the path `is_file()` (`cracker.rs:403-408`), ahead of `XDG_DATA_HOME` and the `$HOME` candidates — the reliable way to pin the file the per-op wipe acts on |
| `ARES_NATS_REQUEST_TIMEOUT_SECS` | 6000 (`ares-core/src/nats.rs:160-164`) | NATS request/reply deadline for every tool dispatch. Deliberately above the orchestrator's outer tool timeout; lower it and the NATS client fires first, so long tools (full-port nmap, DRSUAPI secretsdump, ESC8 relay chains) fail as transport timeouts. Values ≤ 0 ignored |
| `ARES_KERBEROS_TIME_OFFSET_SECS` | unset (inert at unset or 0) | Subtracts a fixed offset from `datetime.now`/`utcnow`/`time.time` inside impacket wrappers via an injected `sitecustomize.py` (`ares-tools/src/kerberos_skew.rs:31`, module doc at `:1-18`). The lever for ranges whose DCs drift — symptom is `KRB_AP_ERR_SKEW` on every Kerberos tool call |
| `HOME` | unset under systemd | The potfile resolver survives it: `home::home_dir()` falls back to `getpwuid` (`cracker.rs:413-421`), the same way hashcat resolves its own potfile. Still set it — the unit does (`ansible/roles/redis/templates/ares@.service.j2:10-15`) — so both sides agree. `ARES_HASHCAT_POTFILE` overrides the whole chain |

The three `concurrency.rs` caps are read once inside `LazyLock<Semaphore>` initialisers — setting them after the first tool dispatch has zero effect.

### Blue team

| Env var | Code default | Effect |
|---|---|---|
| `ARES_BLUE_ENABLED` | unset → off; **must equal `"1"`** (`mod.rs:779`) | Resolved once per op so the spawner and completion loop cannot diverge |
| `ARES_BLUE_ONLY` | off; `"1"` | Investigation poller only, no red (`mod.rs:78`) |
| `ARES_BLUE_LLM_MODEL` (red path, `mod.rs:788-791`) | `ARES_BLUE_LLM_MODEL` (non-empty) > resolved orchestrator spec | |
| `ARES_BLUE_LLM_MODEL` (blue-only path, `mod.rs:1406-1408`) | **precedence is inverted and there is no YAML fallback**: `ARES_LLM_MODEL` > `ARES_BLUE_LLM_MODEL` > hard error `Set ARES_LLM_MODEL or ARES_BLUE_LLM_MODEL for blue-only mode` | Set both in blue-only mode and you get the **red** model. Set neither and the process refuses to start — `agents.orchestrator.model` is never consulted |
| `ARES_BLUE_MAX_STEPS` | 75 (`completion.rs:948`) | |
| `ARES_BLUE_DETERMINISTIC_SWEEP` | on unless falsy (`blue/sweep.rs:1345-1352`) | code-driven detection catalog sweep before the LLM loop |
| `ARES_BLUE_SWEEP_CONCURRENCY` | 6 (`sweep.rs:42`) | |
| `ARES_BLUE_SWEEP_TIMEOUT_SECS` | 360 (`sweep.rs:47`) | |
| `ARES_BLUE_GOLDEN_TICKET_CORRELATION` / `ARES_BLUE_SILVER_TICKET_CORRELATION` | on unless falsy (`sweep.rs:1358`, `:1364`, shared impl `:1367-1375`) | the 4769-without-4768 correlations. Note the `_TICKET_` segment — the baseline vars below drop it |
| `ARES_BLUE_GOLDEN_BASELINE_HOURS` / `ARES_BLUE_SILVER_BASELINE_HOURS` | 8 / 12 (`sweep.rs:162,173`; read at `:1381`, `:1390`) | |
| `ARES_BLUE_ALLOW_RULE_CREATION` | off; `1\|true\|yes\|on` | Adds `create_detection_rule` to blue tool sets — **provisions live Grafana alert rules** (`ares-core/src/detection/mod.rs:65-82`) |
| `ARES_BLUE_DRAIN_MAX_SECS` | `BLUE_INVESTIGATION_TIMEOUT_SECS + BLUE_DRAIN_SLACK_SECS` (`completion.rs:229-237`) | budget for draining blue after red ends |
| `ARES_BLUE_SIMULATED_CONTAINMENT` | off; `"1"` (`blue/runner.rs:194`) | detect-only vs. containment |
| `ARES_DEPLOYMENT` | unset | Read in six places across five files (`orchestrator/mod.rs:1176`, `orchestrator/blue/callbacks.rs:95`, `orchestrator/blue/investigation.rs:177`, `ares-tools/src/blue/detection/mod.rs:38`, `ares-tools/src/blue/investigation/write.rs:610,654`). `build_selector` emits a LogQL stream selector with **no `deployment=` label** when unset (`ares-tools/src/blue/detection/mod.rs:36-46`), so blue silently spans every range writing to the same Loki. Must equal Loki's actual label value; a mismatch yields zero hits, not an error |

### External / non-`ARES_` env

| Env var | Default | What breaks when unset |
|---|---|---|
| `OPENAI_API_KEY` | none | Hard error creating any `openai/` or `gpt-*` provider — i.e. the entire shipped config |
| `ANTHROPIC_API_KEY` | none | Hard error for `anthropic/` and for any unrecognized bare model name |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | only consulted with the `ollama/` prefix |
| `LOKI_URL` | `http://localhost:3100` (`loki.rs:59-62`, `loki_bulk.rs:48`) | Blue LogQL hits localhost and returns nothing |
| `LOKI_AUTH_TOKEN` | none | — |
| `LOKI_TIMEOUT_SECS` | 90 (`loki.rs:103-109`) | Per-attempt request timeout. Values ≤ 0 ignored |
| `LOKI_QUERY_BUDGET_SECS` | = `LOKI_TIMEOUT_SECS` (`loki.rs:172-178`) | Total wall clock one query may spend across all `MAX_RETRIES = 3` attempts. Raising it lets a hung query hold a sweep slot for up to `3 × LOKI_TIMEOUT_SECS`, starving the rest of the detection catalog into `not_run` |
| `GRAFANA_URL` + `GRAFANA_SERVICE_ACCOUNT_TOKEN` (or `GRAFANA_API_KEY`) | none | **Preferred over `LOKI_URL`** — resolved via the Grafana datasource proxy and memoised in a tokio `OnceCell` (`ares-tools/src/blue/loki.rs:15,29,38-42,68-72`), so fixing the env mid-process does nothing |
| `PROMETHEUS_URL` | `http://localhost:9090` (`ares-tools/src/blue/prometheus.rs:12`) | Blue PromQL hits localhost |
| `DREADNODE_API_KEY` / `_SERVER_URL` / `_ORGANIZATION` / `_WORKSPACE` / `_PROJECT` | none | Platform reporting no-ops |
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` → `OTEL_EXPORTER_OTLP_ENDPOINT` | none | **OTLP export is a silent no-op** — Tempo panes come back empty. Only a set-but-*blank* endpoint warns (`ares-core/src/telemetry/init.rs:132-152`) |
| `OTEL_EXPORTER_OTLP_PROTOCOL` | gRPC; set `http/protobuf` for the Alloy gateway | — |
| `OTEL_RESOURCE_ATTRIBUTES` | none | fleet uses `deployment.environment=staging,attack.team=red` |
| `RUST_LOG` | per-service default filter (`init.rs:81`) | — |
| `ARES_DATABASE_URL` | none | **Persistent history disables itself with no error** — `PersistentStoreConfig::is_enabled()` returns false (`ares-core/src/persistent_store/config.rs:73,120`), so ops finish looking healthy while writing nothing to SQL |
| `ARES_PG_POOL_MIN` / `_MAX` / `_TIMEOUT` | 2 / 5 / 30 | — |
| `ARES_RETENTION_DEFAULT_DAYS` | 90 | How long an ordinary op's persisted history survives (`persistent_store/config.rs:98-102`) |
| `ARES_RETENTION_DA_DAYS` | 365 | Same, for ops that reached DA (`config.rs:104-108`) |
| `ARES_RETENTION_ARTIFACT_MAX_BYTES` | 10485760 | Max persisted artifact size (`config.rs:110-114`) |
| `ARES_SECRETS_ID` | `ares/api-keys` | AWS Secrets Manager id — read at **exactly one site**, the benchmark-replay EC2 re-exec path (`ares-cli/src/benchmark/replay.rs:273`). The default literal lives at `secrets.rs:123` but is the fallback for a *caller-supplied argument*, not an env read. Setting it expecting to redirect a normal `ares orchestrator` run does nothing |
| `HASHCAT_SERVICE_URL` / `HASHCAT_TOKEN` | none = local hashcat | remote crackd. **`HASHCAT_TOKEN` is not optional**: with the URL set and the token missing, every remote crack errors `HASHCAT_SERVICE_URL is set but HASHCAT_TOKEN is missing` (`cracker/remote.rs:43-46`) |
| `HASHCAT_REMOTE_RULES` | `best66.rule` (`cracker/remote.rs:196-199`, const at `:33`) | Rule file name sent to crackd; empty string falls back to the default |

**Deliberately not catalogued here:** the benchmark capture/replay env vars — `ARES_REPLAY_CLOCK_MODE` / `_CLOCK_START` / `_CLOCK_END`, `ARES_REPLAY_MAX_STEPS`, `ARES_REPLAY_TEMPO_OTLP_URL`, `BENCHMARK_AWS_PROFILE` / `_AWS_REGION` / `_S3_BUCKET`, `LOKI_S3_BUCKET` / `_PROFILE` / `_REGION` (`ares-cli/src/benchmark/capture.rs:55-61`). They only affect `ares benchmark` subcommands → `references/benchmarks-and-replay.md`.

### Boolean truthiness is NOT uniform

Six dialects coexist. Getting this wrong is a silent no-op, never an error. **The three trim+lowercase dialects differ in what an *unrecognised* value does** — that is the part that bites.

| Dialect | Accepts | Unknown value | Sites |
|---|---|---|---|
| Strict `"1"` only | `1` | false | `ARES_BLUE_ENABLED` (`mod.rs:779`), `ARES_BLUE_ONLY`, `ARES_USE_EVENT_LOG_REPLAY`, `ARES_SCOPE_EXPAND_SUBNETS`, `ARES_LOCK_TAKEOVER`, `ARES_BLUE_SIMULATED_CONTAINMENT` |
| Strict literal | `local` (`mod.rs:565`); `redis` (`mod.rs:1354`) | default branch | `ARES_TOOL_DISPATCH` — `local` opts *in* to in-process on the red path, `redis` opts *out* of in-process on the `benchmark run` blue-consumer path |
| Narrow truthy | `1` \| `true` \| `TRUE` | false | `ARES_KEEP_WORKSPACE` (`sanitize.rs:37-42`), `ARES_KEEP_POTFILE` (`cracker.rs:433-440`) |
| Narrow truthy, case-folded | `1` \| any case of `true` | false — `yes`/`on` **fail** | `ARES_CONTINUE_AFTER_DA` (`strategy.rs:197-198`), `ARES_NOVELTY_ENABLED` (`:244-245`), `ARES_EMIT_PATH_RECORDS` (`:247-248`) |
| **Falsy-list — default ON** | anything **except** `0` \| `false` \| `no` \| `off` (trimmed + lowercased) | **true** | `ARES_AUTO_TEARDOWN` (`cleanup/mod.rs:67-76`), `ARES_BLUE_DETERMINISTIC_SWEEP` (`sweep.rs:1345-1352`), `ARES_BLUE_GOLDEN_TICKET_CORRELATION` / `ARES_BLUE_SILVER_TICKET_CORRELATION` (`sweep.rs:1367-1375`) |
| **Truthy-list — default OFF** | `1` \| `true` \| `yes` \| `on` (trimmed + lowercased) | false | `ARES_ALLOW_IRREVERSIBLE_MUTATION` (`mutation.rs:94-103`), `ARES_BLUE_ALLOW_RULE_CREATION` (`ares-core/src/detection/mod.rs:73-81`) |
| Both lists, **unknown = compiled default** | `1\|true\|yes\|on` → true; `0\|false\|no\|off\|""` → false | the compiled default | `parse_env_bool` (`ares-llm/src/agent_loop/config.rs:373-382`): `ARES_AGENT_ENABLE_PROMPT_CACHE` (`:80`), `ARES_SESSION_LOG_ENABLED` (`:289`) |

`ARES_BLUE_ENABLED=true`, `ARES_TOOL_DISPATCH=remote`, `ARES_KEEP_WORKSPACE=yes` and `ARES_CONTINUE_AFTER_DA=on` all evaluate **false**. `ARES_BLUE_DETERMINISTIC_SWEEP=banana` and `ARES_AUTO_TEARDOWN=disabled` both evaluate **true** — only the four falsy literals turn them off.

### The `observability:` → env injection, and its two traps

```rust
// ares-cli/src/orchestrator/mod.rs:761 (duplicated at :1394 for blue-only mode)
if !obs.loki_url.is_empty() && std::env::var("LOKI_URL").is_err() {
    std::env::set_var("LOKI_URL", &obs.loki_url);
}
```

This is the **only** direction config flows into env, and it fills in only when the var is entirely unset. Two consequences:

1. The guard is `var().is_err()` — **entirely unset**, not "empty". `launch-orchestrator.sh.tmpl:28` unconditionally does `export LOKI_URL='__LOKI_URL__'`, substituted from `{{.EC2_LOKI_URL}}` (`.taskfiles/red/Taskfile.yaml:902`). If `.env` has no `EC2_LOKI_URL`, `LOKI_URL` is exported empty and the YAML's `loki_url` can never win. (The shipped `loki_url: ""` means it back-fills nothing today regardless.)
2. The launch template **never exports `PROMETHEUS_URL`** (checked against the full `--setenv` list, `launch-orchestrator.sh.tmpl:66-88`), so the shipped `observability.prometheus_url: "http://localhost:9090"` **does** get injected on EC2 — pointing blue PromQL at localhost on the attacker box.

`observability.loki_auth_token` exists in the struct (`sections.rs:318-320`) but is absent from the shipped YAML, so `LOKI_AUTH_TOKEN` is never injected from config.

The whole block is behind `#[cfg(feature = "blue")]`. `blue` is a default feature (`ares-cli/Cargo.toml:12`), so it is normally active, but a `--no-default-features` build ignores `observability` entirely.

## How env actually reaches a deployed process

Two EC2 launch paths exist and they propagate env differently. Reading `/etc/ares/env` is **not** proof a value reached the orchestrator.

| Path | Task | Mechanism |
|---|---|---|
| `task ec2:launch` | `.taskfiles/ec2/Taskfile.yaml:1062` | writes chmod-600 `/etc/ares/env`, then `set -a; . /etc/ares/env; set +a` + `nohup ares orchestrator` — **everything in the file propagates** |
| `task red:ec2:multi` | `.taskfiles/red/Taskfile.yaml:890-908` → `launch-orchestrator.sh.tmpl` | sources `/etc/ares/env`, then `systemd-run --unit=ares-orchestrator.service` with an **explicit `--setenv=NAME` allowlist** (`:66-88`) — anything not on the list is dropped |
| workers | `ares@<role>.service` | `EnvironmentFile=-/etc/ares/env` plus unit-level `Environment=` lines (`ansible/roles/redis/templates/ares@.service.j2:9-21`) |

**Written to `/etc/ares/env` but NOT on the `--setenv` allowlist** — these reach the *workers* but not the systemd-run orchestrator: `LOKI_AUTH_TOKEN`, `ARES_SESSION_LOG_DIR`, `ARES_HASHCAT_WORKLOAD`, `HOME`, `NATS_URL`. (`NATS_URL` is harmless — the code default is the same loopback address.) `PROMETHEUS_URL` and `TEMPO_URL` are never written at all.

**`/etc/ares/env` is probe-gated.** `ec2:launch` writes `GRAFANA_URL`, `LOKI_URL` and `ARES_DATABASE_URL` only if a 3-second `/dev/tcp` probe from the box succeeds; on failure it prints `SKIP: <VAR> ... unreachable from box` to **stderr** and blue tools fall back to localhost (`.taskfiles/ec2/Taskfile.yaml:1266-1310`). Note the divergence: `ec2:launch` treats an empty `EC2_GRAFANA_URL`/`EC2_LOKI_URL` as "keep the Secrets Manager value" (`.taskfiles/ec2/Taskfile.yaml:1203-1213`, inside `launch:` at `:1062`), while red's sed path blanks them. **`ec2:deploy:config` is not the lever here** — it is `:465-497` and its whole body is `aws s3 cp config/ares.yaml` + an SSM pull to `/etc/ares/config.yaml`; it never reads Secrets Manager and never references either var (`rg 'EC2_GRAFANA_URL|EC2_LOKI_URL' .taskfiles/ec2/Taskfile.yaml` → `:1095,:1096,:1206-1212` only).

Ground truth for a running orchestrator is the process, not the file:

```bash
task ec2:exec EC2_NAME=kali-ares CMD='sudo tr "\0" "\n" < /proc/$(pgrep -f "ares orchestrator" | head -1)/environ | sort'
task ec2:exec EC2_NAME=kali-ares CMD='systemctl show ares-orchestrator.service -p Environment'
```

Both print API keys — do not paste output verbatim into a report.

### `ares:op:{id}:env_vars` is written and never read

`ops submit` collects `OPS_ENV_VAR_NAMES`, logs `Submitting with env vars: …`, and writes `ares:op:{op_id}:env_vars` (`ares-cli/src/ops/submit.rs:207`). **Nothing reads it.** The only consumed twin is the blue key `ares:blue:inv:{id}:env_vars`, which `run_investigation` GETs and `set_var`s per key *only if not already present* (`orchestrator/blue/investigation.rs:107-124`). So `env FOO=bar ares ops submit …` cannot inject anything into a red run, even though the log line implies it did — red orchestrator env comes solely from the pod manifest / systemd unit.

### go-task variable resolution (verified against task 3.52.0)

The root Taskfile declares `dotenv: ['.env']` (`Taskfile.yaml:5`). Reproduced empirically:

| Consumer | Winner |
|---|---|
| `{{.VAR}}` in a template | CLI var (`task t VAR=x`) > `.env` > OS environment > `\| default` |
| `$VAR` inside a cmd body | OS environment (export) > `.env` — **CLI vars are not exported** |

So `LOKI_URL=https://x task red:ec2:multi` changes nothing the templates read (`LOKI_URL` is in `.env`), yet any raw `$LOKI_URL` in a command body sees your value. Override with a CLI var, never an export.

**Trap: `VAR=` on the command line DOES clear the var, it does not restore the default.** A CLI var replaces the whole `vars:` entry, so the entry's own `| default` never evaluates. Every root-Taskfile var uses that form (`Taskfile.yaml:120,134,137`), so `EC2_NAME=`, `AWS_REGION=`, `ARES_CONFIG=` all resolve to the empty string. Only a `| default` written *inline at the use site* refills on an empty CLI var. Reproduced on task 3.52.0:

```
vars: {FOO: '{{.FOO | default "foo-default"}}'}   cmd: echo "FOO=[{{.FOO}}]"
$ task --dry show          → echo "FOO=[foo-default]"
$ task --dry show FOO=     → echo "FOO=[]"

cmd: echo "BAR=[{{.FOO | default "bar-default"}}]"     # default inline instead
$ task --dry inline FOO=   → echo "BAR=[bar-default]"
```

**Correction to a widely repeated claim:** root-Taskfile defaults do **not** shadow an include's own `vars:` block. `Taskfile.yaml:134` sets `EC2_NAME: ares-tools` and `:137` sets `AWS_REGION: us-east-1`, but `.taskfiles/ec2/Taskfile.yaml:35,40` redeclare them as `kali-ares` / `us-west-1` and the include wins. Verified:

```bash
task --dry --verbose ec2:ops 2>&1 | rg '^task: \[ec2:ops\]'
# task: [ec2:ops] ./target/release/ares --ec2 kali-ares --ec2-profile lab --ec2-region us-west-1 ops list
```

**Keep that filter — bare `task --dry --verbose` prints your API keys.** `--verbose` echoes every dynamic (`sh:`) var's *resolved value*, and `.taskfiles/blue/Taskfile.yaml:32-39` resolves four of them by grepping `.env` (falling back to `op item get`): `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `DREADNODE_API_KEY`, `GRAFANA_SERVICE_ACCOUNT_TOKEN`. Measured: 8 `dynamic variable: … result:` lines, 2 of them carrying live keys. Plain `task --dry` prints none of them — but `ec2:ops` is `silent: true`, so plain `--dry` prints nothing at all, which is why the filtered `--verbose` form is the usable one.

Passing `EC2_NAME=`/`AWS_REGION=` explicitly is still good hygiene, but not because of shadowing — and see the `VAR=` trap above before passing them empty.

**`.env.example` is incomplete.** `OTEL_TRACES_ENDPOINT` and `ALLOY_LOKI_ENDPOINT` are declared and forwarded by the root Taskfile (`:131-132`) but are absent from `.env.example`. A fresh `cp .env.example .env` therefore yields empty OTEL and Alloy endpoints — trace export and Alloy log push become silent no-ops. `setup-env` is `cp -n .env.example .env || true` (`Taskfile.yaml:238`), so it never overwrites and never says it skipped.

## Keys and vars that look like levers and are read by nothing

| Item | Where it appears | Status |
|---|---|---|
| `ARES_MODEL_FOR_<ROLE>` / `ARES_MODEL_FOR_DEFAULT` | `README.md:671-679` only | **Do not exist in source.** The README documents them as the per-role override mechanism; it is fiction. `rg 'ARES_MODEL_FOR' -g '!target'` → README only |
| `OPENAI_BASE_URL` | `README.md:655`, `.taskfiles/proxmox/Taskfile.yaml:173,186,188` | **Never read by Rust.** `create_provider` always calls `OpenAiProvider::new(api_key, None)` (`provider/mod.rs:285-288`). The only working local-endpoint route is the `ollama/` prefix + `OLLAMA_BASE_URL` |
| `llm:` YAML block (`llm.ollama_base_url` / `llm.openai_base_url`) | `README.md:640-646`, awk-scraped by `.taskfiles/proxmox/Taskfile.yaml:164` | No struct field, no shipped YAML. The scrape returns empty, which `deploy:env` treats as "delete the key" |
| `blue.response.confidence_threshold` | `docs/blue-response-actuators.md:246` | No `blue:` section in the YAML, no such field in any struct |
| `ARES_LLM_PREFLIGHT_SKIP` | nowhere | **Does not exist in this tree** (`rg -i 'ARES_LLM_PREFLIGHT'` → zero hits). The only preflight is `monitoring::preflight_tool_check`, a worker *binary*-presence check with no env gate |
| `ARES_WORKER_MODEL`, `ARES_AGENT_{ROLE}_MODEL` | `ops/submit.rs:49-56` | Collected and forwarded; never read |
| `ARES_TASKS` / `ARES_BLUE_TASKS` / `ARES_DEFERRED` / `ARES_DISCOVERIES` / `ARES_OPSTATE` | `ares-core/src/nats.rs:71-80` | JetStream **stream names**, not env vars. Setting them does nothing |
| `agents.orchestrator.tools` (18 names) | `config/ares.yaml:127-149` | Only `.len()` is read. 9 are in `REMOVED_CALLBACK_TOOLS` (`tool_registry/mod.rs:89-107`), 8 exist nowhere in the codebase, 1 (`get_operation_summary`) is live |

`ARES_MODEL` / `ARES_ORCHESTRATOR_MODEL` **are** read — but only in `ops submit`'s model waterfall: `--model` > `ARES_ORCHESTRATOR_MODEL` > `ARES_MODEL` (`ops/submit.rs:73-81`), which hard-fails with `No model specified` when all three are absent. `ARES_MODEL_OVERRIDE` is read in exactly one place, blue auto-submit (`completion.rs:941`). None affect red per-role models.

## Secret sourcing

`ares-cli/src/secrets.rs` runs **before** `Cli::parse()`, so clap's `env = "..."` attributes see the injected values.

| Env var | 1Password item | Field |
|---|---|---|
| `ANTHROPIC_API_KEY` | `Dreadnode Claude` | `api-key` |
| `DREADNODE_API_KEY` | `Dreadnode Dev Platform` | `api-key` |
| `GRAFANA_SERVICE_ACCOUNT_TOKEN` | `Ares Grafana MCP` | `grafana-token` |
| `OPENAI_API_KEY` | `Dreadnode Openai` | `dreadnode-ares-api-key` |

Verified at `ares-cli/src/secrets.rs:12-25`. **`.claude/CLAUDE.md` says the Anthropic key comes from item `Anthropic API` — the code says `Dreadnode Claude`. Trust the code.**

AWS Secrets Manager fallback (used when `op` is unavailable, e.g. re-exec'd onto an EC2 box) injects `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `OPENROUTER_API_KEY` from a secret id, default `ares/api-keys`, region from `AWS_REGION` else `us-west-1` (`secrets.rs:30-33, 119-128`). The id comes from the *caller*, and the only caller that reads `ARES_SECRETS_ID` is the benchmark-replay EC2 re-exec (`ares-cli/src/benchmark/replay.rs:273`) — `secrets.rs` itself never reads the env var.

Loading order and rules:

- `ares` **silently auto-loads `./.env` from cwd** on every invocation *that passes neither `--env-file` nor `--secrets-from`*, before clap. The fallback is `} else if secrets_from.is_none() { secrets::try_load_default_env(); }` (`main.rs:45-59`) — so `ares --secrets-from 1password …` skips `./.env` entirely, which is not obvious from the flag name.
- `--env-file <path>` fails hard (exit 1) on a missing file; it also suppresses the silent `.env` load.
- `--secrets-from` shells out to `op`; the source string is matched **case-sensitively** against exactly `1password` / `1pass` / `op`, and anything else exits 1 with `Unknown secrets source: <x> (supported: 1password)` (`main.rs:75-88`).
- **Neither ever overwrites an already-set variable** (`secrets.rs:83-88`) — explicit env always wins.

**`task ares:config:check` never probes `OPENAI_API_KEY`** (`Taskfile.yaml:369,378,387` check only three of the four items) even though every shipped role model is an OpenAI model, and its Anthropic failure text names field `dreadnode-personal-api-key` while the check itself uses `api-key`. It reports all-green with OpenAI auth unresolvable.

## `ares config` — what it does and doesn't tell you

```bash
ares config show                 # partial view of the resolved config
ares config show --models        # role → model, sorted and aligned
ares config validate             # three checks only
ares config set-model <role> <model>
ares config set-model --all <any-role> <model>
```

`config show` prints operation name/namespace/checkpoint/concurrency/dispatch/rate-limit/stop flags, agents, timeouts, recovery, `vulnerability_priorities`, `context_management`, and grafana. **It does NOT print `strategy`, `technique_weights`, any diversity knob, `acl_publish_cap`, `resources`, `security`, `phase_detection`, `logging`, or `observability`** (`ares-cli/src/config.rs:31-146`). Do not use it to confirm those shipped — grep the file.

`config validate` checks exactly three things (`config.rs:148-197`): every agent has a non-empty `model`, all 8 expected role names are present, and `operation_timeout >= task_timeout`. It never validates that a model exists, nor weights, nor technique spellings — and **it returns `Ok(())` even with warnings**, so it is never a CI gate. Success output has a cosmetic double space: `Config OK: ./config/ares.yaml (8  agent roles)`.

`task ares:config:check` echoes Taskfile variables and probes 1Password; it never reads `config/ares.yaml`. For real per-role models use `task config:models`. (`ares:config:show` was folded into `ares:config:check` on 2026-08-08.)

## Compile-time guards on the shipped values

Two tests fail the build if you change the shipped config:

- `ares-cli/src/orchestrator/strategy.rs:856-866` — `include_str!("../../../config/ares.yaml")`, asserts `selection_temperature == 0.7`, novelty enabled, scope `per-campaign`, `randomize_entry_foothold` and `emit_path_records` true.
- `ares-core/src/config/mod.rs:312-362` (`load_production_config`) — pins `operation.name`, `operation.namespace`, the exact 8 role names, and every role's `max_steps` (200/100/100/150/150/100/300/30).

Update the tests in the same change, or CI goes red on a config-only edit.

## Test data in config and fixtures

Allowed values only — see `references/tools-and-gates.md#test-conventions`. The config-specific exception: `config/ares.yaml` itself is exempt from the sweep (`scripts/goad-token-sweep.sh:36`), so operator-facing comments there may reference the real lab. Nothing you copy *out* of it is exempt.

## Where to go next

Routing map: `SKILL.md`. Nearest neighbours only:

| Question | Go to |
|---|---|
| diversity knobs as shipped, `coverage.csv`, sweep preflight | `references/benchmarks-and-replay.md`; workflow → skill `attack-path-diversity-sweep` |
| where a config value is consumed at runtime, deploy of `config/ares.yaml` | `references/deployment.md` |
| the mistakes this assistant actually makes on this repo | `references/hard-won-lessons.md` — read it first |
