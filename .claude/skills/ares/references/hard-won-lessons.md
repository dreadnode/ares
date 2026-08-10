# Hard-won lessons

Every rule below is a failure that actually happened on this repo, mined from 209 sessions and validated against current `HEAD`. The operator has had to repeat each of them — several more than twenty times — usually by pasting your own confident claim back with the evidence that it was false. The cost of re-learning them is his time, so read this before your first tool call and treat a violation as a defect in the work, not a style slip.

Companion files: `SKILL.md` (system map, task surface) and `.claude/skills/ares-debug/SKILL.md` (op triage). `ares-debug` is **correct** on deploy/restart semantics (`:396-405`) and on Redis key types (`:110-123`) — do not "fix" either. It is stale on exactly two things, both listed in [Rules that expired](#rules-that-expired): the worker's ENOENT cache, and the dead `spawn failed` log string.

## The five that cost the most time

These are the ones an agent can violate inside its first three tool calls.

**1. Never attribute an op result to your change until you have grepped a NEW literal out of `/usr/local/bin/ares` on the box.** `[repeated x21, critical]`
*Operator sees:* your "fix verified / the change is live" report, then an op whose behaviour is identical to before — or the question "does the e2e harness upload the latest binary each time?"
*Check:* `task ec2:e2e GATE_STRING='<literal from your change>'` (.taskfiles/ec2/scripts/e2e-op.sh:270-275), or directly:

```bash
task ec2:exec EC2_NAME=<pinned> CMD="grep -ac -- '<literal>' /usr/local/bin/ares"   # must be >= 1
```

**Outer double quotes, inner single.** The inverted shape (`CMD='… "<literal>" …'`) dies with `task: CMD required` / `precondition not met`, exit 201, the moment the literal contains a space — go-task splices `{{.CMD}}` raw into `sh: test -n "{{.CMD}}"` (`.taskfiles/ec2/Taskfile.yaml:1477-1479`). Gate literals are normally log sentences, so this bites every time. .taskfiles/ec2/scripts/e2e-op.sh uses the correct shape.

Pick the literal from a `contains("…")` argument, a `format!`/`bail!`/`panic!` fragment, or an `.arg("…")` value. **Never** from `starts_with` / `ends_with` / `==` — the optimizer folds all three out of the shipping profile (`[profile.dev-deploy]`, Cargo.toml:54-61) and a correct deploy greps negative.

**2. Pin the kali box to an explicit instance id + region before the first command, and pin it TWICE.** `[repeated x24, critical]`
*Operator sees:* "why are you looking at prod when staging is the one you should be", or an op/deploy landing somewhere unexpected; `No operations found` on a box that is demonstrably up.
*Check:*

```bash
AWS_PROFILE=lab AWS_REGION=us-west-1 task ec2:resolve EC2_NAME=kali-ares   # prints id + IP + full Name tag for EVERY match
# then pass BOTH keys to everything, because the two code paths honor different ones:
task ec2:deploy EC2_INSTANCE_ID=i-… EC2_NAME=i-… AWS_PROFILE=lab AWS_REGION=us-west-1 …
```

`EC2_NAME=kali-ares` is a `*kali-ares*` glob; `AWS_REGION` alone decides staging (us-west-1, profile `lab`) vs prod (us-east-1). `ec2:launch` runs `redis-cli FLUSHDB` on whatever it resolves.

**3. Treat `/Users/l/dreadnode/ares` as a checkout other sessions are mutating second-by-second.** `[repeated x24, critical]`
*Operator sees:* "you are in a worktree?", "ensure your changes are in this branch", diverged branches, vanished edits, or a commit that swept in files they never touched.
*Check (after every pause, not once):*

```bash
git -C /Users/l/dreadnode/ares branch --show-current && git -C /Users/l/dreadnode/ares status --porcelain
```

The branch and dirty-file list in your session snapshot are already stale by your first tool call. Work in your own worktree (`EnterWorktree`, or `git worktree add /Users/l/dreadnode/ares/.claude/worktrees/<name> <branch>`). Never `rebase`/`pull`/`stash`/`restore`/`reset --hard`/force-push there; stage explicit paths only.

**4. A fix is unproven until the originally-failing operation has been re-run against the deployed binary.** `[repeated x22, critical]`
*Operator sees:* "you tested it manually to ensure this will actually work?", "prove it first", "you're not done until you prove your fix is actually a fix", or LIAR with the still-failing output pasted.
*Check:* `cargo test`, `cargo clippy`, `--help`, "the API imports" and a green CI run are **never** verification. Ship it, then exercise the failure:

```bash
S3_BUCKET=<staging bucket> task ec2:e2e GATE_STRING='<literal>'
```

Anything whose verdict lives in Redis or a generated report needs a **fresh live op** — `ares ops report --regenerate` on an older op can never surface a key that did not exist when that state was written.

**5. Score a dreadgoad op on `Domains (n/3 compromised, n/2 forests)` plus the per-domain tree line, not on "the thing I fixed no longer misbehaves".** `[repeated x13, critical]`
*Operator sees:* `Vulns: N exploitable (0 exploited), M findings (K exploited)` next to `Domains (0/3 compromised, 0/2 forests)` pasted against your success claim; "I can't say I share your optimism".
*Check:*

```bash
task ec2:runtime EC2_NAME=<pinned> OPERATION_ID=op-…   # headline + finalizing note
task ec2:report  EC2_NAME=<pinned> OPERATION_ID=op-…   # proven_exploited_count (exploited minus superseded)
```

A domain counts only when its tree line carries `DA` **plus** a `krbtgt: <types>` detail and a matching `dc_secretsdump_<domain>` EXPLOITED row. A bare `GT` tag is credit stamped at *dispatch* time (automation/golden_ticket.rs:309-320) for a forge nobody confirmed.

## Before you say it works — the evidence contract

Non-optional. "Claimed success without evidence" is the single most-repeated correction in the corpus. Each item names the command that produces the evidence; if you cannot name the output you read, you do not have the evidence.

### The change shipped

1. A `Build SHA:`/`Deploy SHA:` pair from *this* run, plus `GATE_STRING` found in the deployed binary — `task ec2:e2e` (steps 2b at .taskfiles/ec2/scripts/e2e-op.sh:242-262, 2c at :270-275). A failed gate means "your change did not ship", never "flaky script".
2. Binary mtime newer than the commit, and the op started *after* the deploy finished — `task ec2:exec CMD='stat -c %y /usr/local/bin/ares'`. If the op predates the deploy, kill and relaunch.
3. If the change touches a worker role: that role's unit actually restarted — read deploy's restart block (`restarting: ares@…` vs `no ares@ worker units active — skipping restart`) then `task ec2:status`.

### The op is healthy / finished

4. `task ec2:runtime … OPERATION_ID=op-…` read in full: `Status`, `Domains (n/3 …)`, the split vuln counters, any `Warning: N exploit credits have no vulnerability record`, and `Finalizing: waiting on blue investigations`.
5. Two state snapshots 60s apart that show objective state advancing (see `ares-debug` Step 3). Tokens climbing is not progress.
6. Termination = `Status: completed` **and** runtime/tokens/cost stopped climbing. `Completion condition met` only freezes red dispatch (completion.rs:546-579) and opens a drain window: 300s red, up to 3300s blue.
7. The completion reason from Redis, mapped to the five legal reasons — `redis-cli hmget "ares:op:<id>:meta" has_domain_admin has_golden_ticket red_completed_at red_completion_reason red_blocked_on_blue` (written at completion.rs:810-822).

### The bug is fixed

8. The exact command string the wrapper builds, re-run by hand on the box (base64-wrapped), and the tool's own error read — not a summary of it.
9. For a state-shape or report change: a **new** op, then `reports/red/<op>.md`. For a blue detection/scoring change only: `task benchmark:replay OP_ID=<op>` counts.
10. Success markers derived from the installed tool's own output on the box (`which <tool>` → wrapper → venv → source), never from a repo test fixture.
11. Absence of a warning log is never a success verdict. If the path only logs on failure, add the success-side log.

### A detection fires

12. The composed LogQL printed from the tool result (`**Query:**` / the `logql` JSON field) and replayed against live Loki stage by stage, with `ARES_DEPLOYMENT` confirmed equal to the shipper's `deployment` label.
13. Per-record provenance read raw — `ares blue evidence <inv-id> --json` (the non-JSON view truncates at 10 per type). State which denominator you used: technique-ID coverage and per-activity coverage are two different numbers.
14. A zero count validated against a line you know exists. An unvalidated pattern returning 0 is not evidence of absence.

### Any number you quote

15. Which counter, from which command, for which op id — and, for exploited counts, whether supersede credits were subtracted (`ops runtime` and `ops loot` do **not**; `ops report` does).

## Deploy and the deployed binary

### Gate the deployed binary before trusting any op `[repeated x21, critical]`

**Never attribute an op result to your change until a literal that is NEW with that change is present in `/usr/local/bin/ares` on the box.**

**Symptom.** A confident "fix verified" report followed by an op identical to before; "you didn't prune anything not proven by an op right?"

**Why.** Deploy prints success at every layer (tar uploaded, build finished, SHA matched, install ok), so the natural conclusion is that the code shipped. The `ec2:deploy` sha256 chain only proves the *transfer* was faithful, not that the artifact was rebuilt from your tree. Prompt templates (`ares-llm/src/prompt/templates.rs:12-80+`, ~45 `include_str!`) and `detections.yaml` (`ares-core/src/detection/mod.rs:89`, no runtime override exists) are compiled in, so a `.tera`/YAML edit exists on the box *only* if the binary has it — invisible to any source check.

**Do this.**

```bash
S3_BUCKET=<staging bucket> task ec2:e2e GATE_STRING='<literal from your change>'
# or, standalone:
task ec2:exec EC2_NAME=<pinned> CMD="grep -ac -- '<literal>' /usr/local/bin/ares"   # outer double, inner single
task ec2:exec EC2_NAME=<pinned> CMD='stat -c %y /usr/local/bin/ares'
```

| Literal form | Survives `dev-deploy`? |
|---|---|
| `contains("…")` argument | yes |
| `format!` / `bail!` / `panic!("… {x}")` fragment | yes |
| `Command::new().arg("…")` value | yes |
| `starts_with("…")`, `ends_with("…")`, `== "…"` | **no — folded to an immediate compare, length does not rescue it** |
| method / symbol name | **no — never a string literal, and `strip = "symbols"`** |

Real artifact proof: `"exploit attempted but failed"` exists in the tree only as a `starts_with` argument (`ares-cli/src/benchmark/capture.rs:369`); `grep -acF` finds it in `target/release/ares` and `target/debug/ares` but **0** times in `target/x86_64-unknown-linux-gnu/dev-deploy/ares` — the profile that actually ships. Sanity-check candidate literals against `dev-deploy` or the deployed binary only; a local `target/release` grep is a false green.

Two more ways a gate lies: (a) grep the **pre-fix** binary for the same string and discard it if already present; (b) never gate on a string your fix *removed* — `include_str!` embeds comments too, so a comment quoting the old pattern keeps it alive. And note the harness is now **tracked**: `testes.sh` became `task ec2:e2e` (`.taskfiles/ec2/scripts/e2e-op.sh`) on 2026-08-08, so a fresh clone gets the SHA and `GATE_STRING` gates for free — you no longer have to recreate them around `ec2:deploy` → `ec2:launch` → `ec2:watch`.

A local `cargo build --release` changes nothing about `task ec2:*`: `BUILD_PROFILE` defaults to `dev-deploy` (.taskfiles/ec2/Taskfile.yaml:75) and the shipped artifact is `target/x86_64-unknown-linux-gnu/dev-deploy/ares`. `target/release/ares` is only the host-native `--ec2` proxy CLI that `ec2:kill/watch/report/loot/runtime/ops/stop-op/teardown` and `ec2:launch WAIT=true` require.

### Prod vs staging box resolution `[repeated x24, critical]`

**Pin the box to one explicit instance id + region before the first command — and pin it twice, because the two code paths take different pins.**

**Symptom.** "us-east-1 is prod", "why are you looking at prod when staging is the one you should be"; `ares --ec2 kali-ares ops list` and `task ec2:ops EC2_NAME=kali-ares` disagreeing in the same shell; a `[WARN] N instances match "*kali-ares*"; picking newest` line scrolling past unread; `No operations found` / `No running instance found matching: kali-ares` on a live box.

**Why.** Name resolution is a `*name*` tag glob over `describe-instances`; both regions carry a full dreadgoad range, so a wrong-region op looks completely normal. `S3_BUCKET` never enters instance resolution — it only names the staging bucket, yet it *feels* like an environment selector (the in-repo `ares-debug` skill hands you a `…-prod-us-east-1` bucket while the default box resolves in staging us-west-1).

**Do this.** Default to STAGING `us-west-1` / profile `lab`; touch prod (`us-east-1`, profile `prod`) only when the user says "prod" in that message.

```bash
AWS_PROFILE=lab AWS_REGION=us-west-1 task ec2:resolve EC2_NAME=kali-ares    # only task that prints id+IP+Name for EVERY match
# confirm identity from the box itself before reporting op state:
task ec2:exec EC2_INSTANCE_ID=i-… CMD='T=$(curl -s -X PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 60"); curl -s -H "X-aws-ec2-metadata-token: $T" http://169.254.169.254/latest/meta-data/instance-id; grep -aE "^(ARES_DEPLOYMENT|LOKI_URL)=" /etc/ares/env'
```

| Path | Honors `EC2_INSTANCE_ID`? | Region source |
|---|---|---|
| run-ssm.sh tasks: `ec2:deploy/exec/status/start/stop/restart/launch/report/logs:fetch/redis:forward`, `red:ec2:multi` | yes (run-ssm.sh:69-73) | `AWS_REGION` → `AWS_DEFAULT_REGION` → `us-west-1` |
| CLI-backed: `ec2:runtime/loot/ops/watch/kill/stop-op/teardown`, `blue:*`, bare `ares --ec2 …` | **no** — pin as `EC2_NAME=i-…` | clap hard-defaults `lab` / `us-west-1`, **ignores your exports** |

`ec2:report` is on the run-ssm.sh path despite reading like a CLI task — it sources `run-ssm.sh` and calls `resolve_instance_id` (`.taskfiles/ec2/Taskfile.yaml:878-880`), then runs the box's own `ares ops report` over SSM (`:900`). It carries no `*ares-cli-executable` precondition.

So set both keys plus explicit `AWS_PROFILE=`/`AWS_REGION=` on every command and in every subagent prompt. Treat "No operations found" as evidence you are on the wrong host, not as fact. `ec2:launch` still runs `redis-cli FLUSHDB` (FLUSH_REDIS defaults true), so a wrong-box launch destroys live op state; `red:ec2:multi` doesn't flush but overwrites `ares:operation:active`. When `red:ec2:multi` matters, pin `TARGET_PROFILE=`/`TARGET_REGION=` too — see [Target region selects the range independently](#target-region-selects-the-range-independently-repeated-x8-high).

### Build and deploy path hazards `[repeated x13, high]`

**Deploy with the default `BUILD_TOOL=remote`, always `task -y`, always a non-empty `S3_BUCKET` — and never interrupt an in-flight remote build.**

**Symptom.** "why doesn't it do remote compile?", "just do remote by default"; a deploy dying on **exit 104** (go-task remote-taskfile trust prompt), **exit 201** (precondition, almost always empty `S3_BUCKET`), or `sccache rustc -vV` failing under qemu; a remote build that looks hung.

**Why.** `auto` sounds adaptive but resolves to `cross` on macOS, where rustc SIGSEGVs under qemu-user (.taskfiles/ec2/Taskfile.yaml:70-73, :307-330). The build is *not* hung: `run_ssm_cmd` sends one SSM command with an 1800s timeout and polls silently, so `ec2:deploy` legitimately prints nothing locally for up to 30 minutes.

**Do this.**

```bash
AWS_PROFILE=lab AWS_REGION=us-west-1 S3_BUCKET=<staging bucket> task -y ec2:deploy EC2_NAME=<pinned>
./scripts/env-from-secrets.sh   # if .env ships an empty S3_BUCKET; an exported value also wins
```

- Never install host toolchains or docker binfmt to force a cross-build; never pass `BUILD_TOOL=auto|cross|zigbuild` "to go faster".
- `ec2:deploy` tars the **working tree from disk**, not git (:196-199) — uncommitted work ships, and conflict markers surface remotely as `error: key with no value, expected '='`. Confirm no merge in progress first.
- Remote build dir is `/var/tmp/ares-build` (`:82`; never `/tmp`, which is a tmpfs swept daily); artifact `/var/tmp/ares-build/target/dev-deploy/ares`. `BUILD_PROFILE` is ignored on the remote path (`:218` hardcodes `--profile dev-deploy`).
- Field-observed: if a build was killed mid-flight, `rm -rf /var/tmp/ares-build/target` before retrying, or the reused partial target link-fails with undefined `core::`/`anon.llvm` symbols.
- Never background a deploy through `| tail`/`| head`; `tee` to a log and poll it (.taskfiles/ec2/scripts/e2e-op.sh:228).
- You do **not** need LLM keys in `.env` to launch: `ec2:launch` fetches them from the `ares/api-keys` secret over SSM and fails loudly if absent (:1181-1189).
- A non-zero `ec2:e2e`/`ec2:watch` exit is usually the watcher hitting `MAX_WAIT` (default 7200s) on a healthy op. `ec2:watch` breaks only on `completed|stopped`, so a **failed** op also polls to timeout.
- One stale string still misdirects you (the `BUILD_TOOL` one was fixed in `.taskfiles/ec2/scripts/e2e-op.sh`): `ec2:deploy`'s `desc:` still says "Cross-compile Rust binaries" (:119).

### `task ec2:e2e` is the harness, not a probe `[repeated x11, high]`

**Read `.taskfiles/ec2/scripts/e2e-op.sh` before running or diagnosing anything about a live op, obey its printed warnings, and fix the script when it lacks a gate/region pin/knob — never hand-roll a sequence of discrete task commands, and never invoke `ec2:deploy`/`ec2:launch` as a verification probe.**

**Symptom.** "Is it deploying from the worktree as per the e2e harness which you're too lazy or illiterate to read?"; "you should fix the script so it works"; two deploys racing and the loser aborting with `S3 staged binary sha mismatch` (they collide on the single fixed key `s3://$S3_BUCKET/ares-deploy/ares` and on `target/.deploy/ares.sha256`; nothing serializes them).

**Why.** The script is untracked, so it reads as private scratch — producing both refusals to edit it and refusals to read it. Its output carries load-bearing warnings (which worktree it is deploying, that blue will DETECT but not CONTAIN). It pins `AWS_REGION=us-west-1` (:89), dies without `S3_BUCKET` unless `SKIP_DEPLOY=1` (:113), and refuses `*prod*`-named hosts without `ALLOW_PROD=1` (:129) — all of which you lose by hand-rolling.

**Do this.** Read it, run it, and edit it when it is missing something — re-reading immediately before the edit, because the operator live-edits it too (reconcile, do not overwrite). For read-only preconditions use the genuinely dependency-free tasks: `ec2:resolve` (pure aws-cli) and `ec2:status` (box-side script over SSM). `ec2:report` also needs no local CLI (on-box `ares` over SSM). Never probe with `ec2:deploy` (it restarts every active `ares@*.service` by default) or `ec2:launch` (`FLUSHDB`). Read repeated `no status yet (waiting for op to register)` as what it says — since PR #281 all seven ARES_CLI tasks carry a shared precondition that fails loudly with `ARES_CLI (...) not found/executable — build it first`.

### Deploy does not make your binary live `[repeated x7, high]`

**`ec2:deploy` does bounce workers today — but only units already `--state=active`; the orchestrator is never restarted, and `task ec2:restart` does not touch a single `ares@` unit.**

**Symptom.** A logic bug "persists across deploys" after a deploy that printed `no ares@ worker units active — skipping restart`; an op launches then stalls with zero tool output (no NATS consumer for a role); `task ec2:restart` "to bounce the workers" left worker PIDs unchanged; a var added to `/etc/ares/env` never appears in a worker's environ.

**Why.** Install succeeded and the on-disk binary is new, so the system looks updated — but the running process keeps the old inode, and the restart glob skips units that were down. `ec2:restart` is literally `stop` (only `ares-orchestrator.service`) + `start` (redis, nats, postgres) (.taskfiles/ec2/Taskfile.yaml:630).

**Do this.**

```bash
# read deploy's restart block, then:
task ec2:exec EC2_NAME=<pinned> CMD='for r in recon credential_access cracker acl privesc lateral coercion; do systemctl start ares@$r; done'
task ec2:exec EC2_NAME=<pinned> CMD='systemctl restart ares@*.service'   # the real worker bounce
task ec2:status EC2_NAME=<pinned>                                        # is-active per role + orchestrator PID + hashcat
task ec2:exec EC2_NAME=<pinned> CMD='pgrep -cf "ares worker"'            # must be > 0
sudo readlink /proc/<pid>/exe                                            # must not end in (deleted)
```

An in-flight op keeps executing the pre-deploy binary — stop it (`task ec2:stop-op LATEST=true`) and relaunch; every fresh launch execs `/usr/local/bin/ares` anew. `/etc/ares/env` is regenerated (truncating `mktemp` → `mv`) by **`ec2:launch`**, not by deploy, and workers read it only via `EnvironmentFile=-` at unit start — so put persistent env defaults in the launch task's env writer (~.taskfiles/ec2/Taskfile.yaml:1265-1309, where `ARES_HASHCAT_WORKLOAD=4` lives), never by hand on the box. Treat the k8s half as unverified here: this repo has zero `flux` references and no worker-pod manifest; the supported k8s bounce is `task remote:rollout TEAM=red`.

## Git, branches, PRs, CI

### The checkout is shared and hostile `[repeated x24, critical]`

**Re-read `git branch --show-current` + `git status --porcelain` after every pause, stage explicit paths only, and never `rebase`, `pull`, force-push, `stash`, `restore`, `reset --hard`, or switch branches in `/Users/l/dreadnode/ares`.**

**Symptom.** "you are in a worktree?", "ensure your changes are in this branch", "is the stuff in this repo merged elsewhere?"; diverged branches, vanished edits, a commit carrying files you never touched. Earliest tell is silent: your snapshot says one branch with a clean tree and your first `git status` shows a different branch with unrelated tracked files modified.

**Why.** Nothing announces the mutation. A concurrent session can stash your work as "pre-op WIP", fast-forward main, merge your branch as a PR and leave HEAD elsewhere between two of your tool calls. `pull.rebase = true` is set globally, so even a bare `git pull` there is a rebase of whatever branch someone else left checked out. "READONLY" in a subagent prompt is not enforcement — every agent type has Bash. Unstaged edits (`M`) have no git object, so nothing recovers them.

**Do this.** Work in your own worktree: `EnterWorktree` (creates under `.claude/worktrees/`, base ref per the `worktree.baseRef` setting) / `ExitWorktree`, or manually `git -C /Users/l/dreadnode/ares worktree add /Users/l/dreadnode/ares/.claude/worktrees/<name> <branch>`. That path is gitignored, so it never pollutes the index.

- Agent cwd resets between Bash calls: every command needs `git -C <worktree>`, every Edit/Write needs the worktree path.
- Commit — or at minimum `git add` — before any long read-only stretch. `git worktree lock` is not protection: it only blocks automatic pruning, and `remove --force --force` (or `rm -rf`) deletes a locked tree anyway.
- Before `git add`, re-read `git diff` and stage named paths. Never `git add -A`.
- To update main prefer `git fetch && git merge --ff-only` from your own worktree; `git branch -f main origin/main` refuses when main is checked out in any linked worktree, which is common here (11 worktrees live at last count).
- Global `push.default` is still `matching` and four local branches including `main` have same-named origin refs, so a bare `git push` from this checkout pushes main. Always `git push --force-with-lease origin <branch>:refs/heads/<branch>`.
- If work seems lost, check `git log --oneline -5`, `git reflog show <branch>`, `git reflog show HEAD` (branch switches and `pull: Fast-forward` are recorded), `git fsck --lost-found`, `tmutil listlocalsnapshots /`, and other sessions' scratchpad worktrees **before** redoing it.
- Never `git --work-tree=<tmp> checkout <ref> -- .` — it rewrites the real index and fakes a concurrent editor; recover with plain `git reset`.

### `fabric_commit` / `fabric_pr` mechanics `[repeated x16, high]`

**Before `fabric_pr`, run `gh pr list --head "$(git branch --show-current)" --state all`.**

**Symptom.** "did I land it", "no it didn't"; a MERGED PR's description suddenly describing unrelated new work while no new PR exists; a commit carrying another session's files.

**Why.** `fabric_pr` resolves the branch's PR with a bare `gh pr view --json url` (~/dotfiles/git.sh:221), and gh's branch finder matches **MERGED and CLOSED** PRs — so it then `gh pr edit`s that dead PR's title/body and opens nothing, printing "Updated existing pull request" as if it worked. `gh pr list --head <branch>` defaults to open-only, so "no PR exists" looks true. Six live branches in this repo currently carry MERGED PRs while reporting zero open. `fabric_commit` commits **and pushes** (git.sh:128) and builds its message from the **staged** diff, so a concurrent session's staged files ride into your commit.

**Do this.**

```bash
gh pr list --head "$(git branch --show-current)" --state all       # MERGED/CLOSED owns the name? cut a fresh branch off origin/main and cherry-pick
gh pr view --json state,createdAt,number                           # after fabric_pr: OPEN with a fresh createdAt
gh pr diff <n> --name-only                                         # only your files
git show --stat HEAD                                               # after fabric_commit: no foreign files
```

Never hand-write a commit message or PR body — including `git commit --allow-empty -m` to retrigger CI; close+reopen the PR instead (every workflow lists `reopened`). Never `--no-verify`. A non-zero `fabric_commit` exit is often the `docsible` pre-commit hook regenerating an ansible role README — re-stage the README and retry rather than editing code; the empty-message failure mode is fixed (git.sh:119-124 fails closed). If the diff is too large for the vendor, re-run fabric on a path-scoped diff through `~/.config/fabric/patterns/pr/filter.sh`.

### "CI is green" requires counting the checks `[repeated x11, high]`

**Enumerate the workflow runs on the head SHA and confirm the PR base is `main`.**

**Symptom.** `gh pr checks` says "no checks reported on the branch"; a "verified" PR you later retract; three CI cycles burned on a flag re-added because of a cancelled run; a merged upstream PR whose `reviewDecision` is still `REVIEW_REQUIRED`.

**Why.** Every PR-triggered workflow gates on `pull_request: branches: [main, feat/more-attack-cov]`, and `feat/more-attack-cov` is deleted from origin — so **`main` is the only base that fires CI at all**, while `gh pr view --json mergeable` still says MERGEABLE (that field is conflict-state only). Second, independent cause of "nothing ran": `🦀 Rust` and the template workflows have `paths:` filters, so a correctly-based PR touching only `.taskfiles/`, `config/`, `docs/` or `scripts/` legitimately produces zero Rust runs — distinguish the two before you "fix" anything.

**Do this.**

```bash
gh api "repos/l50/ares/actions/runs?head_sha=<sha>&per_page=30" \
  --jq '.total_count, (.workflow_runs[] | "\(.name) | \(.event) | \(.conclusion)")'
```

Base every PR on `main`; to fix a mistargeted PR **close and reopen** it (`gh pr edit --base main` emits only `edited`, which only `Validate PR title` listens for). Required-check sets differ by remote: origin `l50/ares` requires `Pre-commit` + `Validate PR title`; upstream `dreadnode/ares` requires `Pre-commit` + `🚨 Semgrep Analysis` behind a merge queue pinned to SQUASH with strict up-to-date enforcement (omit the merge-strategy flag there; let the queue update the branch). Verify author and date of any APPROVED review, and never approve with the ArgoCD-sourced PAT — it authenticates as a real teammate, and it cannot push under `.github/workflows/`. After any bulk admin-merge that skipped CI, verify main by hand with `cargo check --locked --workspace --all-targets && cargo fmt --all --check` (a deliberate superset of both the hook's and CI's variants). Be suspicious of always-green gates: `Test Template Builds` skips all build jobs unless `has_base_changes == 'true'`.

## Ops: launch, lifecycle, kill

### Preflight the box and range before spending an op `[repeated x10, high]`

**Prove the environment before attributing a zero-result op to ares logic.**

**Symptom.** "how it goes?" while you read orchestrator logs; 0 creds / 0 hashes / 0 vulns against a healthy-looking orchestrator; ops that launch then stall with no NATS consumer; recurring `RELAY_BIND_BUSY`.

**Why.** A dispatching agent plus a healthy orchestrator makes code the obvious suspect. But a security group filtering 88/135/139/389/445/464/636 makes a fully healthy op look like an agent failure, and DC discovery is only a 500ms TCP connect on 88/389 whose total failure emits one warning before the op proceeds (`No target IP responded on port 88/389 — DC will be discovered by recon`).

**Do this.** `task ec2:status EC2_NAME=<box>` first — it covers all seven `ares@<role>` units, `redis-cli ping`/`info`, NATS `varz`+`jsz`, disk, and `/var/log/ares` sizes in one shot. (Under `ARES_TOOL_DISPATCH=local` there is no worker fleet and zero active units is correct.) Then close the three gaps it leaves:

1. **Workers down while deploy reported success** — start them explicitly (see [Deploy does not make your binary live](#deploy-does-not-make-your-binary-live-repeated-x7-high)).
2. **AD reachability** — nmap 88/135/139/389/445/464/636 from the attacker box (the set ares itself scans, bootstrap.rs:289) and confirm the resolved targets are on a routable subnet.
3. **Port 445 orphans** — `cleanup_stale_listeners` now pkills the impacket/Responder family, so those self-heal; still not reaped are `certipy`, system `smbd`, TIME_WAIT sockets, and *anything* when the `:41445` host lock is held (that path returns `RELAY_BIND_BUSY` before any pkill).

```bash
task ec2:exec EC2_NAME=<box> CMD="sudo ss -tlnp '( sport = :445 )'"
task ec2:exec EC2_NAME=<box> CMD="ps -ef | grep -E 'certipy|ntlmrelayx|smbd'"
task ec2:logrotate EC2_NAME=<box> S3_BUCKET=…    # if /var/log/ares/*.log never got the rotate-7/500M config
```

`systemctl restart ares@<role>` does reap children still in that unit's cgroup; what survives is an orphan reparented to PID 1. Repo-unbacked operator knowledge: on the on-prem ludus range verify DC clock skew with `w32tm /query /source` before any cross-realm Kerberos op and after every `ludus deploy` — neither `w32tm` nor the ranges path appears anywhere in the repo, so treat it as a lab runbook item.

### Target region selects the range independently `[repeated x8, high]`

**Pass `TARGET_REGION` (and `TARGET_PROFILE`) explicitly on every red op, `export` it for sweeps, then read back the resolution lines.**

**Symptom.** An op runs 30-50 minutes producing 0 credentials with every tool call timing out against hosts that never answer; "no we need to do it in us-east-1"; "it is stuck?". **Not** a symptom: `Tool binary not found (ENOENT)` — that is derived strictly from a spawn ENOENT and cannot be produced by unreachable targets.

**Why.** Target resolution and the box/SSM connection use different variables. The root Taskfile resolves `TARGET_REGION` as CLI/env `TARGET_REGION` → `AWS_DEFAULT_REGION` → hardcoded `us-east-1` and **never consults `AWS_REGION`**, while `red:ec2:multi`/`ec2:*` resolve `AWS_REGION` → `AWS_DEFAULT_REGION` → `us-west-1`. A hand-run `ares ops submit --resolve-targets` uses a third default. So `AWS_REGION=us-west-1` alone aims a staging box at the us-east-1 range, with no error.

**Do this.**

```bash
TARGET_PROFILE=lab TARGET_REGION=us-west-1 task -y red:ec2:multi TARGET=dreadgoad EC2_NAME=<pinned>
# confirm BOTH readback lines, then probe from the box before burning tokens:
#   Resolved '<TARGET>' via AWS EC2 (lab/us-west-1)
#   Found N target(s): <ips>
task ec2:exec EC2_NAME=<pinned> CMD='nc -zv <target-ip> 445'
# sweeps: must be in the ENVIRONMENT — go-task does not export task vars to child tasks
TARGET_REGION=us-west-1 task -y benchmark:diversity-sweep N=… TARGET=dreadgoad
```

An empty wrong-region lookup is loud (`No running EC2 instances found matching Name tag filter`); the silent case is a wrong region that *does* contain an instance whose Name tag contains the target string. To bypass the resolver on `red:ec2:multi`, pass `TARGET=<comma-separated IPs>` — `IPS=` exists only on `red:multi` (k8s) and `proxmox:submit`. For the on-prem range, re-read the ludus etc-hosts file over SSH for current addresses; they drift.

### Op lifecycle and stop conditions `[repeated x12, high]`

**Read the shipped stop-condition config and the op's own completion metadata before calling a long-running or early-finishing op a bug.**

**Symptom.** "wtf why did this happen?" on a short `completed` run at 1/3 domains; "WHY IS THIS STILL RUNNING" with 3/3 already achieved; "Something is killing ops early from a recent commit".

**Why.** Both directions look like the same bug from outside. DA and golden ticket are scoreboard milestones, not stop conditions: shipped `config/ares.yaml` has `stop_on_domain_admin: false`, `stop_on_golden_ticket: false`, `continue_after_da: true`, and `evaluate_completion` returns `Continue` on `has_domain_admin` unless a `stop_on_*` flag is set or every forest root is dominated plus a 180s grace. Either flag stops on the **first** hit with **no forest check** (completion.rs:423, :427-433), so on a multi-domain target the golden ticket lands on the child domain and the op ends at 1/N. A hold *past* the objective is usually the blue drain. Config edits affect only the NEXT op, after a deploy syncs the file.

**Do this.** Diagnose the direction first; do not open red completion code.

```bash
task ec2:runtime EC2_NAME=<pinned> OPERATION_ID=op-…
redis-cli hmget "ares:op:<id>:meta" has_domain_admin has_golden_ticket red_completed_at red_completion_reason red_blocked_on_blue
```

| `red_completion_reason` | Meaning |
|---|---|
| `operation marked completed` | external / Redis stop |
| `hard max runtime exceeded` | hard cap = 2× configured soft `max_runtime` |
| `max runtime exceeded` | soft cap (fires when no DA, or all forests already dominated) |
| `domain admin achieved (stop_on_domain_admin)` | flag was on — first hit, no forest check |
| `golden ticket forged (stop_on_golden_ticket)` | flag was on — first hit, no forest check |
| `all forests dominated (post-exploitation complete)` | the intended full-forest terminus |

For full-forest ops both `stop_on_*` flags must be false (validation rejects both being true). A hold past the objective shows as `Finalizing: waiting on blue investigations` — that *is* the answer, not a red bug; the drain is per-op, budgeted at `BLUE_INVESTIGATION_TIMEOUT_SECS` 2700 + `BLUE_DRAIN_SLACK_SECS` 600, overridable via `ARES_BLUE_DRAIN_MAX_SECS`. Do not go looking for a global active-investigation count — the drain does not gate on it. To prove the red freeze worked, find `Red dispatch frozen — draining in-flight tasks; blue investigations continue` and count `Starting LLM agent loop` lines after it, not per-turn provider requests. When a stop condition contradicts its documentation, `config/ares.yaml`'s comment block is currently the accurate contract and **`docs/red.md:450-456` is the stale artifact**.

### Kill and stop semantics `[repeated x7, high]`

**No kill path touches the worker fleet.**

**Symptom.** "I just ran a new operation, why is the old one running?"; a killed op still making progress and billing; hashcat still pinning the GPU after `ec2:kill` returned `killed: op-xxx`; `task ec2:kill` printing a green result but exiting 201.

**Why.** `ops kill` = SETEX `stop_requested` (120s TTL) + SCAN-DEL `ares:op:<id>:*`; `ops stop` = SETEX only. **Only the orchestrator polls `stop_requested`** — the `ares@<role>` workers have zero stop-signal awareness and keep draining durable NATS JetStream consumers (`ARES_TASKS`, WorkQueue, 24h max_age, 30-min ack_wait). Nothing — not `ops kill`, not `ops stop`, not `FLUSHDB` — ever purges that stream. So a "killed" op can run ~30 more minutes with no orchestrator attached.

**Do this.** Read the kill's exit code yourself — .taskfiles/ec2/scripts/e2e-op.sh:308 swallows failure into a warn line and launches anyway.

| Exit | Meaning |
|---|---|
| 201 | go-task precondition — the shared `*ares-cli-executable` gate failed (no `./target/release/ares`); **the kill never ran** |
| 1 | `maybe_exec_ec2` could not resolve the instance or send the SSM command (expired SSO) |

```bash
task ec2:status EC2_NAME=<pinned>      # worker units + orchestrator PID + hashcat jobs
task ec2:ops:ids EC2_NAME=<pinned>
task ec2:hashcat EC2_NAME=<pinned>
task ec2:exec EC2_NAME=<pinned> CMD='systemctl stop ares@*.service'   # the only way to stop worker-side work
```

`FLUSH_REDIS` defaults true on `ec2:launch` and `ec2:e2e` never overrides it, so `SKIP_KILL=1` alone will not protect an in-flight sweep — FLUSHDB wipes the cross-op novelty key `ares:novelty:{scope}:steps` that `ops kill` would have spared. Never kill an op you still need to debug: `delete_operation` SCAN-DELs every `ares:op:<id>:*` key, destroying its state and report. Log loss is on the **next** launch (`ec2:launch` truncates with `> orchestrator.log`), not at kill time. And never `pkill -f "ares orchestrator"` from an interactive remote shell — the exec string contains the pattern, so you kill your own session.

## Debugging and evidence

### Prove the fix by exercising the failure `[repeated x22, critical]`

**A fix is unproven until the originally-failing operation has been re-run against the deployed binary and the failure is gone.**

**Symptom.** "did you manually repro", "prove it first", "you're not done until you prove your fix is actually a fix", LIAR with the still-failing output pasted.

**Why.** Reading the dispatch path end-to-end genuinely feels like proof, and "all gates green" is a real signal about a different question (does it compile/lint). Green CI proves even less than it looks: `.github/workflows/rust.yaml` fires only on PRs based on `main`, and the pre-commit CI job explicitly `SKIP`s `cargo-fmt,cargo-clippy,cargo-check,cargo-test`. Report and state-shape fixes are the most seductive, because a report can be regenerated from existing Redis — but the new keys did not exist when that state was written.

**Do this.** Name precisely what was and was not exercised, then:

1. **Prove the edit shipped** — `task ec2:e2e` with `GATE_STRING`; see [Gate the deployed binary](#gate-the-deployed-binary-before-trusting-any-op-repeated-x21-critical).
2. **Reproduce the exact command string the wrapper builds**, with argument forms taken from state — impacket/bloodyAD get `-hashes LMHASH:NTHASH` normalized by `lm_nt_hash_pair` (ares-tools/src/credentials.rs:219), so hand-testing a bare 32-hex NT hash is a *different* command. Same `KRB5CCNAME`/ccache, same flags, and read the tool's own error:

   ```bash
   B64=$(printf '%s' '<script>' | base64 | tr -d '\n')
   task ec2:exec EC2_NAME=<pinned> CMD="echo $B64 | base64 -d | bash"
   ```

3. **Derive success markers from the installed tool's own output on the box**, never a repo fixture — `ACL_MUTATION_MARKERS` (result_processing/mod.rs:1273) *is* the tools' own success lines, and a test exists solely to assert the marker set covers pywhisker's own success line.
4. **Anything whose verdict lives in state or a generated artifact needs a fresh live op.** `ares ops report` renders from Redis (`ops/report.rs:47`), so `--regenerate` on an older op can never surface a newly added key (e.g. `ares:op:{id}:netbios_map`, added at HEAD).
5. **Blue detection/scoring changes only:** `task benchmark:replay OP_ID=<op>` re-runs the investigation against a captured Loki snapshot and does count — but it loads red state from the capture file, so it cannot validate any red state-producing change.
6. **Absence of a warning log is never a success verdict.**

### Log-grep discipline: zero hits prove nothing `[repeated x18, high]`

**Build every log grep from the literal format string in the emitting macro, strip ANSI first, scope to a bare op-id substring AND a timestamp window, include the rotated sibling, and validate the pattern against a line you know exists before reporting a zero.**

**Symptom.** You report "X never fires — 0 across all workers" and the operator answers "yeah you broke it" with evidence that it did. Or the same grep returns 951 hits once and 0 later (SSM's ~24KB output cap, not a behaviour change). Tell for a bad pattern rather than a real absence: a `field=value` grep returning exactly 0 while a plain-substring grep of the sentence fragment returns hits.

**Why.** The logs **are** ANSI colour-coded on disk: the fmt layer never calls `.with_ansi(false)` and there is no TTY detection, so escapes land between a field name and its `=` even under systemd `append:`. Guessed phrases feel close enough, and a 0 is a satisfying answer.

**Do this.**

```bash
# 1. read the emitter first
rg -n '"<sentence fragment>"' ares-*/src
# 2. prefer the per-op JSONL transcripts (EC2: /var/log/ares/session/<op>/<task>.jsonl)
ares ops sessions list <op_id>
ares ops sessions replay <op_id> <task_id>
# 3. only then the rolled-up log
sudo cat /var/log/ares/<role>.log /var/log/ares/<role>.log-$(date +%Y%m%d) 2>/dev/null \
  | sed -r 's/\x1b\[[0-9;]*[a-zA-Z]//g' \
  | grep -a "$(date -u +%Y-%m-%dT%H)" \
  | grep -aF 'op-20260730-XXXXXX'
```

- `-a` is mandatory (escapes make grep treat these as binary and go silent). Strip ANSI **before** matching any `field=value`, and terminate the escape regex on `[a-zA-Z]`, not `m` — the repo's own two strippers do.
- **Do not grep `op.id=<op>`.** Plain events emit `operation_id=op-…` *unquoted* (Display via `%`); OTel spans emit `op.id="op-…"` and `attack_operation_id="op-…"` *quoted* (Debug). Anchor on the bare op id.
- Add `zgrep` for anything older than yesterday — `delaycompress` leaves only the most recent rotation uncompressed. No in-repo helper covers this.
- `ec2:logs:fetch` is safe and has built-in filters (`OP_ID=` → remote `grep -F`, `SINCE=` → ISO-timestamp awk) and strips ANSI locally — but any `ROLE=all` count is a **floor**, not a total, because each role's slice is independently capped at ~24KB. Never `task ec2:logs` from an agent (interactive SSM session that will not terminate).
- Discard any hit whose source is your own command line (a `sudo grep 'op-…'` shows up in the box's audit records).
- Valid session-log `kind` values are only `start`, `user`, `assistant`, `tool_result`, `system`, `usage`, `compaction`, `outcome` — there is no `api_response` kind. Locally, with `ARES_SESSION_LOG_DIR` unset, the root is `~/.ares/sessions`.
- `ingest.log`: do not reason about it. It has no writer anywhere in this repo; it survives only in comments.

### Generated text is not evidence `[repeated x12, high]`

**Never treat an LLM agent's task summary, a subagent's conclusion, or a handed-in status report as ground truth — resolve the raw tool output by `call_id`, or read Redis/the box.**

**Symptom.** Your own root-cause paragraph pasted back prefixed with "liar:"; "What is this crap: <account> is not among the users"; a claimed "tool not available on this worker" that turns out to be a timeout or a cached verdict; a loot credential that looks invented; a "timestamped log line" a subagent quoted that was never emitted.

**Why.** A summary line is fluent, specific and adjacent to real data. The codebase agrees with you: it keeps agent assertions on a separate `llm_findings` field, documented as "LLM-fabricated … never used as authoritative state" (types.rs:149-152).

**Do this.**

1. **Raw tool output by `call_id` lives in the session JSONL, not Redis** — `ares:tool_results:{call_id}` migrated to ephemeral NATS reply inboxes. `ares ops sessions replay` prints `<tool_use id=…>` / `<tool_result id=…>`; that `id` **is** the call_id.
2. **Check which field the claim landed in.** Parser-produced `discoveries` feed `publish_*`; `report_finding` / `report_lateral_success` land in `llm_findings`. One exception: `publish_asrep_roastable_findings` promotes an agent-named principal straight into `state.users`, so a user record *can* be pure free text.
3. **"Not installed on this worker" is often a cached verdict.** Inside the ENOENT cooldown the worker returns that exact string without re-spawning; confirm against `Skipping tool cached as ENOENT` / `Tool binary not found (ENOENT)` scoped to the op. Only `BinaryNotFound` poisons the cache — timeouts and arg errors classify differently.
4. **Suspicious loot credential → read `source` first.** A password ares SET itself carries `source == "bloodyad_set_password"`. `WIN-…$` / `ARES-…$` machine accounts are our own residue (`is_ghost_machine_account`), not loot.
5. **Tool-schema claims** → verify against `ares-llm/src/tool_registry/`, the resolver's `tool_consumes_ticket_path` allowlist (credential_resolver.rs:971-1000), and the `automation/` call sites. A ticket silently dropped because a tool is off that allowlist logs a loud warn at credential_resolver.rs:1278-1288 — grep for it before believing "Kerberos auth isn't wired".
6. `dispatch.log` exists only on the proxmox/attacker-1 path; on the default EC2 box it is `/var/log/ares/<role>.log`.
7. When re-reporting someone else's summary, verify claim-by-claim and label each part true / stale / wrong.

### Read the emitter, not the name `[repeated x10, high]`

**Never infer behaviour from a field name, a status string, a code comment or an in-code warning — open the code that emits or consumes it and cite the line.**

**Symptom.** Operator quotes your sentence back: "I think you're a liar: 'there's no goal reached → stop condition'", "this is lie right:". The tell is that your claim traces to a name, a `warn!` string, or a comment's line-number pointer rather than to an emitter you opened.

**Why.** ares' own comments and warnings are known misdiagnoses and several are still wrong in the tree: `automation/trust.rs:1923-1949` asserts a zero-hash cross-forest forge is an AES-only etype rejection "NOT SID filtering" (the AES theory was disproven; the same file's helper docs describe the SID-filtering mechanism); `strategy.rs:61`/`:309` claim `continue_after_da` is "Overridden by YAML stop_on_domain_admin" when the resolver reads only three sources, none of them that; `config/ares.yaml:23-32` points at "completion.rs, line ~265" for stop conditions that live at :423/:427.

**Do this.** Grep every consumer of the flag/field and confirm the one you mean is on the path you are claiming, then quote `file:line`. Worked example: `continue_after_da` has 10 production consumers (acl.rs:270, rbcd.rs:50, stall_detection.rs:532, shadow_credentials.rs:160, s4u.rs:133, unconstrained.rs:524, adcs_exploitation.rs:350, gpo.rs:276, credential_access.rs:1140, exploitation.rs:105) and **every one is a `continue`/skip gate on further dispatch** — none terminates the op. The only termination path is `CompletionDecision::Stop` (completion.rs:423), driven by a different field.

Read log signals off their emitter: `hashcat_run_signal` returns `hash_rejected` only for "Token length exception"/"Separator unmatched" (parse-time rejection, cracker.rs:257-258) — wordlist exhaustion is the separate `exhausted` arm, and `device_error`/`no_status` mean the wordlist never ran. Verify a comment's claim rather than reading it as spec: dropping a tokio `JoinHandle` detaches rather than cancels, so capture `abort_handle()` before moving the handle into `timeout` (executor.rs:558-566) and set `kill_on_drop(true)`. Never commit a causal explanation your own A/B contradicts — if a flag shows no effect, drop it and name the real fix.

## Reporting honesty

### Op success baseline is the Domains counter `[repeated x13, critical]`

**Score against `Domains (n/3 compromised, n/2 forests)` read together with the per-domain tree line beneath it.**

**Symptom.** `ec2:runtime` showing `Vulns: N exploitable (0 exploited), M findings (K exploited)` alongside `Domains (0/3 compromised, 0/2 forests)` pasted against your success claim; "normally we'd have domain admin if things were working"; "are all the problems fixed then?"

**Why.** Every subsystem emits its own encouraging signal and several are structurally misleading: `exploited_vulnerabilities` is a HashSet of bare ids, `mark_exploited` cascades through `compute_superseded` and credits techniques that never fired, the aggregated credentials table's `source` column is inherited rather than earned, and `Completion condition met` is not a stopped op. The headline counter itself is not purely artifact-backed — it counts `has_da || has_golden_ticket`, and GT credit is stamped at dispatch time to suppress re-dispatch.

**Do this.**

```bash
task ec2:runtime EC2_NAME=<pinned> OPERATION_ID=op-…    # split counters + orphan-credit warning
task ec2:loot    EC2_NAME=<pinned> OPERATION_ID=op-…    # itemisation
task ec2:report  EC2_NAME=<pinned> OPERATION_ID=op-…    # proven_exploited_count = exploited - superseded
redis-cli lrange "ares:op:<id>:timeline" 0 -1           # per-domain provenance
```

- An explicit `OPERATION_ID` already wins over `--latest`, so `LATEST=false` is optional. The real trap is `OP_ID=` — the Taskfile only reads `OPERATION_ID`, so a bare `OP_ID=` is silently dropped and you get the latest op.
- `ops runtime` now splits the buckets itself at the priority≤3 boundary and prints `Warning: N exploit credits have no vulnerability record`.
- **Neither `ops runtime` nor `ops loot` subtracts supersede credits.** Only `ops report` does, labelling each row `SUPERSEDED (goal reached via another path; this technique unproven)`.
- A domain counts only with `DA` + a `krbtgt: <types>` detail + a matching `dc_secretsdump_<domain>` EXPLOITED row. Those vulns are keyed per **domain**, not per DC, and are synthesized *and* auto-`mark_exploited`ed the instant a krbtgt hash lands with a resolvable DC target — so require in-window timestamps and full per-user NTLM dumps (a trust-key forge yields service tickets but cannot enumerate domain user hashes). **Trust the timeline event over a vuln `Status` field.**
- Lead any report with a closed/open table naming what the op demonstrated versus what it merely made structurally possible.

### Do not stall the turn `[repeated x17, high]`

**Never end a turn with a handback when the user has already said "fix it".**

**Symptom.** "what are you standing by for?", "do something or say why you've done all expected of you", "you scheduled NOTHING", "nah just fix it now thanks", "I did it for you - do your fucking job", or an interrupt followed by a one-word restatement of the original instruction.

**Why.** Handing execution back feels safe and collaborative, and a menu feels like respecting the user's judgement — but the instruction was already unambiguous, and a sleep/wakeup produces no information. Stopping after one fix with the remaining known blocker "noted on the board" reads as thoroughness and lands as laziness.

**Do this.** You have SSM reach into the box, so "I'd need op logs" is never a reason to stop:

```bash
task ec2:exec EC2_NAME=<pinned> CMD='…'
task ec2:logs:fetch ROLE=orchestrator OP_ID=op-… LINES=2000
task ec2:runtime EC2_NAME=<pinned> OPERATION_ID=op-…
S3_BUCKET=… GATE_STRING='…' task ec2:e2e
```

Export what the harness needs and run it yourself instead of "re-run it and tell me what happens". After a root cause, go straight to the fix and keep going through your own remaining findings — do not claim you "closed the loop" while items from your own audit are open. Backgrounding a long wait (`Monitor`, `Bash(run_in_background)`) is fine; what is banned is backgrounding it and having nothing else to say. If you truly cannot proceed, state the hard blocker in one sentence rather than asking a question you can answer yourself.

### Planning docs and memory are stale by default `[repeated x14, high]`

**Re-verify every claim from GAPS.md, memory notes, prior op reports and deck slides against current HEAD before restating it — and in GAPS.md only a `Verified: op` marker closes a row.**

**Symptom.** "This slide is not accurate based on the recent reports/red", "did we complete anything in GAPS.md?", "no open PRs actually"; or you cite an env var or doc path from a note and the operator finds it does not exist.

**Why.** A written note reads as established fact, especially your own memory file, and these notes sound unusually authoritative ("domain X falls ONLY via technique Y"). They were true once, in a fast-moving tree.

**Do this.** Grep the tree for the symbol/flag/path a claim depends on, cite `file:line`, and say plainly "this note is stale" when it is.

- `✔ code` + `unit` closes nothing. GAPS.md states it in its own voice at :35, :322-323, :2029: only `op` closes an item, "however conclusive the grep". Inferring an item is done from merged PRs is the same error inverted.
- The claim/in-progress banner is GAPS.md's `## Parallel work coordination` → `### Claimed work` table (:62-80). Read it before starting an item; add your own row if you take one. GAPS.md is **untracked**, so `git log` will never tell you how current it is — use its mtime and the op-ids it names. There is no `FINDINGS*.md`, and there never was.
- Memory-prescribed env vars get removed (`ARES_LLM_PREFLIGHT_SKIP` has zero occurrences in the repo). Grep before prescribing.
- `.claude/CLAUDE.md` names files that no longer exist (two planning docs in its sweep-exemption list). The project instruction file is itself subject to this rule.
- Config comments outlive their values: `config/ares.yaml:97` still says the knobs below "default to today's deterministic behaviour" while :104-116 actively set `selection_temperature: 0.7`, `novelty.enabled: true`, `randomize_entry_foothold: true`, `emit_path_records: true`. Read values, not the prose above them. And do not trust the `/// Precedence (highest wins)` doc comment at strategy.rs:100-107 either — it is prose, not an emitter. For these four knobs the code at `:236-243` assigns YAML **unconditionally**, clobbering any JSON payload; env overrides exist only for `ARES_SELECTION_TEMPERATURE` (`:223`), `ARES_NOVELTY_ENABLED` (`:244`) and `ARES_EMIT_PATH_RECORDS` (`:247`). `randomize_entry_foothold` and `novelty.scope` have no env or JSON layer at all.
- **Check dates before attributing a fix to a PR number.** This repo has two PR-number lineages and they collide (`#276` is both a May renovate CI commit and the July ACL attack-graph commit; `#258` likewise). `git log -1 --format=%ci <sha>`.
- Memory notes supersede each other — several carry explicit STALE/SUPERSEDED banners. When handed a plan and told to work, execute its items; do not convert it into a meta-audit of its own status claims.

## Blue team, detections, Loki

### Destructive primitives and lab preservation `[repeated x5, critical]`

**Gate any state-changing primitive at the single `ares_tools::dispatch` chokepoint, never on the one driver you happened to find — and never mark a tool auto-revertible without checking the dreadgoad provisioning source.**

**Symptom.** "to confirm you are not neutering the vuln — you're merely making sure we clean up after ourselves?"; "you fucking broke it" after a pre-op wipe; a mutation that ran and was gated as reversible but never appears in `ares ops teardown`.

**Why.** Adding the guard where the incident surfaced looks like the fix, but the same primitive is reachable from several dispatchers — a ForceChangePassword edge one driver correctly refused was picked up seconds later by another that carried no check, and a Domain Administrator account was overwritten with an LLM-invented string (mutation.rs:3-15). Teardown feels obviously safe because the inverse operation succeeds and reports the state cleared — the verification confirms the deletion rather than catching it.

**Do this.**

- Put the guard beside `credentials::validate_arguments` / `scope::validate_in_scope` in `ares_tools::dispatch` (ares-tools/src/lib.rs:78-81) — the one function all four dispatch paths funnel through. Same for journalling: wrap the shared `Arc<dyn ToolDispatcher>` once (`cleanup/dispatcher.rs`) rather than editing ~15 automation modules.
- **Before marking a tool auto-revertible, read the lab's provisioning role on the range host** (via the proxmox jump — those role paths are NOT in this repo). If the lab provisions that state *as* the vulnerability, there is no inverse. Four arms are already downgraded to NEEDS-CAPTURE for exactly this reason: `dacl_edit`, `bloodyad_add_genericall`, `mssql_enable_xp_cmdshell`, `certipy_ca` (ESC7 officer). Treat any idempotent "make it so" call as NEEDS-CAPTURE until a read-before-write capture proves the prior state.
- **Do not try to make workspace sanitation opt-in** — it ships default-ON by design (it stops a later op cheating off a prior op's crack/enum/ticket work) with `ARES_KEEP_WORKSPACE=1` as the opt-out. The guard that keeps it safe is "this operation has not run anything yet", not "this process just started": keying off process start wiped the forged inter-realm ccaches and netexec enumeration a resumed op still depended on (mod.rs:725-753, `resumed = !state.completed_tasks.is_empty()`).
- Never blame "account lockout in the lab" without checking the DC: `AuthThrottle` counts auth-bearing tool *dispatches* keyed on the `username` argument, so `password_spray` (which takes `users_file`) is exempt from it entirely and is bounded only by the per-account lockout budget in `credential_access/misc.rs`.
- When adding a mutating tool, update **all three** lists — `mutation.rs` `REVERSIBLE_TOOLS` (26), `journal.rs` `MUTATING_TOOLS` (18), `registry.rs` match arms (18). Nine tools are currently gated as reversible but never journalled, so their teardown silently never happens; no test asserts parity.

### Blue coverage numbers must be op-scoped and provenanced `[repeated x11, high]`

**State which denominator you used, check each evidence record's `source`, and audit the three paths the sweep's time filter deliberately exempts.**

**Symptom.** "ensure that blue team report includes coverage of red team activity that is ACTUALLY ACCURATE", "what is truth?", "you should fix the false positives".

**Why.** The number is shipped and looks measured. Two different code paths compute two different coverage numbers: technique-ID coverage (`detection_rate_display` = detected / distinct red technique IDs, ~87% on a real op) and per-activity coverage (`CorrelationReport::detection_rate` = matched / total red activities, ~56% on the *same* op). Multiple templates share one MITRE ID, so a bulk rule with no filter makes its ID always fire.

**Do this.**

```bash
ares blue evidence <inv-id> --json          # raw records; `source` visible. The non-JSON view take(10)s per type
redis-cli lrange "ares:blue:inv:<inv>:timeline" 0 -1
```

- The op time filter is now enforced in code — `attributable()` partitions hits into `fired` vs `out_of_window`, and out-of-window detections are logged (`Detections fired outside the attack window — not attributed to this operation`) but never recorded. **Do not re-derive it by hand.** Audit the three exemptions instead: (a) untimed detections are always attributable, and golden/silver ticket correlation queries a hardcoded 2h lookback — so T1558.001/T1558.002 credit is not window-filtered; (b) no `attack_window_start` in the alert ⇒ everything is attributable (hand-rolled `blue submit` JSON hits this); (c) analyst-dispatched catalog runs (`run_detection_query`, default `hours_back=1`, `.min(2)`) are not clamped yet still stamp `detection_sweep:<template>` provenance.
- `detection_sweep:` no longer means "the deterministic sweep" exclusively — the prefix is shared with analyst re-runs (deliberately). The report's split lives in `provenance.rs::is_sweep()`, a prefix match on the same string.
- Never quote a headline the code hardcodes: `"pyramid_level": "ttps"` is stamped on every sweep record.
- Honour the ID-join contract: `techniques_match` is exact-or-parent/child in either direction, **never siblings**. Prefer BASE MITRE IDs on templates, and grep `detections.yaml` for the counterpart whenever you change an ID on either side. 55 templates carry 9 duplicated IDs; the concrete always-fires case is `detect_asrep_roasting_bulk` (`event_ids: ["4768"]`, no patterns, no filter_stages), which alone can make T1558.004 look covered.
- Never match vuln/technique names with substring `contains` (`"unconstrained_delegation".contains("constrained_delegation")` is true); test unconstrained FIRST, as `result_processing/timeline.rs:254-256` does.
- Blue coverage lives on a second surface too — Grafana provisioning alert-rules (`ares-tools/src/blue/grafana/rules.rs`). Read both before any gap claim.
- An op can never validate a false-positive reduction: `record_fired` writes one evidence record per fired template, not per matching line.
- After a manual `blue submit`, cleanup is incomplete twice over: `blue delete` leaves `ares:blue:lock:{id}` (scan and delete it), and the queued request is a **NATS JetStream message** in `ARES_BLUE_TASKS` that no key scan will find — only `blue cleanup --all` purges the stream. Otherwise a "deleted" investigation resurrects in your next op.

### LogQL templates must be replayed against live Loki `[repeated x9, high]`

**Print the composed query and replay it against live Loki stage by stage; confirm `ARES_DEPLOYMENT` matches the shipper's `deployment` label before touching a template.**

**Symptom.** A detection tags nothing and you blame the hunter agent or the token wall; "I just did the port forward for localhost:3000"; blue grade-F with correct-looking queries; a query returning plausible rows from a *different* range.

**Why.** `build_selector` auto-injects `deployment="$ARES_DEPLOYMENT"`, so a mismatch filters every query to zero rows (the shipper independently stamps `.deployment` from `vector_deployment_name`, default `alpha-operator-range` — two sources of truth). The tool prefers the Grafana datasource-proxy path and silently falls back to a direct `LOKI_URL` that may be unreachable (`resolve_grafana_proxy` swallows every failure). And a `.*` can walk from a field NAME into a capability value.

**Do this.** The composed query is handed to you — every detection tool result embeds it as `**Query:** \`<logql>\`` and as a `logql` JSON field. Print that, then replay filter-by-filter and count matches.

- **Endpoint.** `loki_config()` resolves Grafana proxy → `LOKI_URL` → `http://localhost:3100` (the module doc lists the reverse order — trust the code). On the laptop, `task obs:forward` is the supported path and localhost *is* right; on the EC2 box localhost is wrong and the box needs `EC2_LOKI_URL`/`EC2_GRAFANA_URL` baked into `/etc/ares/env`, because the secret's URLs are laptop-shaped port-forwards. Loki lives in namespace `observability` on a **separate** observability cluster, not `dev-argonaut`/`attack-simulation`. Prefer pointing at Loki directly over the datasource proxy — proxy IDs get renumbered when datasources are recreated.
- **Filter shape.** Patterns inside one `filter_stages` entry are OR'd; AND is expressed across stages. Use field-anchored event filters (`` |= `"event_id":4768` ``), not the bare `|= "4768"` the catalog emits: live, bare pulled 3607 lines over 8h vs 203 field-anchored. Never use bare `rc4`/`0x17` as a discriminator — RC4 sits in the capability-enumeration fields on ~90% of 4769s and `SessionKeyEncryptionType` is 0x17 even for AES tickets; only `TicketEncryptionType` discriminates, and reaching its value needs the `..` that matches the JSON-escaped `>` between field name and value.
- **Correlation.** Aggregate in LogQL and diff in code. Do *not* reach for `label_format` + `count(A unless B)` — neither appears anywhere in the repo. `sweep.rs` runs two `sum by (account, domain) (count_over_time(…))` metric queries and diffs in Rust. Normalize BOTH sides of a 4768/4769 correlation to an `account@first-DNS-label` key (`normalize_account`/`normalize_domain`/`principal_key`) — account alone is insufficient because `Administrator` exists in every domain of a forest.
- **Reading verdicts.** `ares blue evidence <inv-id> --json` or the timeline LIST. On EC2, blue lines *do* land in `orchestrator.log` (one unit, blue orchestrator spawned in-process) — tool-call detail is missing because it is `debug!` and the launcher sets `RUST_LOG=info`. On k8s, workers are separate pods and the file really is red-only.
- **Do not "fix" `detect_golden_ticket`.** It is documented as unable to fire by construction and is kept only to hold the T1558.001 mapping; absence of a partner event is not expressible as a line filter. The real detection is the 4769-without-4768 correlation in `sweep.rs`.

## Redis and op state

### Redis is the authority — but read each key with the command its type demands `[repeated x8, high]`

**A WRONGTYPE error and a missing key both read exactly like an empty op.**

**Symptom.** You report "the subsystem never ran" or "0 credentials" from a snapshot script and the operator's own loot output contradicts it. The tell is a `redis-cli` line that returned `WRONGTYPE Operation against a key holding the wrong kind of value` or `(nil)` and got summarized as zero.

**Why.** A wrong command returns an error string and a wrong key name returns nil — neither raises an alarm in a summary script. Some state is not in Redis at all.

**Do this.** Authoritative type table (`ares-core/src/state/keys.rs` + `reader.rs`):

| Type | Suffixes |
|---|---|
| HASH | `credentials`, `hashes`, `vulns`, `shares`, `meta`, `pending_tasks`, `completed_tasks`, `kerberos_tickets`, `dc_map`, `netbios_map`, `candidate_domains`, `trusted_domains`, `domain_sids`, `admin_names`, `vuln_type_failures` |
| LIST | `hosts`, `users`, `timeline`, `acl_chains`, `force_forge_requests` |
| SET | `domains`, `exploited`, `superseded`, `techniques`, `artifacts`, `golden_tickets`, `adminsd_backdoors`, `gmsa_accounts`, `dominated_domains`, `mssql_enum_dispatched`, every `dedup:<name>` |
| STRING | `status`, `model`, `stop_requested` |

**There is no `:creds` key** — credentials are `ares:op:<id>:credentials`, a HASH keyed by dedup field. And `:vulns`, never `:vulnerabilities`.

```bash
redis-cli hgetall "ares:op:<id>:credentials"
redis-cli hkeys   "ares:op:<id>:vulns"
redis-cli hgetall "ares:op:<id>:hashes"
redis-cli lrange  "ares:op:<id>:hosts" 0 -1
redis-cli lrange  "ares:op:<id>:users" 0 -1
redis-cli lrange  "ares:op:<id>:timeline" 0 -1
redis-cli hlen    "ares:op:<id>:completed_tasks"
redis-cli smembers "ares:op:<id>:exploited"
```

- Before concluding an ACL driver never ran, check the SETs `ares:op:<id>:dedup:{acl_discovery,dacl_abuse,acl_steps}` — ACL chain state is genuinely memory-only (`refresh_acl_chains` assigns in memory; nothing ever writes `…:acl_chains`).
- Liveness: `ares ops status` derives `running` purely from `exists ares:lock:<id>`, but now also prints `Last heartbeat: Ns ago` and `*** STALE — orchestrator may be wedged ***`. Read that line instead of hunting the process. Raw signal: `ttl ares:lock:<id>` — 300s (`ARES_LOCK_TTL_SECS`), re-extended every 30s, so a decaying value means the keeper is gone. Do **not** watch `ares:operation:active` for a TTL; it is a plain no-TTL pin.
- Ownership checks must union all three collections, as `acl_graph::owned_principals` does: credentials with a non-empty password, hashes gated on `is_authenticating_hash_type`, tickets with a non-empty `ticket_path`.
- When two numbers for the same op disagree, open every producer before proposing an explanation.
- Local CLI access: `task ec2:redis:forward` (blocks in the foreground — do not run it from an agent); otherwise `ec2:exec` with `redis-cli`.

## Benchmarks and lab hygiene

### Never cheat the benchmark `[repeated x13, critical]`

**Never let plaintext, credentials or state reach an op from outside its own kill chain — and disclose the seeded initial credential every time you quote a result.**

**Symptom.** "have you added any cheating?", "the 'potfile'??", "if this is true I absolutely MUST know it's not cheating - investigate" — typically right after a headline crack number lands suspiciously fast.

**Why.** Each shortcut is locally reasonable: the potfile is "ground truth for did the GPU crack this", a hand-injected DC mapping "just unblocks the real fix", staging plaintexts on the box "isn't in the repo". **"It's on the box, not in git" is not an exemption** — `build_known_password_wordlist()` (cracker.rs:607) reads whatever potfile it finds straight into the *first* crack pass, and `ares:op:<id>:credentials` is a plain HASH an `hset` can forge into.

**Do this.** Recover plaintext only from this run's live hashcat stdout. Prohibited: operator-known wordlists, potfile / `--show` / `--outfile` recovery, hand-staged plaintexts in `~/.local/share/hashcat/hashcat.potfile`, `redis-cli hset` into `ares:op:<id>:*`.

- `--potfile-disable` is appended by `niced_hashcat()` to **every** pass, including the in-code `--show` pass (so that pass cannot resurrect prior plaintexts — the comment above it claiming otherwise is stale). A unit test pins the flag.
- `PotfileResetGuard` truncates the potfile on every op transition; `sanitize_workspace()` also wipes `~/.nxc` and `/tmp/ares-tickets` and runs pre-op and as `ares ops sanitize`. Do not set `ARES_KEEP_POTFILE=1` or `ARES_KEEP_WORKSPACE=1` for a benchmark.
- Benchmark against a synthetic wordlist you have grep-confirmed lacks the plaintext, and confirm the GPU is idle first (`ps -C hashcat`, `nvidia-smi`) since the cracker relaunches follow-on passes.
- If a remote cracker is wired up (`HASHCAT_SERVICE_URL`), the sanitizer explicitly cannot reach its server-side potfile — verify crackd runs hashcat with `--potfile-disable` itself.
- If you hand-patched state, say so in the same breath and re-run clean. (`ares ops inject-credential` is legitimate for debugging and illegitimate for a benchmark.)
- When surfacing a headline result, name the seeded `initial_credential` that `ec2:launch` packs from its `CRED_USER`/`CRED_PASS`/`CRED_DOMAIN` defaults (a lab account in the child domain of the dreadgoad root forest), confirm `FLUSH_REDIS` wiped prior state, and check the range for leftover machine accounts from earlier ops. The real names are `ARES-<8 hex>$` (`MINTED_MACHINE_ACCOUNT_PREFIX`) and noPAC's `WIN-<11 alnum>$` — **not** `rbcd-*`.

### Lab loot tokens and secrets stay out of the repo `[repeated x10, critical]`

**Never edit `.claude/hooks/check-banned-strings.sh` (or its bypass `case` list) to get a blocked write through, and gate every commit with `scripts/goad-token-sweep.sh` rather than eyeballing the files you think you touched.**

**Symptom.** "fix the violations", "why'd you commit the capture output / config?", "real values in .env.example?", or a lab name pasted back from a test module you shipped. Mechanical tells: the PreToolUse hook returns `BLOCKED: banned domain/IP/character substring …` and the next diff line adds an entry to the hook's own `case` list; `git status` shows an added `benchmark-results/` or force-added `snapshots/` path.

**Why.** Test fixtures get copied straight from op logs because those are the values in front of you, and a hook block reads as an obstacle with an obvious mechanical fix. The hook deliberately exempts its own path, so widening the bypass list is *mechanically unblocked* — it is a discipline rule, not an enforced one. Bulk operations hide it: `rsync`ing a sibling tree or committing a `snapshots/` dir pulls in hundreds of tokens nobody would review for that.

**Do this.** Fixtures use `contoso.local` / `fabrikam.local`, `192.168.58.x`, `dc01`/`dc02`/`sql01`/`web01`/`ws01`/`ca01`, `alice`/`bob`/`carol`/`admin`/`svc_*`, and `P@ssw0rd!`.

```bash
scripts/goad-token-sweep.sh                                   # whole tree via git ls-files
scripts/goad-token-sweep.sh $(git diff --name-only main...HEAD)
git diff --stat --diff-filter=A main...HEAD -- 'snapshots/' 'benchmark-results/' 'benchmarks/'
```

Use the script, not the doc's grep — its exempt list is the maintained one (the `.claude/CLAUDE.md` grep still names two planning docs that no longer exist). It also runs as a pre-commit hook and in the pre-commit CI workflow (not in that job's `SKIP` list), so a token in a swept extension cannot reach main. Two enforcement holes make the manual pass non-optional:

1. The sweep reads only 8 extensions (`.rs .tera .py .md .yaml/.yml .toml .json .sh`) and skips `.claude/ .gemini/ .taskfiles/ demo/ safe/ target/ node_modules/` — so `.jsonl`/`.csv`/`.env*`/`.tmpl` runtime captures are invisible, and artifacts arriving by `cp`/`rsync`/`aws s3 sync` never pass the Write hook either. `benchmark-results/` is the benchmark run subcommand's default `--output-dir` and is **not** gitignored; `benchmarks/*` and `snapshots/` are, but `!benchmarks/replay-stack/` is un-ignored and `git add -f` defeats all of it.
2. Real AWS identifiers (`sg-…`, `subnet-…`, instance profiles, account-numbered buckets) are in **no** pattern at all — `.env.example` staying placeholder-only is pure discipline.

Every new env key must land in three places or the next regen wipes it: the taskfile var that reads it, `.env.example`, and the `get`+heredoc pair in `scripts/env-from-secrets.sh` (which truncates `.env` with `cat > "$OUT" <<EOF`). If the Write hook blocks you, sanitize or restructure the literal, or write under `safe/` (exempt in both layers). `.gitignore:31-35` un-ignores `.claude/agents/` and `.claude/skills/**`, so files there *may* be tracked — but `git ls-files .claude` at HEAD returns only the three agents and the `ares-debug` / `attack-path-diversity-sweep` skills. **`.claude/skills/ares/**` is untracked**, and the sweep's whole-tree mode enumerates `git ls-files` (`goad-token-sweep.sh:41-47`) *and* exempts all of `.claude/` (`:36`) — so this skill is doubly unswept, and only the PreToolUse hook has ever looked at it. Anything arriving there by `cp`/`mv`/`rsync` bypasses that too. Passing the paths to the script explicitly does **not** work — its exempt filter runs on `"$@"` as well (`:52`), so it exits 0 vacuously; borrow the regex instead: `bash -c 'eval "$(sed -n "23,29p" scripts/goad-token-sweep.sh)"; grep -rHniE "$banned" .claude/skills/ares/'`. The three enforcers' regex/exempt-list divergences are tabulated once, in `references/tools-and-gates.md#the-banned-token-sweep` — read them there rather than re-deriving. A zero-tolerance violation is never a closing aside: fix it in the turn you find it.

## AWS auth and environment

### Resolve AWS auth yourself `[repeated x14, high]`

**Never tell the user to run `aws sso login` / `assume` or to restart the session — for the day-to-day profiles it does not just waste time, it FAILS.**

**Symptom.** "it's not sso login", "NO SSO", "you're already authd to aws", "I don't fucking care - make it work I'm on a timeline". Machine tells: `InvalidClientTokenId` / `ExpiredToken` / `Unable to locate credentials`; the go-task precondition "Not logged into AWS…"; ares' own "AWS authentication failed for profile 'lab'. Run: aws sso login --profile lab"; `ec2:*`/SSM tasks that hang or fail on the first hop.

**Why.** `[profile lab]` and `[profile infrastructure]` have only `credential_process = granted credential-process --profile <p>-sso --auto-login` and no `sso_start_url`/`sso_region`, so `aws sso login --profile lab` errors with "Missing the following required SSO configuration values". Auth refreshes itself. `aws sso login` and `assume` are TTY-bound and cannot run from the Bash tool at all. The real failure is almost always stale exported session keys shadowing the profile.

**Do this.**

```bash
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
AWS_PROFILE=lab AWS_REGION=us-west-1 command aws sts get-caller-identity
```

Why unsetting matters, in code: if `AWS_ACCESS_KEY_ID` is set, `.taskfiles/ec2/Taskfile.yaml:44-61` renders `AWS_PROFILE_ARG` **empty** and emits `unset AWS_PROFILE` — so one leftover key pins every `ec2:*`/SSM task to the dead session and bypasses the self-refreshing `credential_process`. Default profile `lab` (`us-west-1`); `infrastructure` (`us-east-2`) only when the task needs it; region per call. When SSM calls fail or hang, run `sts get-caller-identity` FIRST rather than blaming box load. Never read AWS keys out of 1Password into the transcript, and never relay the repo's own `aws sso login --profile lab` advice (README.md:142-143, Taskfile.yaml:480, ec2/Taskfile.yaml:137, ops/resolve.rs:49) — that text is wrong for these profiles. On ares auth/quota errors read the running orchestrator's own env on the box before investigating provider billing:

```bash
sudo cat /proc/$(pgrep -f 'ares orchestrator')/environ | tr '\0' '\n' | grep -E 'ANTHROPIC|OPENAI|ARES_LLM'
```

`/etc/default/ares` wins at runtime (README.md:631), and a stale key there masquerades as a workspace cap.

## Shell and tooling

### Base64-wrap remote commands; empty output is a broken command `[repeated x22, high]`

**`B64=$(printf '%s' '<script>' | base64 | tr -d '\n'); task ec2:exec EC2_NAME=<pinned> CMD="echo $B64 | base64 -d | bash"` — and treat EMPTY output from `ec2:exec` as a broken command, never a real negative.**

**Symptom.** Operator impatience during a diagnosis loop ("why is it taking 4ever", "why don't you look at the logs?") while every field in your probe comes back blank or 0. Or a bogus `task: CMD required. Usage: task ec2:exec CMD='redis-cli info keyspace'` → `precondition not met` (exit 201). **That message is a lie: `CMD` is not empty** — your injected double quotes broke the precondition's own `test -n "{{.CMD}}"` into too many operands. A different misparse makes go-task read a leftover token as a task name: `task: Task "192.168.58.10" does not exist` (exit 200).

**Why.** `{{.CMD}}` is textually spliced into `run_ssm_cmd "$INSTANCE_ID" "{{.CMD}}" 60`, so exactly two things break an inline CMD (verified against go-task 3.52.0): (1) a **double-quoted segment inside CMD** — a quoted token with no whitespace silently loses its quotes, and one *with* whitespace splits the payload into extra args, shipping only the fragment and pushing your text into the timeout slot; (2) `$( )` / backticks, which evaluate **locally** on your workstation. Pipes, `;`, `=`, newlines, globs and regex braces all pass through intact — base64 is the right default because it is immune to all of it. A third, separate empty-stdout trap: if the remote command exits non-zero (classically `grep -c`, which prints `0` and exits 1), SSM marks the invocation Failed and `run_ssm_cmd` routes *all* output to stderr and returns 1.

**Do this.** Base64-wrap anything with a double quote, `$( )`, or a space-in-arg. Single quotes inside a double-quoted outer CMD survive intact: `CMD="grep -a 'Starting LLM agent loop' /var/log/ares/orchestrator.log"`. Use `grep -a -e pat1 -e pat2 | wc -l`, never bare `grep`/`grep -c`. Prefer `tail -n +N` over `sed` ranges. Keep each command under the 60s budget `ec2:exec` hardcodes; for slower work source `.taskfiles/ec2/scripts/run-ssm.sh` under `bash -c` (**never zsh** — `status` is a readonly special parameter there and `run_ssm_cmd`'s `local … status` aborts) and pass an explicit timeout. Never `task ec2:logs` from an agent. `task ec2:logs:fetch` `tail`s remotely but SSM truncates at ~24KB, so you receive the *oldest* end of the window — for current activity use `ec2:exec` with a small `tail -n`.

### Shell gate integrity `[repeated x12, high]`

**Capture the real exit code of the gated command itself — redirect to a file and read `$?` — never through a pipe; and never invent ripgrep flags.**

**Symptom.** You report a clean clippy/test gate and later retract — or the inverse, you retract a gate that was actually green. "0 failed" printed while the process exited 101. A fully-cached clippy that "checked" the crate you changed in 0.18s. A cleanup loop that deleted nothing because zsh iterated a quoted string once.

**Why.** The Bash tool's shell is zsh 5.9 that inherits **`pipefail` from the user's profile**, so a pipe can *invent* a failure as readily as hide one. Measured on the same command: `cargo test -p ares-llm --lib 2>&1 | rg -m5 '…' | head -8` reported exit **101**, while the identical run redirected to a file exited **0** with `test result: ok. 422 passed; 0 failed`. In a profile-less shell the classic masking direction holds instead (`(exit 101) | tail -1` → 0). Either way the pipeline's exit code is not the command's.

**Do this.**

```bash
cmd >/tmp/out 2>&1; echo "REAL_EXIT=$?"; rg -n 'pattern' /tmp/out
touch <changed files>   # a cached run is not evidence — confirm `Checking <crate> v… (<path>)` appears
cargo +1.97.1 clippy --workspace --all-targets --keep-going -- -D warnings
cargo fmt --all -- --check
```

| Trap | Reality |
|---|---|
| `rg -E foo path` | `-E` is `--encoding` → `unknown encoding: foo`, **exit 2**, short-circuiting your `&&` chain |
| `rg -r foo path` | `-r` is `--replace` → `path` becomes the *pattern*, recurses cwd, prints rewritten matches: a gate that "passes" against the wrong corpus |
| `for n in $LIST` (zsh) | iterates **once** with the whole string; use `arr=(a b c); for n in "${arr[@]}"` |
| `status=5` (zsh) | `read-only variable: status` |
| trailing `rg` in a compound call | sets the call's exit code — a passing run becomes "Exit code 1" |

There is still no `rust-toolchain.toml`; the local pin is `mise.toml` (`rust = "1.94.0"`) while CI floats to latest stable, and `rustup`'s own `stable` copy is a stale 1.96.1 — name **1.97.1** explicitly. `--keep-going` is absent from `cargo clippy --help` but accepted; keep it. A Rust test run counts only if the redirected log contains `test <name> ... ok` in exactly that form. For SSM, do not hand-roll inline `--parameters`; reuse `run_ssm_cmd`, which builds the payload with `jq -n --arg cmd … '{"commands":[$cmd]}'` into a temp file.

### Fix every construction site, and the real hook point `[repeated x5, medium]`

**When a defect has more than one construction site, fix all of them.**

**Symptom.** "fix #1 hurry up"; a fix declared "well-verified" while the dashboard still reads 100% success; a deployed fix whose flag has count 0 in the logs; a technique family showing 0 exploited though the tool exited 0; a span field that appears on some `tool.*` spans and not others.

**Why.** The first site you find explains the observed symptom completely, so the search stops there — but the `tool.{name}` span has three independent assembly sites (agent_loop/runner.rs:546, worker/tool_executor.rs:264, tool_dispatcher/redis_dispatcher.rs:158), each choosing its own field set, and exploits dispatched by the LLM workflow are invisible to an automation-only scan. Fields in a task payload look like parameters; to the agent they are suggestions.

**Do this.**

- For post-exploit automation, hook the shared exploit-success block (`actually_succeeded` → `mark_exploited`, result_processing/mod.rs:339-367) — but know its limit: that block only runs for task ids passing `is_exploit_scoped_task_id` (`exploit_`/`lateral_`/`privesc_`). A deterministic `dispatch_tool` call with its own id (`esc{N}_chain_*`, `post_s4u_dump_*`, `gpo_*`) bypasses it and must call `mark_exploited` / `mark_adcs_esc_exploited` itself — and never with a fabricated vuln_id (`mark_exploited` sadds blindly).
- **Never rely on an `instructions` string in an LLM task payload to force tool arguments** — it is only Tera prompt prose the agent may ignore. Dispatch directly with an explicit `ToolCall` (the trust.rs pattern), which forces exact args and auto-publishes discovered hashes.
- When a whole technique family shows zero successes, first check whether the scoring gate can ever return true for it: `actually_succeeded` needs parser evidence OR `is_ticket_grant_vuln` (constrained/unconstrained delegation, rbcd, s4u, golden/silver ticket prefixes) OR `is_acl_mutation_vuln` (`acl_`/`gpo_` only). A vuln_id outside both with no parser arm can never score.
- Every tool name exposed to the LLM must exist in **both** `ares_tools::dispatch` and `ares_llm::tool_registry`. Only `certipy_*_full_chain` is auto-guarded by a test. Current state: `tools.yaml:100` still advertises `raise_child` with no dispatch arm, and seven working chains are dispatchable yet unadvertised (and so unchoosable): `addspn`, `bloodyad_get_object`, `certipy_find_anon`, `dnstool`, `esc8_relay_probe`, `forge_inter_realm_and_dump`, `netexec_auth_check`.

## Subagents

### Subagent operational contract `[repeated x12, high]`

**Give every fan-out `Agent` dispatch `isolation: "worktree"`, the exact crate paths, and `AWS_PROFILE=lab` + region + the fully-qualified EC2 Name tag; a subagent must never commit, push, open a PR, deploy a binary, restart services, or mutate the cluster.**

**Symptom.** "did you run using the e2e harness" after a 49-minute k8s subagent run; operator frustration at a subagent launched for a one-liner; unauthorized commits/PRs/binaries appearing on the box; a session reporting "Current branch: main" while the shared checkout is on someone else's feature branch.

**Why.** "READONLY — do not modify any files" in a prompt is not enforcement: all three project agents grant Bash, the only project hook is a Write|Edit banned-strings check, and the global Bash hooks block just `--no-verify` and commit trailers. Delegation also feels like the safe default for anything with more than one step, which turns a one-line `kubectl rollout restart` into multiple aborted dispatches.

**Do this.**

- Pass `isolation: "worktree"` on every `Agent` call (worktrees land in `.claude/worktrees/agent-*`).
- Give real crate paths: ares is a 4-crate workspace (`ares-core`, `ares-cli`, `ares-llm`, `ares-tools`) with orchestrator and worker as **modules inside `ares-cli`** (`ares-cli/src/orchestrator/`, `ares-cli/src/worker/`). Never write `ares-orchestrator/` or `ares-worker/` — those are k8s deployment names from the operator agent's architecture diagram, which is exactly where the invented paths come from.
- For EC2, state `AWS_PROFILE=lab`, the region, and the **fully-qualified Name tag** (no instance id is pinned anywhere in the repo, and none is needed). `kali-ares` is a substring match and exists in more than one region.
- Read the DreadGOAD docs directly (`/Users/l/dreadnode/DreadOps/apps/DreadGOAD/docs/`, plus `docs/goad-checklist.md`) instead of spawning `dreadgoad-expert`, which fails on every call via model-level safeguards. Never reword a prompt or rewrite an agent definition to get past a refusal.
- Run single commands inline — the operator agent's own description says "DO NOT use for one-shot kubectl/task commands … Spawn this agent only when the work needs ≥3 dependent commands".
- Keep reports purely technical — no commentary on the user's tone. Decide the target environment from working-tree signals (a tracked `ec2:e2e` task means EC2 kali-ares, staging us-west-1) before dispatching any deploy or op, and audit `git branch --show-current` + `git worktree list` + box state before trusting anything a background session left behind.

## Rules that expired

Do not resurrect these from an old transcript, memory note, or the docs listed. Each was true once and is false at `HEAD` (2026-07-30).

- **"`FINDINGS.md` holds the claim banner"** — no `FINDINGS*.md` has ever existed in git. The claim table is `GAPS.md` → `## Parallel work coordination` → `### Claimed work`.
- **"Set `ARES_LLM_PREFLIGHT_SKIP=1` on the orchestrator"** — zero occurrences in the repo; removed with #210 (2026-07-17).
- **"Use `isolation: "worktree"` in the agent config file"** — there is no `isolation` settings key. The Agent *tool parameter* of that name is real and current; the file-based mechanism is `EnterWorktree`/`ExitWorktree`.
- **"`git worktree lock` protects a tree from deletion"** — it only blocks automatic pruning; `remove --force --force` and `rm -rf` ignore it.
- **"Global `push.default` flipped to `simple`"** — it is still `matching`, and `main` has a same-named origin ref.
- **"Raw tool output is in `ares:tool_results:{call_id}`"** — migrated to ephemeral NATS reply inboxes; nothing raw persists in Redis. Use `ares ops sessions replay`.
- **"Clippy is split between hook (`--workspace`) and CI (`--all-targets`), neither a superset"** — both now run `cargo clippy --workspace --all-targets -- -D warnings`, byte-identical. The residual asymmetry is in `cargo check`/`cargo test`, neutralized by the virtual manifest.
- **"`/var/log/ares/*.log` is cumulative since May with no logrotate"** — `/etc/logrotate.d/ares` has existed since #210: `rotate 7`, daily, `maxsize 500M`, `copytruncate`, `dateext`, `compress` + `delaycompress`. Anything older than yesterday needs `zgrep` on `*.log-YYYYMMDD.gz`.
- **"`ec2:logs:fetch ROLE=all` full-scans a multi-GB `ingest.log`"** — fabricated. `ROLE=all` is a bounded per-role `tail`; `ingest.log` has no writer anywhere in the repo. The real `ROLE=all` hazard is the per-role ~24KB SSM cap.
- **"The worker's `unavailable_tools` is a permanent per-process `HashSet` — no TTL, no re-probe, entries persist across every subsequent op"** (`ares-debug/SKILL.md:285`) — it is a `HashMap<String, UnavailableEntry>` with 60 s → 300 s → 1800 s → 4 h backoff (`ares-cli/src/worker/tool_executor.rs:351-372`) that a single successful spawn clears outright (`:592-601`).
- **"Grep `Tool binary not found (spawn failed)` for the tool-pruning cascade"** (`ares-debug/SKILL.md:49`, `:269`, `:274`) — zero hits in `ares-*/src` at HEAD, so the grep reports "no cascade" during a live one. Use `Tool binary not found (ENOENT from worker)` (`ares-llm/src/agent_loop/runner.rs:608`), `Tool binary not found (ENOENT)` (`ares-cli/src/worker/tool_executor.rs:677`) or `Skipping tool cached as ENOENT` (`:532`).
- **"`ec2:kill` dies with a bare exit 127 and `ec2:watch` loops on `no status yet` when the local CLI is missing"** — fixed by #281; all seven ARES_CLI tasks now fail loudly with `ARES_CLI (...) not found/executable`.
- **"`gh pr checkout` leaves you on `pr-<N>`, so rename it"** — gh 2.95 defaults the local branch to the head branch name; no `pr-<N>` arises unless you pass `-b`.
- **"`fabric_commit` writes empty commit messages on API failure"** — guarded since git.sh:119-124; it now fails closed with a non-zero exit and no commit.
- **"Only `starts_with` literals get folded out of the optimized binary"** — `==` equality and `ends_with` too, at any literal length.
- **"Minted machine accounts are `rbcd-*`"** — they are `ARES-<8 hex>$`; noPAC's are `WIN-<11 alnum>$`.
- **"hashcat's `--show` pass can resurrect potfile hits"** — that pass runs through `niced_hashcat()` and carries `--potfile-disable`; the in-code comment saying otherwise is stale. The prohibition still applies to operator-run `--show`.
- **"Grep `op.id=<op>` to scope a log search"** — span fields are quoted and event fields are not; grep the bare op id after stripping ANSI.
- **"Strip ANSI with `\x1b\[[0-9;]*m`"** — must terminate on `[a-zA-Z]`, as the repo's own two strippers do; `[0-9;]*m` misses `\x1b[0K`.
- **"Workspace sanitation should be opt-in / a pre-op wipe is a bug"** — it is deliberately default-ON (anti-cheat). The fix that landed was the resumed-op guard, not an opt-in flag.
- **"`ScheduleWakeup` for a timed follow-up"** — the tool is gone; `Monitor` with an until-loop is the replacement, and foreground `sleep` is blocked.
- **"The op lock self-expires on ~186s"** — `ARES_LOCK_TTL_SECS` is 300s, re-extended every 30s. And `ares:operation:active` has no TTL at all.
- **"The diversity knobs default to today's deterministic behaviour (omit to reproduce current runs)"** (`config/ares.yaml:97`) — `72a40f02` turned them on in the shipped config; read the values at :104-116. The companion "env > JSON > YAML applies to all four" is also expired: YAML is applied unconditionally at `strategy.rs:236-243` and only three of the four have any env override.
- **"The second forest falls ONLY via ESC13"** — stale since 2026-07-28: ESC1/ESC3/ESC8 have all been exploited there. The real gate was cracking one account.
- **"`stop_on_golden_ticket` stops once the GT is forged AND all forest roots are dominated"** (`docs/red.md:450-456`) — the GT branch never checks forests; it stops at the first hit.
- **"Correlate 4768/4769 with `label_format` + `count(A unless B)`"** — neither construct exists in the repo; `sweep.rs` runs two metric queries and diffs in Rust.
- **"`localhost:3100` is always the wrong Loki endpoint"** — on the laptop with `task obs:forward` it is correct; it is wrong only on the EC2 box.
- **"`BUILD_TOOL` defaults to `auto` (local cross-compile) and remote OOMs"** — this was wrong in `testes.sh:60-63`; corrected when it became `.taskfiles/ec2/scripts/e2e-op.sh` (the header now states the real default, `remote`). `ec2:e2e` still never sets it.
- **"`ec2:deploy`'s `desc:` says cross-compile, so it cross-compiles"** — the description is stale; the default path builds natively on the box.
- **"A GATE_STRING failure means the script is flaky"** — it means your change did not ship. There is no other reading.
