# Ansible Collection Development

This collection lives inside the [ares](https://github.com/dreadnode/ares)
repository and is consumed directly from the `ansible/` subdirectory — it is
**not** published to Ansible Galaxy. Changes ship as part of normal ares pull
requests; there is no separate release tag, changelog generation, or
`galaxy.yml` version bump flow.

## Layout

- `ansible/roles/` — role implementations (each with `defaults/`, `tasks/`,
  `meta/`, optional `molecule/` scenarios, and a generated `README.md`).
- `ansible/playbooks/ares/` — playbooks that wire roles together for the ares
  attack box (e.g. `goad_attack_box.yml`, `recon.yml`, `lateral_movement.yml`).
- `ansible/playbooks/{linux,windows}/` — generic provisioning playbooks for
  range hosts.
- `ansible/plugins/modules/` — custom modules (`vnc_pw`,
  `merge_list_dicts_into_list`, `getent_passwd`).
- `ansible/changelogs/` — retained from the upstream collection; no longer
  updated as part of the ares workflow.

## Local Development

### Prerequisites

- Ansible (>= 2.18.4)
- [Molecule](https://molecule.readthedocs.io/) + Docker for role tests
- [pre-commit](https://pre-commit.com/) for linting and doc/diagram regen
- [act](https://github.com/nektos/act) (optional) to run the molecule workflow
  locally

Install the Python tooling used by the hooks and the molecule workflow:

```bash
pip install -r .hooks/requirements.txt
```

### Pre-Commit Hooks

`.pre-commit-config.yaml` runs the following on any change under `ansible/`:

- `ansible-lint` — config at `.hooks/ansible/ansible-lint.yaml`.
- `yamllint` / `markdownlint` / `codespell` / `detect-secrets` — repo-wide.
- `docsible` (`.hooks/ansible/docsible-hook.sh`) — regenerates each
  `roles/*/README.md` from role metadata.
- `update-architecture-diagram` (`.hooks/ansible/gen-arch-diagram.py`) —
  scans `ansible/{roles,plugins,playbooks}` and rewrites the Mermaid block
  in `ansible/README.md` between the `## Architecture Diagram` and
  `## Requirements` markers. Roles/playbooks with a `molecule/` directory get a
  trailing `*` in the diagram.

Install hooks once, then they run on every commit:

```bash
pre-commit install
pre-commit run --all-files   # one-off run across the repo
```

If the diagram hook updates `ansible/README.md`, it exits non-zero so you can
stage the regenerated README and re-commit.

### Running Molecule Locally

Each role/playbook with a `molecule/` directory can be exercised directly:

```bash
cd ansible/roles/<role_name>
molecule test                       # full create / converge / verify / destroy
molecule converge                   # iterate on tasks against a live container
molecule verify                     # re-run assertions only
```

To reproduce the GitHub Actions matrix locally, use `act` against
`.github/workflows/molecule.yaml`:

```bash
act -W .github/workflows/molecule.yaml \
    --input ROLE=<role_name> \
    --input SCENARIO=default
```

ARM64 macOS hosts should pass `--container-architecture linux/amd64` to `act`.

## CI

Two workflows guard ansible changes:

- `.github/workflows/pre-commit.yaml` — runs the full pre-commit suite on PRs.
- `.github/workflows/molecule.yaml` — runs molecule scenarios on changes under
  `ansible/**`, `.github/workflows/molecule.yaml`, or `.hooks/requirements.txt`.
  Also runs weekly (Sunday 04:00 UTC) and supports `workflow_dispatch` with
  `ROLE` / `SCENARIO` inputs to target a single scenario.

## Adding a New Role or Playbook

1. Scaffold under `ansible/roles/<name>/` (or `ansible/playbooks/<group>/`).
2. Add a `meta/main.yml` with `argument_specs` so `docsible` can generate the
   role README on commit.
3. Add a `molecule/default/` scenario; `verify.yml` should assert the
   end-state your role guarantees.
4. Wire the role into the relevant ares playbook under
   `ansible/playbooks/ares/` if it should run as part of the attack box build.
5. Commit — the architecture diagram in `ansible/README.md` will regenerate
   automatically.

## Consuming the Collection

Within ares, playbooks reference roles via the fully-qualified
`dreadnode.nimbus_range.<role>` name. Ansible resolves the collection from the
`ansible/` subdirectory using `ansible.cfg`'s `collections_path` /
`ANSIBLE_COLLECTIONS_PATH`; no `ansible-galaxy collection install` step is
required for in-repo use.

## License

Covered by the repository-wide [LICENSE](../../LICENSE) at the ares root.
