# Ares Rust Blue Triage Agent Warp Gate Template

This template builds **Ares Rust Blue Triage Agent** images using Warp Gate. It supports
building **Docker images** (for `amd64` and `arm64`). The triage agent performs initial
incident assessment and alerting using a compiled Rust binary with embedded Python and
Grafana MCP integration.

---

## Requirements

- [Warp Gate](https://github.com/cowdogmoo/warpgate) installed and configured
- Docker (for building Docker images)
- `GITHUB_TOKEN` environment variable set (for cloning the ares repository)
- Required Packer plugins (installed automatically via `warpgate init`):
  - `docker`

---

## Configuration

The template configuration is managed in `warpgate.yaml`. Key settings include:

- `name`: Template name (`ares-rust-blue-triage-agent`)
- `base.image`: Base Docker image (`ares-base`)
- `sources`: Clones the ares repository for Rust compilation
- `targets`: Defines build targets (container images)

---

## Building Docker Images

This builds **Ares Rust Blue Triage Agent** Docker images for `amd64` and `arm64`
architectures, installs Grafana MCP tooling, compiles the Rust worker binary with
Python bindings, and configures it for incident triage operations.

**Initialize the template:**

```bash
warpgate init ares-rust-blue-triage-agent
```

**Build Docker images:**

```bash
warpgate build ares-rust-blue-triage-agent --only 'docker.*'
```

After the build, Docker images will be available locally as
`ares-rust-blue-triage-agent:latest`.

---

## Local Testing

After building the image, you can test it locally:

```bash
# Run the agent container interactively
docker run -it --rm \
  -e REDIS_URL="redis://localhost:6379" \
  -e ANTHROPIC_API_KEY="your-api-key" \
  ares-rust-blue-triage-agent:latest

# Verify installed components
docker run --rm ares-rust-blue-triage-agent:latest ares-worker --version
docker run --rm --entrypoint mcp-grafana ares-rust-blue-triage-agent:latest --version
```

---

## Installed Tools

- **ares-worker** - Rust-compiled worker binary with PyO3 Python bindings
- **mcp-grafana** - Grafana MCP server for observability integration
- **Ares Python framework** - Agent orchestration and tool execution

---

## Notes

- **Docker build:**
  - Multi-arch (`amd64` + `arm64`) support
  - Default user: `root`
  - Working directory: `/root`
  - Entrypoint: `ares-worker` (compiled Rust binary)
- **Installed Components:**
  - Provided by `ares-base` (Python 3.13.x, uv, Ares framework, dependencies, procps)
  - Rust-compiled `ares-worker` binary with PyO3 Python bindings
  - `mcp-grafana` for Grafana observability integration
- **Build Process:**
  - Installs `mcp-grafana` binary (architecture-specific)
  - Clones ares repository from `feature/rust-cli` branch
  - Compiles Rust binary with `--features python` for Python interop
  - Installs binary to `/usr/local/bin/ares-worker`
  - Cleans up build artifacts

---

## Differences from ares-blue-triage-agent (Python)

| Component | Python | Rust |
| ----------- | ---------------------- | ------------------ |
| Entrypoint | `python -m ares --args.multi-agent` | `ares-worker` (binary) |
| Runtime | Python interpreter | Compiled Rust + embedded Python |
| Build | No compilation needed | Rust compilation with PyO3 |
| mcp-grafana | Included | Included |

---

## Customization

To customize the build, edit the `warpgate.yaml` file:

- Modify `base.image` to use a different base image
- Adjust the entrypoint or environment in the `base` section
- Adjust `targets` to change build platforms

For more information on Warp Gate template configuration, see the [Warp Gate documentation](https://github.com/cowdogmoo/warpgate).
