# Ares Blue Agent Warp Gate Template

This template builds the **Ares Blue Agent** base image using Warp Gate. It
provides the foundation for defensive security operations, built on top of the
`ares-base` image with no additional tooling -- specialized blue team agents
(triage, threat hunter, lateral analyst) extend this image.

---

## Requirements

- [Warp Gate](https://github.com/cowdogmoo/warpgate) installed and configured
- Docker (for building Docker images)
- `ares-base` image built first

---

## Configuration

The template configuration is managed in `warpgate.yaml`. Key settings include:

- `name`: Template name (`ares-blue-agent`)
- `base.image`: Base Docker image (`ghcr.io/dreadnode/ares-base:latest`)
- `targets`: Container images for `amd64` and `arm64`

---

## Building Docker Images

**Initialize the template:**

```bash
warpgate init ares-blue-agent
```

**Build Docker images:**

```bash
warpgate build ares-blue-agent --only 'docker.*'
```

After the build, Ares Blue Agent Docker images will be available
locally as `ares-blue-agent:latest`.

---

## Pushing Docker Images to GitHub Container Registry

```bash
docker tag ares-blue-agent:latest ghcr.io/dreadnode/ares-blue-agent:latest
echo $GITHUB_TOKEN | docker login ghcr.io -u YOUR_USERNAME --password-stdin
docker push ghcr.io/dreadnode/ares-blue-agent:latest
```

---

## Validating the Template

```bash
warpgate validate ares-blue-agent
```

---

## Notes

- **Docker build:**
  - Multi-arch (`amd64` + `arm64`) support
  - Default entrypoint: `python -m ares --args.multi-agent`
  - Inherits all base tools from `ares-base`
- **Directory Structure:**
  - `/ares/` - Main Ares workspace directory
  - `/ares/.venv/` - Python virtual environment
  - `/ares/agents/` - Agent storage directory
  - `/ares/data/` - Data storage directory

---

## Relationship to Other Blue Team Agents

| Agent | Extends | Additional Tools |
| --- | --- | --- |
| `ares-blue-agent` | `ares-base` | None (base blue agent) |
| `ares-blue-triage-agent` | `ares-base` | Grafana MCP |
| `ares-blue-threat-hunter-agent` | `ares-base` | Grafana MCP |
| `ares-blue-lateral-analyst-agent` | `ares-base` | Grafana MCP |

For more information on Warp Gate template configuration, see the
[Warp Gate documentation](https://github.com/cowdogmoo/warpgate).
