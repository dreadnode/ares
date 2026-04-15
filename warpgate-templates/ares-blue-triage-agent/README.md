# Ares Blue Triage Agent Warp Gate Template

This template builds the **Ares Blue Triage Agent** image using Warp Gate. It
provides initial incident assessment and alert triage capabilities, with
[Grafana MCP](https://github.com/grafana/mcp-grafana) for querying logs,
metrics, and alert state from a Grafana stack.

---

## Requirements

- [Warp Gate](https://github.com/cowdogmoo/warpgate) installed and configured
- Docker (for building Docker images)
- `ares-base` image built first

---

## Configuration

The template configuration is managed in `warpgate.yaml`. Key settings include:

- `name`: Template name (`ares-blue-triage-agent`)
- `base.image`: Base Docker image (`ghcr.io/dreadnode/ares-base:latest`)
- `provisioners`: Shell provisioners that install Grafana MCP (arch-specific)
- `targets`: Container images for `amd64` and `arm64`

---

## Building Docker Images

**Initialize the template:**

```bash
warpgate init ares-blue-triage-agent
```

**Build Docker images:**

```bash
warpgate build ares-blue-triage-agent --only 'docker.*'
```

---

## Pushing Docker Images to GitHub Container Registry

```bash
docker tag ares-blue-triage-agent:latest ghcr.io/dreadnode/ares-blue-triage-agent:latest
echo $GITHUB_TOKEN | docker login ghcr.io -u YOUR_USERNAME --password-stdin
docker push ghcr.io/dreadnode/ares-blue-triage-agent:latest
```

---

## Validating the Template

```bash
warpgate validate ares-blue-triage-agent
```

---

## Notes

- **Docker build:**
  - Multi-arch (`amd64` + `arm64`) support
  - Default entrypoint: `python -m ares --args.multi-agent`
  - Installs `mcp-grafana` binary to `/usr/local/bin/`
- **Grafana MCP** enables the agent to:
  - Query Loki logs with LogQL
  - Query Prometheus metrics with PromQL
  - List and inspect alert rules and contact points
  - Search dashboards and retrieve panel queries
- **Use Cases:**
  - Initial alert assessment and severity classification
  - Log correlation across multiple data sources
  - Quick incident scoping before escalation

For more information on Warp Gate template configuration, see the
[Warp Gate documentation](https://github.com/cowdogmoo/warpgate).
