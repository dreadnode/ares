# Ares Blue Threat Hunter Agent Warp Gate Template

This template builds the **Ares Blue Threat Hunter Agent** image using Warp
Gate. It provides proactive threat detection and investigation capabilities,
with [Grafana MCP](https://github.com/grafana/mcp-grafana) for deep log
analysis and metric correlation.

---

## Requirements

- [Warp Gate](https://github.com/cowdogmoo/warpgate) installed and configured
- Docker (for building Docker images)
- `ares-base` image built first

---

## Configuration

The template configuration is managed in `warpgate.yaml`. Key settings include:

- `name`: Template name (`ares-blue-threat-hunter-agent`)
- `base.image`: Base Docker image (`ghcr.io/dreadnode/ares-base:latest`)
- `provisioners`: Shell provisioners that install Grafana MCP (arch-specific)
- `targets`: Container images for `amd64` and `arm64`

---

## Building Docker Images

**Initialize the template:**

```bash
warpgate init ares-blue-threat-hunter-agent
```

**Build Docker images:**

```bash
warpgate build ares-blue-threat-hunter-agent --only 'docker.*'
```

---

## Pushing Docker Images to GitHub Container Registry

```bash
docker tag ares-blue-threat-hunter-agent:latest ghcr.io/dreadnode/ares-blue-threat-hunter-agent:latest
echo $GITHUB_TOKEN | docker login ghcr.io -u YOUR_USERNAME --password-stdin
docker push ghcr.io/dreadnode/ares-blue-threat-hunter-agent:latest
```

---

## Validating the Template

```bash
warpgate validate ares-blue-threat-hunter-agent
```

---

## Notes

- **Docker build:**
  - Multi-arch (`amd64` + `arm64`) support
  - Default entrypoint: `python -m ares --args.multi-agent`
  - Installs `mcp-grafana` binary to `/usr/local/bin/`
- **Grafana MCP** enables the agent to:
  - Query Loki logs with LogQL for IOC detection
  - Query Prometheus metrics for anomaly identification
  - Correlate events across dashboards and data sources
  - Inspect alert rules for detection gap analysis
- **Use Cases:**
  - Proactive threat hunting across log sources
  - Hypothesis-driven investigation of suspicious patterns
  - Detection rule validation and gap identification
  - MITRE ATT&CK technique correlation

For more information on Warp Gate template configuration, see the
[Warp Gate documentation](https://github.com/cowdogmoo/warpgate).
