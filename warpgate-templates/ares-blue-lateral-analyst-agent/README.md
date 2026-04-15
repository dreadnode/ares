# Ares Blue Lateral Analyst Agent Warp Gate Template

This template builds the **Ares Blue Lateral Analyst Agent** image using Warp
Gate. It specializes in detecting and analyzing lateral movement activity, with
[Grafana MCP](https://github.com/grafana/mcp-grafana) for querying
authentication logs, network telemetry, and security events.

---

## Requirements

- [Warp Gate](https://github.com/cowdogmoo/warpgate) installed and configured
- Docker (for building Docker images)
- `ares-base` image built first

---

## Configuration

The template configuration is managed in `warpgate.yaml`. Key settings include:

- `name`: Template name (`ares-blue-lateral-analyst-agent`)
- `base.image`: Base Docker image (`ghcr.io/dreadnode/ares-base:latest`)
- `provisioners`: Shell provisioners that install Grafana MCP (arch-specific)
- `targets`: Container images for `amd64` and `arm64`

---

## Building Docker Images

**Initialize the template:**

```bash
warpgate init ares-blue-lateral-analyst-agent
```

**Build Docker images:**

```bash
warpgate build ares-blue-lateral-analyst-agent --only 'docker.*'
```

---

## Pushing Docker Images to GitHub Container Registry

```bash
docker tag ares-blue-lateral-analyst-agent:latest ghcr.io/dreadnode/ares-blue-lateral-analyst-agent:latest
echo $GITHUB_TOKEN | docker login ghcr.io -u YOUR_USERNAME --password-stdin
docker push ghcr.io/dreadnode/ares-blue-lateral-analyst-agent:latest
```

---

## Validating the Template

```bash
warpgate validate ares-blue-lateral-analyst-agent
```

---

## Notes

- **Docker build:**
  - Multi-arch (`amd64` + `arm64`) support
  - Default entrypoint: `python -m ares --args.multi-agent`
  - Installs `mcp-grafana` binary to `/usr/local/bin/`
- **Grafana MCP** enables the agent to:
  - Query authentication and logon event logs
  - Analyze network connection patterns across hosts
  - Correlate SMB, WinRM, RDP, and SSH session activity
  - Detect pass-the-hash, pass-the-ticket, and token impersonation
- **Use Cases:**
  - Lateral movement detection and path reconstruction
  - Authentication anomaly analysis
  - Credential usage tracking across hosts
  - Post-compromise scope assessment

For more information on Warp Gate template configuration, see the
[Warp Gate documentation](https://github.com/cowdogmoo/warpgate).
