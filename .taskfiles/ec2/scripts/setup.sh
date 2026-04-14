#!/bin/bash
# One-time ares EC2 setup: Redis, log dirs, systemd worker template
set -euo pipefail

echo "=== Installing Redis ==="
if command -v redis-server > /dev/null 2>&1; then
    redis-server --version
else
    if command -v apt-get > /dev/null 2>&1; then
        apt-get update -qq && apt-get install -y -qq redis-server
    elif command -v yum > /dev/null 2>&1; then
        yum install -y redis
    elif command -v dnf > /dev/null 2>&1; then
        dnf install -y redis
    else
        echo "ERROR: No supported package manager found"
        exit 1
    fi
fi

echo "=== Creating directories ==="
mkdir -p /var/log/ares /etc/ares

echo "=== Creating systemd worker template unit ==="
cat > /etc/systemd/system/ares-worker@.service << 'UNIT_EOF'
[Unit]
Description=Ares Worker (%i)
After=redis.service
Wants=redis.service

[Service]
Type=simple
ExecStart=/usr/local/bin/ares-worker
Environment=ARES_REDIS_URL=redis://127.0.0.1:6379
Environment=ARES_WORKER_ROLE=%i
Environment=ARES_WORKER_MODE=tool_exec
Environment=RUST_LOG=info
Environment=OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
Environment=OTEL_RESOURCE_ATTRIBUTES=service.namespace=ares,deployment.environment=staging,attack.team=red
Restart=on-failure
RestartSec=5
StandardOutput=append:/var/log/ares/%i.log
StandardError=append:/var/log/ares/%i.log

[Install]
WantedBy=multi-user.target
UNIT_EOF

echo "=== Installing cracking tools ==="
if ! command -v hashcat > /dev/null 2>&1 || ! command -v john > /dev/null 2>&1; then
    if command -v apt-get > /dev/null 2>&1; then
        apt-get install -y -qq hashcat john
    fi
fi

echo "=== Fixing pip/system impacket conflicts ==="
# Kali's system impacket has patches (regsecrets) that pip versions lack.
# Remove any pip-installed impacket that shadows the system package.
if [ -d /usr/local/lib/python3.13/dist-packages/impacket ]; then
    pip3 uninstall -y impacket --break-system-packages 2> /dev/null || true
    rm -rf /usr/local/lib/python3.13/dist-packages/impacket \
           /usr/local/lib/python3.13/dist-packages/impacket-*.dist-info
    echo "Removed pip impacket shadow — using system package"
fi

echo "=== Enabling Redis ==="
systemctl enable redis-server 2> /dev/null || systemctl enable redis 2> /dev/null || true
systemctl start redis-server 2> /dev/null || systemctl start redis 2> /dev/null || true
systemctl daemon-reload

echo "=== Setup complete ==="
redis-cli ping 2> /dev/null || echo "Redis not responding"
