#!/bin/bash
# One-time ares EC2 setup: Redis, NATS JetStream, log dirs, systemd worker template
set -euo pipefail

NATS_VERSION="${NATS_VERSION:-2.10.22}"

echo "=== Installing Redis ==="
if command -v redis-server >/dev/null 2>&1; then
	redis-server --version
else
	if command -v apt-get >/dev/null 2>&1; then
		apt-get update -qq && apt-get install -y -qq redis-server
	elif command -v yum >/dev/null 2>&1; then
		yum install -y redis
	elif command -v dnf >/dev/null 2>&1; then
		dnf install -y redis
	else
		echo "ERROR: No supported package manager found"
		exit 1
	fi
fi

echo "=== Installing NATS JetStream server ==="
if command -v nats-server >/dev/null 2>&1 && nats-server --version | grep -q "${NATS_VERSION}"; then
	nats-server --version
else
	arch="$(uname -m)"
	case "${arch}" in
	x86_64) nats_arch="amd64" ;;
	aarch64) nats_arch="arm64" ;;
	armv7l) nats_arch="arm7" ;;
	*)
		echo "ERROR: Unsupported arch: ${arch}"
		exit 1
		;;
	esac
	tarball="nats-server-v${NATS_VERSION}-linux-${nats_arch}.tar.gz"
	curl -fsSL -o "/tmp/${tarball}" \
		"https://github.com/nats-io/nats-server/releases/download/v${NATS_VERSION}/${tarball}"
	tar -xzf "/tmp/${tarball}" -C /tmp
	install -m 0755 "/tmp/nats-server-v${NATS_VERSION}-linux-${nats_arch}/nats-server" /usr/local/bin/nats-server
	rm -rf "/tmp/${tarball}" "/tmp/nats-server-v${NATS_VERSION}-linux-${nats_arch}"
fi

echo "=== Configuring NATS ==="
getent group nats >/dev/null || groupadd --system nats
getent passwd nats >/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin --gid nats nats
mkdir -p /etc/nats /var/lib/nats/jetstream /var/log/nats
chown -R nats:nats /var/lib/nats /var/log/nats
chmod 0750 /var/lib/nats/jetstream

cat >/etc/nats/nats-server.conf <<'NATS_EOF'
host: "127.0.0.1"
port: 4222
http: "127.0.0.1:8222"
server_name: "ares-nats"
log_file: "/var/log/nats/nats-server.log"
logtime: true
jetstream {
  store_dir: "/var/lib/nats/jetstream"
  max_memory_store: 512MB
  max_file_store: 4GB
}
NATS_EOF
chown nats:nats /etc/nats/nats-server.conf
chmod 0640 /etc/nats/nats-server.conf

cat >/etc/systemd/system/nats-server.service <<'NATS_UNIT_EOF'
[Unit]
Description=NATS Server (Ares broker)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=nats
Group=nats
ExecStart=/usr/local/bin/nats-server -c /etc/nats/nats-server.conf
ExecReload=/bin/kill -HUP $MAINPID
LimitNOFILE=65536
Restart=on-failure
RestartSec=5
StandardOutput=append:/var/log/nats/nats-server.stdout.log
StandardError=append:/var/log/nats/nats-server.stderr.log

[Install]
WantedBy=multi-user.target
NATS_UNIT_EOF

echo "=== Creating directories ==="
mkdir -p /var/log/ares /etc/ares

echo "=== Creating systemd worker template unit ==="
cat >/etc/systemd/system/ares@.service <<'UNIT_EOF'
[Unit]
Description=Ares Worker (%i)
After=redis.service nats-server.service
Wants=redis.service nats-server.service

[Service]
Type=simple
ExecStart=/usr/local/bin/ares worker
EnvironmentFile=-/etc/ares/env
Environment=ARES_REDIS_URL=redis://127.0.0.1:6379
Environment=NATS_URL=nats://127.0.0.1:4222
Environment=ARES_WORKER_ROLE=%i
Environment=ARES_WORKER_MODE=tool_exec
Environment=RUST_LOG=info
Environment=OTEL_RESOURCE_ATTRIBUTES=deployment.environment=staging,attack.team=red
Restart=on-failure
RestartSec=5
StandardOutput=append:/var/log/ares/%i.log
StandardError=append:/var/log/ares/%i.log

# Contain child processes (netexec, hashcat, nmap, etc.) within this cgroup.
# Without these limits, runaway tool processes can OOM the entire system and
# take down the SSM agent.
Delegate=yes
Slice=system-ares.slice
MemoryHigh=1500M
MemoryMax=2G
TasksMax=256

[Install]
WantedBy=multi-user.target
UNIT_EOF

echo "=== Installing cracking tools ==="
if ! command -v hashcat >/dev/null 2>&1 || ! command -v john >/dev/null 2>&1; then
	if command -v apt-get >/dev/null 2>&1; then
		apt-get install -y -qq hashcat john
	fi
fi

echo "=== Fixing pip/system impacket conflicts ==="
# Kali's system impacket has patches (regsecrets) that pip versions lack.
# Remove any pip-installed impacket that shadows the system package.
if [ -d /usr/local/lib/python3.13/dist-packages/impacket ]; then
	pip3 uninstall -y impacket --break-system-packages 2>/dev/null || true
	rm -rf /usr/local/lib/python3.13/dist-packages/impacket \
		/usr/local/lib/python3.13/dist-packages/impacket-*.dist-info
	echo "Removed pip impacket shadow — using system package"
fi

echo "=== Enabling services ==="
systemctl daemon-reload
systemctl enable redis-server 2>/dev/null || systemctl enable redis 2>/dev/null || true
systemctl start redis-server 2>/dev/null || systemctl start redis 2>/dev/null || true
systemctl enable nats-server
systemctl restart nats-server

echo "=== Setup complete ==="
redis-cli ping 2>/dev/null || echo "Redis not responding"
curl -fsS http://127.0.0.1:8222/varz >/dev/null 2>&1 && echo "NATS responding" || echo "NATS not responding"
