#!/usr/bin/env bash
# Provision the box-local PostgreSQL that backs the ares-history store.
#
# Why box-local instead of the shared ares-history RDS: that RDS is private in a
# us-west-1 VPC (not publicly accessible, security-group-scoped, no peering) and
# kali-ares now runs in us-east-1, so the box has no network path to it. A
# loopback Postgres co-located with the orchestrator gives the projector + op
# finalizer a DB to write to (ARES_DATABASE_URL) with zero cross-region
# networking. ares self-migrates on startup (sqlx::migrate!), so an empty
# database is all this needs to create — the schema builds itself on first run.
#
# Auth: the ares_admin role is passwordless and pg_hba trusts it on loopback
# only, while listen_addresses stays 'localhost'. Nothing off-box can reach it
# and no secret lands in git. Single-tenant red-team box — acceptable tradeoff.
#
# Idempotent: safe to re-run.
set -euo pipefail

DB_NAME=ares_history
DB_USER=ares_admin
export DEBIAN_FRONTEND=noninteractive

# Guard on the server, not psql: kali-ares ships postgresql-client (pulled in by
# other tooling) without the server, so `command -v psql` is true even when no
# cluster exists. pg_lsclusters (from postgresql-common) is the exact command
# this script relies on next, so its absence is the right install trigger.
if ! command -v pg_lsclusters >/dev/null 2>&1; then
	echo "[*] Installing postgresql server (waiting up to 300s for apt lock)..."
	apt-get -o DPkg::Lock::Timeout=300 update -qq
	apt-get -o DPkg::Lock::Timeout=300 install -y -qq postgresql
fi

# Debian/Kali auto-create and start the 'main' cluster on install; make sure it
# is enabled and running before we talk to it.
systemctl enable --now postgresql >/dev/null 2>&1 || true
# Kali policy leaves the per-cluster unit only runtime-enabled, so a reboot
# would silently drop history persistence. Persistently enable the concrete
# cluster unit (version-derived) so it survives reboots.
PG_VER=$(pg_lsclusters -h 2>/dev/null | awk 'NR==1{print $1}')
if [ -n "$PG_VER" ]; then
	systemctl enable --now "postgresql@${PG_VER}-main" >/dev/null 2>&1 || true
fi

# Role: LOGIN, no password (loopback trust below handles auth).
sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='${DB_USER}'" | grep -q 1 ||
	sudo -u postgres psql -qc "CREATE ROLE ${DB_USER} LOGIN"

# Database owned by the role.
sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'" | grep -q 1 ||
	sudo -u postgres createdb -O "${DB_USER}" "${DB_NAME}"

# Loopback trust for the ares role, prepended above the packaged host rules so
# it wins. Marker line keeps the insert idempotent across re-runs.
HBA=$(sudo -u postgres psql -tAc 'SHOW hba_file')
if ! grep -q 'ares-history loopback trust' "$HBA"; then
	echo "[*] Adding loopback trust rules to $HBA"
	TMP=$(mktemp)
	{
		echo "# ares-history loopback trust (managed by setup-history-db.sh)"
		echo "host  ${DB_NAME}  ${DB_USER}  127.0.0.1/32  trust"
		echo "host  ${DB_NAME}  ${DB_USER}  ::1/128       trust"
		cat "$HBA"
	} >"$TMP"
	cp "$HBA" "${HBA}.bak.$(date +%s)"
	cat "$TMP" >"$HBA"
	chown postgres:postgres "$HBA"
	chmod 640 "$HBA"
	rm -f "$TMP"
	systemctl reload postgresql
fi

echo "[*] Verifying TCP connection as ${DB_USER}..."
psql "postgresql://${DB_USER}@127.0.0.1:5432/${DB_NAME}" -tAc \
	"SELECT 'connected as', current_user, 'to', current_database()"

echo "[+] ares-history DB ready: postgresql://${DB_USER}@127.0.0.1:5432/${DB_NAME}"
