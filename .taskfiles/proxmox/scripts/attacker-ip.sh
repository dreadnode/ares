#!/usr/bin/env bash
set -uo pipefail

PROXMOX_SSH_HOST="${1:-${PROXMOX_SSH_HOST:-proxmox}}"
ATTACKER_VMID="${2:-${ATTACKER_VMID:-200}}"

ssh -o ConnectTimeout=10 -o BatchMode=yes "${PROXMOX_SSH_HOST}" \
	"qm guest cmd ${ATTACKER_VMID} network-get-interfaces 2>/dev/null" 2>/dev/null |
	python3 -c "
import sys, json
try:
    for nic in json.load(sys.stdin):
        if nic.get('name') == 'lo':
            continue
        for ip in nic.get('ip-addresses', []):
            if ip.get('ip-address-type') == 'ipv4' and not ip['ip-address'].startswith('127.'):
                print(ip['ip-address'])
                sys.exit(0)
except Exception:
    pass
" 2>/dev/null

exit 0
