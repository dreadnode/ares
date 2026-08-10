#!/bin/bash
# Post-AMI pentest tool install (invoked via SSM run_ssm_cmd).
# Installs system packages, pipx-based tools (impacket, netexec, bloodhound,
# certipy, lsassy), evil-winrm, impacket wrappers, and the rockyou wordlist.
set -e
export DEBIAN_FRONTEND=noninteractive
export PATH="/root/.local/bin:/usr/local/bin:$PATH"

echo "=== Installing system deps ==="
apt-get update -qq
apt-get install -y -qq nmap smbclient samba-common-bin ldap-utils dnsutils whois python3-pip python3-venv pipx git jq unzip hashcat

echo "=== Installing tools via pipx ==="
pipx ensurepath
pipx install impacket 2>&1 | tail -3
pipx install git+https://github.com/Pennyw0rth/NetExec.git 2>&1 | tail -3
pipx install bloodhound 2>&1 | tail -3
pipx install certipy-ad 2>&1 | tail -3
pipx install lsassy 2>&1 | tail -3

echo "=== Installing evil-winrm ==="
apt-get install -y -qq ruby ruby-dev build-essential 2>/dev/null
gem install evil-winrm --no-document 2>&1 | tail -3 || echo "evil-winrm install failed (non-fatal)"

echo "=== Creating impacket wrappers ==="
for s in secretsdump GetNPUsers GetUserSPNs psexec wmiexec smbexec getTGT getST ticketer lookupsid findDelegation addcomputer rbcd dacledit raiseChild ntlmrelayx mssqlclient; do
	printf '#!/bin/bash\nexec /root/.local/share/pipx/venvs/impacket/bin/%s.py "$@"\n' "$s" >"/usr/local/bin/impacket-${s}"
	chmod +x "/usr/local/bin/impacket-${s}"
done

echo "=== Creating symlinks ==="
for cmd in netexec nxc bloodhound-python certipy lsassy; do
	SRC="/root/.local/bin/$cmd"
	[ -f "$SRC" ] && ln -sf "$SRC" "/usr/local/bin/$cmd"
done

echo "=== Installing wordlists ==="
mkdir -p /usr/share/wordlists
if [ ! -f /usr/share/wordlists/rockyou.txt ]; then
	curl -sL https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt -o /usr/share/wordlists/rockyou.txt
	echo "rockyou.txt: $(wc -l </usr/share/wordlists/rockyou.txt) entries"
else
	echo "rockyou.txt already present"
fi

echo "=== Verifying ==="
for cmd in nmap netexec impacket-secretsdump impacket-GetNPUsers smbclient rpcclient ldapsearch lsassy evil-winrm; do
	printf "%-30s %s\n" "$cmd:" "$(which $cmd 2>/dev/null || echo NOT_FOUND)"
done
echo "=== Done ==="
