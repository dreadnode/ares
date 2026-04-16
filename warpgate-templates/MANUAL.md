# Manual EC2 Instance Setup for Ares

Steps performed manually on `i-04db753fa01ccda91` (staging-alpha-operator-range-kali-ares) that should be automated via the ansible playbook or Taskfile.

## 1. Install AWS CLI

```bash
apt-get update -qq && apt-get install -y -qq unzip
curl -sL https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip -o /tmp/awscliv2.zip
cd /tmp && unzip -qo awscliv2.zip && ./aws/install --update
rm -rf /tmp/aws /tmp/awscliv2.zip
```

## 2. Install Pentest Tools via pipx

Ubuntu doesn't have Kali's apt packages for impacket/netexec. Use pipx for isolated installs:

```bash
apt-get install -y -qq pipx hashcat
pipx ensurepath
pipx install impacket
pipx install git+https://github.com/Pennyw0rth/NetExec.git
pipx install bloodhound
pipx install certipy-ad
```

## 3. Create Impacket Wrapper Scripts

pipx doesn't expose impacket's console_scripts. Create wrappers in `/usr/local/bin`:

```bash
VENV_BIN="/root/.local/share/pipx/venvs/impacket/bin"
for script in secretsdump GetNPUsers GetUserSPNs psexec wmiexec smbexec \
  getTGT getST ticketer lookupsid findDelegation addcomputer rbcd \
  dacledit raiseChild ntlmrelayx mssqlclient; do
  cat > "/usr/local/bin/impacket-${script}" << 'WRAPPER'
#!/bin/bash
exec /root/.local/share/pipx/venvs/impacket/bin/${script}.py "$@"
WRAPPER
  chmod +x "/usr/local/bin/impacket-${script}"
done
```

## 4. Create Symlinks for pipx Tools

```bash
for cmd in netexec nxc bloodhound-python certipy; do
  SRC="/root/.local/bin/$cmd"
  [ -f "$SRC" ] && ln -sf "$SRC" "/usr/local/bin/$cmd"
done
```

## 5. Fix Worker PATH in Systemd

The systemd worker unit doesn't include `/root/.local/bin` or `/usr/local/bin` in PATH:

```bash
sed -i '/\[Service\]/a Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/root/.local/bin' \
  /etc/systemd/system/ares-worker@.service
systemctl daemon-reload
```

Then restart all workers:

```bash
for role in recon credential_access cracker acl privesc lateral coercion; do
  systemctl restart ares-worker@$role
done
```

## 6. Install Wordlists

The cracker role needs wordlists for hashcat/john. Without them, kerberoast and AS-REP hashes can't be cracked.

```bash
mkdir -p /usr/share/wordlists
curl -sL https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt \
  -o /usr/share/wordlists/rockyou.txt
```

## 6. Store API Keys in Secrets Manager

```bash
# From local machine with 1Password CLI:
OPENAI_KEY=$(op item get "Dreadnode Openai" --fields label="dreadnode-ares-api-key" --reveal)
ANTHROPIC_KEY=$(op item get "Dreadnode Claude" --fields label="api-key" --reveal)

aws secretsmanager create-secret \
  --profile lab --region us-west-1 \
  --name "ares/api-keys" \
  --secret-string "{\"OPENAI_API_KEY\": \"$OPENAI_KEY\", \"ANTHROPIC_API_KEY\": \"$ANTHROPIC_KEY\"}"
```

**Note**: The EC2 instance role (`staging-alpha-operator-range-kali-ares-ssm-role`) needs `secretsmanager:GetSecretValue` permission on `ares/api-keys` for the orchestrator to self-serve keys. Currently blocked by IAM policy — keys must be passed directly via SSM command or env file.

## 7. Launch Orchestrator

```bash
# On the EC2 instance (or via SSM):
export OPENAI_API_KEY="..."
export ANTHROPIC_API_KEY="..."
export ARES_REDIS_URL=redis://127.0.0.1:6379
export RUST_LOG=info
export ARES_CONFIG=/etc/ares/config.yaml
export ARES_OPERATION_ID='{"operation_id":"<uuid>","target_domain":"sevenkingdoms.local","target_ips":["10.1.2.254","10.1.2.220","10.1.2.58","10.1.2.150","10.1.2.51"],"initial_credential":{"username":"samwell.tarly","password":"Heartsbane","domain":"sevenkingdoms.local"}}'

nohup /usr/local/bin/ares-orchestrator >/var/log/ares/orchestrator.log 2>&1 &
```
