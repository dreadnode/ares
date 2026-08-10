# ares-attack-box-proxmox

Builds a **Proxmox VE VM template** with the full Ares red team toolchain
(recon, ACL abuse, coercion, credential access, password cracking, lateral
movement, privilege escalation), driven by the same
`dreadnode.nimbus_range` Ansible collection used by `ares-golden-image`.

## How it differs from `ares-golden-image`

- Emits a **Proxmox VM template** instead of an AWS AMI.
- NVIDIA drivers + CUDA toolkit are **opt-in** via `CRACKING_TOOLS_GPU_SUPPORT=true`.
- Provisioners run **over SSH** against the cloned VM (not via EC2 Image
  Builder / SSM), so commands use `sudo`.

## How warpgate's Proxmox builder works

The warpgate Proxmox target is **clone-based**, not ISO-boot. It:

1. Resolves a **source template** (by name or VMID) on the configured node.
2. Clones it to a new VMID, applies cloud-init (user, password, SSH key, IP).
3. Boots the clone, waits for the QEMU guest agent, resolves its IP.
4. Runs warpgate provisioners (`shell`, `ansible`, `file`) over SSH.
5. Stops the VM, detaches cloud-init, converts it to a Proxmox template.

You therefore need a base Proxmox template that already has:

- `cloud-init` enabled
- `qemu-guest-agent` installed and set to start on boot
- SSH reachable, with the cloud-init user having NOPASSWD sudo

## Prereq: build a Kali base Proxmox template

Run on a Proxmox node, once. Adjust `STORAGE`, `VMID`, and the image URL.

```bash
STORAGE=local-lvm
VMID=9000
IMG=kali-linux-2026.1-cloud-genericcloud-amd64.qcow2
URL=https://kali.download/cloud-images/current/$IMG

# 1. Fetch the Kali cloud image
cd /var/lib/vz/template/iso
wget "$URL"

# 2. Create a shell VM
qm create $VMID --name kali-base --memory 4096 --cores 2 \
  --net0 virtio,bridge=vmbr0 --ostype l26

# 3. Import the disk and attach it
qm importdisk $VMID $IMG $STORAGE
qm set $VMID --scsihw virtio-scsi-pci --scsi0 $STORAGE:vm-$VMID-disk-0

# 4. Add cloud-init drive and serial console
qm set $VMID --ide2 $STORAGE:cloudinit
qm set $VMID --boot order=scsi0
qm set $VMID --serial0 socket --vga serial0

# 5. Enable the QEMU guest agent (warpgate waits for it)
qm set $VMID --agent enabled=1

# 6. Convert to template
qm template $VMID
```

The cloud image already includes `qemu-guest-agent` and `cloud-init`, but
you should confirm the agent autostarts when the clone boots. If your
image doesn't have it, install during a one-shot boot before converting
to template:

```bash
qm start $VMID
# wait, ssh in as the cloud-init user, then:
sudo apt-get update && sudo apt-get install -y qemu-guest-agent
sudo systemctl enable --now qemu-guest-agent
sudo shutdown -h now
qm template $VMID
```

The template name (`kali-base` above) is what you'll pass as
`PROXMOX_SOURCE_TEMPLATE`.

## Configure warpgate

### 1. Persistent endpoint (one-time)

Add to `~/.config/warpgate/config.yaml`:

```yaml
proxmox:
  endpoint: https://pve.contoso.local:8006/api2/json
  api_token_id: warpgate@pve!builder
  # api_token is read from $PROXMOX_API_TOKEN below — do not put it here
```

Create the API token in the Proxmox UI under
*Datacenter → Permissions → API Tokens*. Grant it `VM.Allocate`,
`VM.Clone`, `VM.Config.*`, `VM.PowerMgmt`, `Datastore.AllocateSpace`,
and `SDN.Use` on `/` (or scope tighter per your environment).

### 2. Per-shell env vars

```bash
export PROXMOX_API_TOKEN='your-token-secret'
export PROXMOX_NODE='pve1'
export PROXMOX_SOURCE_TEMPLATE='kali-base'
export PROXMOX_STORAGE='local-lvm'
export PROXMOX_POOL=''                       # optional, leave empty if unused
export PROXMOX_CI_PASSWORD='change-me'
export PROXMOX_CI_SSH_KEY="$(cat ~/.ssh/id_ed25519.pub)"
export PROXMOX_SSH_PRIVATE_KEY="$(cat ~/.ssh/id_ed25519)"
```

## Build

```bash
# CPU-only attacker box (default)
warpgate build templates/ares-attack-box-proxmox/warpgate.yaml

# With GPU support (host must have PCIe passthrough configured)
warpgate build templates/ares-attack-box-proxmox/warpgate.yaml \
  --var CRACKING_TOOLS_GPU_SUPPORT=true
```

## Validate

Structural validation needs no live Proxmox, but the validator expands env
vars and enforces `node` / `source_template_name` are non-empty, so dummy
values are fine for a syntax check:

```bash
PROXMOX_NODE=dummy PROXMOX_SOURCE_TEMPLATE=dummy PROXMOX_STORAGE=dummy \
PROXMOX_POOL='' PROXMOX_CI_PASSWORD=dummy PROXMOX_CI_SSH_KEY=dummy \
PROXMOX_SSH_PRIVATE_KEY=dummy \
  warpgate validate templates/ares-attack-box-proxmox/warpgate.yaml
```

## Variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `PROXMOX_NODE` | — | Proxmox node name (e.g., `pve1`) |
| `PROXMOX_SOURCE_TEMPLATE` | — | Name of the Kali base template to clone |
| `PROXMOX_STORAGE` | — | Storage backend for the cloned disk (e.g., `local-lvm`) |
| `PROXMOX_POOL` | empty | Optional resource pool |
| `PROXMOX_CI_PASSWORD` | — | cloud-init default user password |
| `PROXMOX_CI_SSH_KEY` | — | Authorized SSH public key(s) |
| `PROXMOX_SSH_PRIVATE_KEY` | — | PEM private key used to run provisioners |
| `PROXMOX_API_TOKEN` | — | Proxmox API token secret (paired with `api_token_id` in config) |
| `CRACKING_TOOLS_GPU_SUPPORT` | `false` | When `true`, install NVIDIA drivers + build hashcat with GPU support |

## After the build

Warpgate prints the new template VMID. Clone instances from it:

```bash
qm clone <template-vmid> <new-vmid> --name attacker-1 --full
qm set <new-vmid> --ipconfig0 ip=dhcp
qm start <new-vmid>
```
