# ares-golden-azure

Azure variant of the Ares golden image. Builds a Kali Linux image via Azure
VM Image Builder and publishes a version into a Compute Gallery, with feature
parity against the AWS `ares-golden-image` AMI.

Ships the same red-team toolchain installed by
`ansible/playbooks/ares/goad_attack_box.yml`:

- recon, credential access, privilege escalation
- password cracking (hashcat from source, GPU-accelerated)
- lateral movement, ACL abuse, coercion
- Alloy telemetry agent
- NVIDIA driver + CUDA toolkit for T4 GPU acceleration

## Prerequisites

The template's `targets[].azure` fields are parameterized via environment
variables so the same template works across subscriptions and environments.
The values below are placeholders — substitute your own.

Provisioned manually (one-time):

- An Azure subscription (`${AZURE_SUBSCRIPTION_ID}`)
- A resource group (`${AZURE_RESOURCE_GROUP}`) in your chosen region
  (`${AZURE_LOCATION}`, e.g. `centralus`)
- A Compute Gallery (`${AZURE_GALLERY_NAME}`)
- Image definition `ares-golden-azure` (Linux, Generalized, HyperV V2,
  publisher=`dreadnode`, offer=`ares`, sku=`golden`)
- A user-assigned managed identity (`${AZURE_IDENTITY_ID}` — full resource ID)
  with Contributor on the resource group
- Quota for the chosen `${AZURE_VM_SIZE}` in `${AZURE_LOCATION}`
  (e.g. `Standard_NC4as_T4_v3` for T4 GPU, `Standard_D4s_v3` for CPU-only)
- Kali Marketplace terms accepted on the subscription:
  `az vm image terms accept --publisher kali-linux --offer kali --plan kali-2026-1`

## Build

Export the required env vars, then build:

```bash
export AZURE_SUBSCRIPTION_ID=<your-subscription-id>
export AZURE_LOCATION=centralus
export AZURE_RESOURCE_GROUP=<your-rg>
export AZURE_GALLERY_NAME=<your-gallery>
export AZURE_IDENTITY_ID=/subscriptions/<sub>/resourcegroups/<rg>/providers/Microsoft.ManagedIdentity/userAssignedIdentities/<uami>
export AZURE_VM_SIZE=Standard_NC4as_T4_v3
export GITHUB_TOKEN=<token-with-repo-read>

warpgate build path/to/ares-golden-azure --target azure
```
