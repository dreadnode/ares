# ares-golden-azure

Azure variant of the Ares golden image. Builds a Kali Linux image via Azure
VM Image Builder and publishes a version into the `warpgateTestGallery` Compute
Gallery, with feature parity against the AWS `ares-golden-image` AMI.

Ships the same red-team toolchain installed by
`ansible/playbooks/ares/goad_attack_box.yml`:

- recon, credential access, privilege escalation
- password cracking (hashcat from source, GPU-accelerated)
- lateral movement, ACL abuse, coercion
- Alloy telemetry agent
- NVIDIA driver + CUDA toolkit for T4 GPU acceleration

## Prerequisites

Provisioned manually (one-time):

- Resource group `warpgate-test-rg` in `eastus`
- Compute Gallery `warpgateTestGallery`
- Image definition `ares-golden-azure` (Linux, Generalized, HyperV V2,
  publisher=`dreadnode`, offer=`ares`, sku=`golden`)
- User-assigned managed identity `warpgate-aib-uami`
  with Contributor on `warpgate-test-rg`
- Quota for `Standard_NC4as_T4_v3` in `centralus` (T4 GPU family)
- Kali Marketplace terms accepted on the subscription:
  `az vm image terms accept --publisher kali-linux --offer kali --plan kali-last`

## Build

```bash
warpgate build path/to/ares-golden-azure --target azure
```
