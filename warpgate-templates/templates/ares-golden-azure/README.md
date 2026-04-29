# ares-golden-azure

Azure variant of the Ares golden image. Builds an Ubuntu 22.04 LTS image via Azure
VM Image Builder and publishes a version into the `warpgateTestGallery` Compute
Gallery.

This template is intentionally lighter than `ares-golden-image` (the AMI variant) —
its purpose is to prove the warpgate Azure pipeline works end-to-end. It exercises:

- shell customizer
- ansible customizer (with auto-bootstrap of ansible-core)
- gallery image version publish

## Prerequisites

Provisioned manually (one-time):

- Resource group `warpgate-test-rg` in `eastus`
- Compute Gallery `warpgateTestGallery`
- Image definition `ares-golden-azure` (Linux, Generalized, HyperV V2,
  publisher=`dreadnode`, offer=`ares`, sku=`golden`)
- User-assigned managed identity `warpgate-aib-uami`
  with Contributor on `warpgate-test-rg`

## Build

```bash
warpgate build path/to/ares-golden-azure --target azure
```
