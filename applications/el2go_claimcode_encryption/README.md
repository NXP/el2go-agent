# EL2GO Claimcode Encryption

Utility that encrypts a device claim code and stores the encrypted blob in flash for the RTP agent.

---

## Table of Contents

1. [Purpose](#purpose)
2. [Supported Platforms and Guides](#supported-platforms-and-guides)
3. [Libraries and Backends Used](#libraries-and-backends-used)
4. [Source Layout](#source-layout)
5. [Related Documents](#related-documents)

---

## Purpose

`el2go_claimcode_encrypt(...)` encrypts the claim code with the public key from `include/rtp/el2go_rtp_claimcode.h`.
`write_claimcode_blob_to_flash(...)` then writes it with an indicator at the configured flash address. On an
error the application halts. The flash address is documented in the sample guide.

## Supported Platforms and Guides

| OS | Status | Guide |
|---|---|---|
| Zephyr | Supported (`frdm_rw612`, `rd_rw612_bga`) | [Zephyr sample](../../zephyr/samples/el2go_claimcode_encryption/README.rst) |

## Libraries and Backends Used

| Component | Path | Role |
|---|---|---|
| Platform | `libs/platforms` | Linked by `CMakeLists.txt` |
| ELS PKC backend | `src/els_pkc/` | Encryption on the secure hardware |

## Source Layout

| Path | Contents |
|---|---|
| `src/el2go_claimcode_encryption.c` | Entry point and flash write |
| `src/el2go_claimcode_encrypt.c` | Encryption wrapper |
| `src/els_pkc/` | ELS PKC backend |
| `flash_config/` | Flash programming helpers |
| `inc/` | Public headers of the application |

## Related Documents

| Topic | Link |
|---|---|
| Zephyr build, configuration, flash address | [Zephyr sample](../../zephyr/samples/el2go_claimcode_encryption/README.rst) |
| Consumer of the blob (`el2go_keystore_import_claimcode_from_flash()`) | [RTP agent](../el2go_rtp_agent/README.md) |
| RTP library | [RTP library guide](../../doc/rtp/el2go_rtp_lib.md) |
