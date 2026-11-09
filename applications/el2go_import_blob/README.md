# EL2GO Import Blob

Application that reads EdgeLock 2GO Secure Objects from a dedicated memory address and imports them into PSA ITS.

---

## Table of Contents

1. [Purpose](#purpose)
2. [Supported Platforms and Guides](#supported-platforms-and-guides)
3. [Libraries and Backends Used](#libraries-and-backends-used)
4. [Source Layout](#source-layout)
5. [Related Documents](#related-documents)

---

## Purpose

The flow in `src/el2go_import_blob.c` initializes PSA Crypto, reads the EdgeLock 2GO Secure Objects from a
dedicated memory address, imports them into PSA ITS and runs the validators. No network connection is needed.

## Supported Platforms and Guides

| OS | Status | Guide |
|---|---|---|
| Zephyr | Supported (`rd_rw612_bga/rw612/ns`, `frdm_rw612/rw612/ns`, `rd_rw612_bga`, `frdm_rw612`) | [Zephyr sample](../../zephyr/samples/el2go_import_blob/README.rst) |

## Libraries and Backends Used

| Component | Path | Role |
|---|---|---|
| PSA Crypto | provided by the Zephyr build | Key import and validation |
| net_crypto | `libs/net_crypto` | Linked by `CMakeLists.txt` |
| Platform | `libs/platforms` | Linked by `CMakeLists.txt` |

## Source Layout

| Path | Contents |
|---|---|
| `src/el2go_import_blob.c` | Entry point |
| `src/el2go_psa_import.c` | Blob parsing and import |
| `src/el2go_import_blob_validate.c` | Validator hooks (weak defaults) |
| `src/psa/` | Extra validators, built only with the `VALIDATE_PSA_IMPORT_*` variables in `sources.cmake` |

## Related Documents

| Topic | Link |
|---|---|
| Zephyr build, configuration, flash areas | [Zephyr sample](../../zephyr/samples/el2go_import_blob/README.rst) |
| Online provisioning path | [RTP agent](../el2go_rtp_agent/README.md) |
| Consumers of the imported credentials | [OTA agent core](../ota_agents/el2go_ota_agent_core/README.md), [OTA agent advanced](../ota_agents/el2go_ota_agent_advanced/README.md), [MQTT demo](../el2go_mqtt_demo/README.md) |
