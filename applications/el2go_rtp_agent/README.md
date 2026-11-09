# EL2GO RTP Agent

Reference application for Remote Trust Provisioning (RTP). It connects to the EdgeLock 2GO server and
provisions keys and certificates into the device.

---

## Table of Contents

1. [Purpose](#purpose)
2. [Supported Platforms and Guides](#supported-platforms-and-guides)
3. [Libraries and Backends Used](#libraries-and-backends-used)
4. [Source Layout](#source-layout)
5. [Related Documents](#related-documents)

---

## Purpose

The agent (`src/el2go_rtp_agent_demo.c`) shows how an application uses the RTP library. It does the following:

1. Initializes the network once at startup.
2. Runs a loop in which each iteration:
   - sets up the RTP library (platform, keystore and datastore),
   - provisions the device,
   - cleans up.

**Registration modes**

A device can be registered in one of two modes:

- **By UUID** (default): the device UUID is printed at startup.
- **With a claim code**.

**Runtime arguments**

The following optional arguments can be passed to the agent:

| Argument | Meaning |
|----------|---------|
| `argv[1]` | Server host |
| `argv[2]` | Server port |
| `argv[3]` | Claim code |

**Note:** on Linux this is a minimal reference application. For a production-oriented Linux provisioning
application see the [OEM Provisioning Application](https://github.com/nxp-imx/oem-prov-app).

## Supported Platforms and Guides

| OS | Status | Guide |
|---|---|---|
| Zephyr | Supported (`rd_rw612_bga/rw612/ns`, `frdm_rw612/rw612/ns`, `rd_rw612_bga`, `frdm_rw612`) | [Zephyr sample](../../zephyr/samples/el2go_rtp_agent/README.rst) |
| Linux | Supported (minimal reference) | [Linux build guide](../../doc/rtp/rtp_linux_build_instructions.md) |

## Libraries and Backends Used

| Component | Path | Role |
|---|---|---|
| RTP Library | `libs/el2go_rtp_lib` | Provisioning protocol and mTLS connection |
| MQTT verification | `applications/common/mqtt` | Optional check of the provisioned credentials |
| Network | `applications/common/network` | Wi-Fi bring-up on Zephyr |
| Backends | `libs/keystores`, `libs/datastores`, `libs/platforms` | Selected through the RTP library, see the library guide |

## Source Layout

| Path | Contents |
|---|---|
| `src/el2go_rtp_agent_demo.c` | Agent entry point and provisioning loop |
| `inc/` | Agent configuration, logging and timing headers |
| `sources.cmake`, `CMakeLists.txt` | Build integration |

## Related Documents

| Topic | Link |
|---|---|
| Zephyr build, configuration, sample output | [Zephyr sample](../../zephyr/samples/el2go_rtp_agent/README.rst) |
| Library architecture and protocol flow | [RTP library guide](../../doc/rtp/el2go_rtp_lib.md) |
| Linux build and install | [Linux build guide](../../doc/rtp/rtp_linux_build_instructions.md) |
| Claim code preparation (runs before this agent) | [Claimcode encryption](../el2go_claimcode_encryption/README.md) |
| Consumers of the provisioned credentials | [MQTT demo](../el2go_mqtt_demo/README.md), [OTA agent core](../ota_agents/el2go_ota_agent_core/README.md), [OTA agent advanced](../ota_agents/el2go_ota_agent_advanced/README.md) |
| Alternative provisioning path | [Import blob](../el2go_import_blob/README.md) |
