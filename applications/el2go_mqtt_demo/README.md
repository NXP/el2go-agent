# EL2GO MQTT Demo

Demo application that connects to AWS IoT Core or Azure IoT Hub (DPS) over MQTT with credentials provisioned by EdgeLock 2GO.

---

## Table of Contents

1. [Purpose](#purpose)
2. [Supported Platforms and Guides](#supported-platforms-and-guides)
3. [Libraries and Backends Used](#libraries-and-backends-used)
4. [Source Layout](#source-layout)
5. [Related Documents](#related-documents)

---

## Purpose

Only `src/el2go_mqtt_client.c` lives in this directory. The shared MQTT code is in `applications/common/mqtt/`
(`el2go_mqtt.c` weak default, `applications/common/mqtt/zephyr/el2go_mqtt_zephyr.c`). The credentials must already be provisioned, for
example by the RTP agent. The `EL2GO_RTP_MQTT_*` symbols come from the RTP sample: the Kconfig of the MQTT
sample sources `zephyr/samples/el2go_rtp_agent/Kconfig`.

## Supported Platforms and Guides

| OS | Status | Guide |
|---|---|---|
| Zephyr | Supported (`rd_rw612_bga/rw612/ns`, `frdm_rw612/rw612/ns`, `rd_rw612_bga`, `frdm_rw612`) | [Zephyr sample](../../zephyr/samples/el2go_mqtt_demo/README.rst) |

## Libraries and Backends Used

| Component | Path | Role |
|---|---|---|
| MQTT | `applications/common/mqtt` | Shared MQTT verification code |
| Network | `applications/common/network` | Wi-Fi bring-up |
| net_crypto | `libs/net_crypto` | TLS for the MQTT transport |
| Keystore | `libs/keystores` | Source of the client certificate |

## Source Layout

| Path | Contents |
|---|---|
| `src/el2go_mqtt_client.c` | Entry point and demo thread |
| `applications/common/mqtt/` | Shared MQTT implementation and configuration header |

## Related Documents

| Topic | Link |
|---|---|
| Zephyr build, configuration, flash layout | [Zephyr sample](../../zephyr/samples/el2go_mqtt_demo/README.rst) |
| Provisioning the credentials | [RTP agent](../el2go_rtp_agent/README.md), [Import blob](../el2go_import_blob/README.md) |
| RTP library | [RTP library guide](../../doc/rtp/el2go_rtp_lib.md) |
