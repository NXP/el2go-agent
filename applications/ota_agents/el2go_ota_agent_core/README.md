# EL2GO OTA Agent Core

Minimal reference agent for over-the-air firmware updates. It polls the EL2GO OTA server and applies updates
through FWUAL.

---

## Table of Contents

1. [Purpose](#purpose)
2. [Supported Platforms and Guides](#supported-platforms-and-guides)
3. [Libraries and Backends Used](#libraries-and-backends-used)
4. [Source Layout](#source-layout)
5. [Related Documents](#related-documents)

---

## Purpose

The agent runs a single-threaded poll loop in `src/main.c`, without a scheduler, retry policy or persisted agent
state. The mTLS credentials are a prerequisite: they are provisioned beforehand and only read by this agent.
Where they are stored is explained in the section "Credentials and secure storage (PSA ITS)" of the
[Zephyr sample guide](../../../zephyr/samples/el2go_ota_agent_core/README.rst).

## Supported Platforms and Guides

| OS | Status | Guide |
|---|---|---|
| Zephyr | Supported (`frdm_rw612`, `rd_rw612_bga`) | [Zephyr sample](../../../zephyr/samples/el2go_ota_agent_core/README.rst) |
| Linux | Builds for validation with `BUILD_OTA=ON`; OTA is not functional | [OTA libraries guide](../../../doc/ota/el2go_ota_lib.md) |

## Libraries and Backends Used

| Component | Path | Role |
|---|---|---|
| OTA Library | `libs/el2go_ota_lib` | Server connection, update check, chunked download, status reporting |
| FWUAL | `libs/fwual` | Image writing, verification, activation, confirmation |
| Application support | `applications/common/{network,system,time}` | Network, reboot and sleep, time |
| Agent support | `applications/ota_agents/common/{diag,persist,event}` | Diagnostics, persistence, network events |

## Source Layout

| Path | Contents |
|---|---|
| `src/main.c` | Agent flow |
| `sources.cmake`, `CMakeLists.txt` | Build integration |

## Related Documents

| Topic | Link |
|---|---|
| Zephyr build, configuration, flash layout, MCUboot, credentials | [Zephyr sample](../../../zephyr/samples/el2go_ota_agent_core/README.rst) |
| Library architecture, update flow, agent comparison | [OTA libraries guide](../../../doc/ota/el2go_ota_lib.md) |
| Credentials provisioned by | [RTP agent](../../el2go_rtp_agent/README.md), [Import blob](../../el2go_import_blob/README.md) |
| Extended reference agent | [OTA agent advanced](../el2go_ota_agent_advanced/README.md) |
