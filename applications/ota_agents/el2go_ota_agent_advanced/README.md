# EL2GO OTA Agent Advanced

Production-style reference agent for over-the-air firmware updates, built from a scheduler, a policy and an updater
module.

---

## Table of Contents

1. [Purpose](#purpose)
2. [Supported Platforms and Guides](#supported-platforms-and-guides)
3. [Libraries and Backends Used](#libraries-and-backends-used)
4. [Source Layout](#source-layout)
5. [Related Documents](#related-documents)

---

## Purpose

The agent extends the [core agent](../el2go_ota_agent_core/README.md) flow with features needed in a production
setup:

- Scheduling with backoff.
- A blackout and defer policy that controls when updates may be applied.
- Retries for the download and for the status report.
- Persisted agent state, used to reconcile interrupted or rejected updates after a reboot.

A side-by-side comparison with the core agent is in the "Reference Agents" section of the
[OTA libraries guide](../../../doc/ota/el2go_ota_lib.md#reference-agents).

**Prerequisite: mTLS credentials**

- The mTLS credentials must be provisioned on the device before the agent runs.
- The agent only reads them; it never creates them.
- See the [Zephyr sample guide](../../../zephyr/samples/el2go_ota_agent_advanced/README.rst) for details.

## Supported Platforms and Guides

| OS | Status | Guide |
|---|---|---|
| Zephyr | Supported (`frdm_rw612`, `rd_rw612_bga`) | [Zephyr sample](../../../zephyr/samples/el2go_ota_agent_advanced/README.rst) |

## Libraries and Backends Used

| Component | Path | Role |
|---|---|---|
| OTA Library | `libs/el2go_ota_lib` | Server connection, update check, download, status reporting |
| FWUAL | `libs/fwual` | Image handling and confirmation |
| Agent support | `applications/ota_agents/common/{persist,event,diag}` | Persisted state, network events, diagnostics |
| Time | `applications/common/time` | Time source for the blackout policy |

## Source Layout

| Path | Contents |
|---|---|
| `src/main.c` | Initialization and scheduler start |
| `src/scheduler.c`, `applications/ota_agents/el2go_ota_agent_advanced/include/scheduler.h` | Poll cadence, backoff, network-up trigger |
| `src/policy.c`, `applications/ota_agents/el2go_ota_agent_advanced/include/policy.h` | Blackout and defer decisions |
| `src/updater.c`, `applications/ota_agents/el2go_ota_agent_advanced/include/updater.h` | Update check, download, handoff, boot reconciliation in `updater_finalize_boot()` |

## Related Documents

| Topic | Link |
|---|---|
| Zephyr build, configuration, flash layout, MCUboot, credentials | [Zephyr sample](../../../zephyr/samples/el2go_ota_agent_advanced/README.rst) |
| Library architecture and agent comparison | [OTA libraries guide](../../../doc/ota/el2go_ota_lib.md) |
| Minimal reference agent | [OTA agent core](../el2go_ota_agent_core/README.md) |
| Credentials provisioned by | [RTP agent](../../el2go_rtp_agent/README.md), [Import blob](../../el2go_import_blob/README.md) |
