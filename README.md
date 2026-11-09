# EL2GO Services Libraries and Applications

This repository contains the C implementation of various EL2GO services for
NXP devices, including Remote Trust Provisioning (RTP) and Over-the-Air (OTA)
firmware update support.

## Overview

The following services are supported:

| Service | Description |
|---------|-------------|
| **RTP** | Remote Trust Provisioning -- establishes a mutually authenticated TLS session with the EdgeLock 2GO cloud service, downloads secure objects (keys, certificates, credentials, blobs), and provisions them into the device secure storage.  |
| **OTA** | Over-the-Air Updates -- connects to the EdgeLock 2GO cloud service over a mutually authenticated TLS session, checks for pending firmware update packages, downloads and verifies them, hands them off to the Firmware Update Abstraction Layer (FWUAL) for installation, and reports the update outcome back to the server. |

## Supported Operating Systems

| Service | Zephyr | Linux |
|---------|:------:|:-----:|
| RTP     | Yes    | Yes   |
| OTA     | Yes    | No    |

## Applications

The repository includes example applications demonstrating the available
services.

| Application | Description | Supported OS |
|-------------|-------------|:------------:|
| [`el2go_rtp_agent`](applications/el2go_rtp_agent/README.md) | Full RTP agent demo: connects to the EdgeLock 2GO server, provisions keys and certificates into the device, and prints a status report. On Linux this is a minimal reference application; for a more complete, production-oriented Linux provisioning application see the [OEM Provisioning Application](https://github.com/nxp-imx/oem-prov-app). | Zephyr, Linux |
| [`el2go_ota_agent_core`](applications/ota_agents/el2go_ota_agent_core/README.md) | Core OTA agent: connects to the EdgeLock 2GO server, downloads a firmware update, and applies it using the FWUAL layer. | Zephyr |
| [`el2go_ota_agent_advanced`](applications/ota_agents/el2go_ota_agent_advanced/README.md) | Advanced OTA agent with additional lifecycle management, rollback support, and dual-bank update handling. | Zephyr |
| [`el2go_claimcode_encryption`](applications/el2go_claimcode_encryption/README.md) | Utility application that encrypts a device claim code for secure off-line device onboarding. | Zephyr |
| [`el2go_csr`](applications/el2go_csr/README.md) | Certificate Signing Request (CSR) generation sample: generates a CSR using the on-chip key and prints it in PEM format. | Zephyr |
| [`el2go_import_blob`](applications/el2go_import_blob/README.md) | Imports a pre-provisioned secure blob into the device keystore. | Zephyr |
| [`el2go_mqtt_demo`](applications/el2go_mqtt_demo/README.md) | MQTT connectivity demo that uses an RTP-provisioned client certificate and key for broker authentication. | Zephyr |

## Repository Structure

The following is a non-exhaustive overview of the top-level layout; some
subdirectories are omitted for brevity.

```
.
+-- applications/       Example applications (see table above)
+-- include/            Public C headers
|   +-- common/         Shared types and status codes
|   +-- rtp/            RTP service public API
|   +-- ota/            OTA service public API
|   +-- fwual/          Firmware Update Abstraction Layer API
+-- libs/               Service implementation libraries
|   +-- common/         Shared utilities used across libraries
|   +-- el2go_rtp_lib/  RTP core library
|   +-- el2go_ota_lib/  OTA core library
|   +-- net_crypto/     TLS/crypto abstraction (mbedTLS backend)
|   +-- keystores/      Keystore abstraction
|   +-- datastores/     Datastore abstraction (filesystem, plain)
|   +-- osal/           OS abstraction layer (Zephyr, Linux)
|   +-- platforms/      Hardware platform backends (e.g. smw)
|   +-- fwual/          Firmware Update Abstraction Layer
|   +-- protobuf/       nanopb-generated protobuf sources
+-- priv/               Internal/private headers shared across libraries
+-- tests/              Unit and component test suites
+-- doc/                Protobuf reference docs and build guides (e.g. RTP Linux build)
+-- scripts/            Helper scripts (formatting, hooks, packaging, Linux build scripts)
+-- zephyr/             Zephyr module integration files

```

## Documentation

- [Linux RTP Build and Installation Guide](doc/rtp/rtp_linux_build_instructions.md) --
  compilation, configuration, and deployment instructions for the RTP service on Linux.
- [RTP Library Guide](doc/rtp/el2go_rtp_lib.md) --
  architecture, provisioning flow, backends and limitations of the RTP library.
- [OTA Libraries Guide](doc/ota/el2go_ota_lib.md) --
  architecture, update flow, FWUAL, reference agents and backends of the OTA components.
- Application guides (`applications/**/README.md`) --
  what each application does.
- Zephyr sample guides (`zephyr/samples/<sample>/README.rst`) --
  how to build, configure and run each Zephyr sample.
- API reference --
  [EL2GO RTP User Manual](doc/rtp/EL2GO_RTP_UserManual.pdf) and
  [EL2GO OTA User Manual](doc/ota/EL2GO_OTA_UserManual.pdf).

### Zephyr Samples Overview

`its_partition` is a reserved range of non-volatile (flash) memory that is used to store assets such as keys and
certificates. It backs PSA ITS (Internal Trusted Storage). Provisioning samples write the credentials into it and other
samples read them from there. Location, size and rules are described in the "Credentials and secure storage (PSA ITS)"
section of the
[OTA agent core sample README](zephyr/samples/el2go_ota_agent_core/README.rst).

| Sample | Purpose | TF-M (`/ns`) variant | Uses `its_partition` (non-TF-M) | Depends on |
|--------|---------|----------------------|---------------------------------|------------|
| [el2go_rtp_agent](zephyr/samples/el2go_rtp_agent/README.rst) | Online provisioning via EdgeLock 2GO RTP | Yes | Yes | Optional claim code blob |
| [el2go_import_blob](zephyr/samples/el2go_import_blob/README.rst) | Offline provisioning, imports secure object blobs | Yes | Yes | Blobs loaded in flash |
| [el2go_claimcode_encryption](zephyr/samples/el2go_claimcode_encryption/README.rst) | Encrypts and writes the claim code blob | No | No | -- |
| [el2go_mqtt_demo](zephyr/samples/el2go_mqtt_demo/README.rst) | Verifies provisioned credentials over MQTT (AWS/Azure) | Yes | Yes | Provisioned credentials |
| [el2go_csr](zephyr/samples/el2go_csr/README.rst) | CSR generation and certificate verification | No | Yes | Host Tool |
| [el2go_ota_agent_core](zephyr/samples/el2go_ota_agent_core/README.rst) | Minimal OTA update agent (MCUboot) | No | Yes | mTLS credentials from RTP agent or Import Blob |
| [el2go_ota_agent_advanced](zephyr/samples/el2go_ota_agent_advanced/README.rst) | Production-style OTA agent (scheduler, policy, persistence) | No | Yes | mTLS credentials from RTP agent or Import Blob |

Typical flow: provision with `el2go_rtp_agent` or `el2go_import_blob`, then run an OTA agent that reads the
credentials from the same `its_partition`.

## License

This project is licensed under the Apache License 2.0.
See the [LICENSE](LICENSE) file for details.
