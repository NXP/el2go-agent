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
| `el2go_rtp_agent` | Full RTP agent demo: connects to the EdgeLock 2GO server, provisions keys and certificates into the device, and prints a status report. On Linux this is a minimal reference application; for a more complete, production-oriented Linux provisioning application see the [OEM Provisioning Application](https://github.com/nxp-imx/oem-prov-app). | Zephyr, Linux |
| `el2go_ota_agent_core` | Core OTA agent: connects to the EdgeLock 2GO server, downloads a firmware update, and applies it using the FWUAL layer. | Zephyr |
| `el2go_ota_agent_advanced` | Advanced OTA agent with additional lifecycle management, rollback support, and dual-bank update handling. | Zephyr |
| `el2go_claimcode_encryption` | Utility application that encrypts a device claim code for secure off-line device onboarding. | Zephyr |
| `el2go_csr` | Certificate Signing Request (CSR) generation sample: generates a CSR using the on-chip key and prints it in PEM format. | Zephyr |
| `el2go_import_blob` | Imports a pre-provisioned secure blob into the device keystore. | Zephyr |
| `el2go_mqtt_demo` | MQTT connectivity demo that uses an RTP-provisioned client certificate and key for broker authentication. | Zephyr |

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

## License

This project is licensed under the Apache License 2.0.
See the [LICENSE](LICENSE) file for details.
