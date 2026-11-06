# List of changes

This file briefly describes the list of changes and bug fixes for each
EdgeLock 2GO Agent (RTP/OTA/FWUAL libraries) release.

## List of releases

1. [Release 7.0.0](#release-700)

## Release 7.0.0

### 1. RTP library
* Major redesign of the RTP library, migrating from release 6.5.x.
  Supported platforms are MPUs under the Linux operating system and
  MCUs under the Zephyr operating system.
* Introduced a new, redesigned public API; the library was also
  renamed as part of this redesign.
* All applications in this repository were migrated to the new API.

#### ⚠ Breaking changes

* This release is **not backward compatible** with release 6.5.x or
  earlier. The public API, library name and build/configuration options
  have all changed; applications built against previous releases must
  be ported to the new API before upgrading.

### 2. OTA library
* Initial version of the EdgeLock 2GO OTA (Over-the-Air) library. It has
  support for MCUs under the Zephyr operating system.

### 3. FWUAL library
* Initial version of the Firmware Update Abstraction Layer (FWUAL)
  library. It has support for MCUs under the Zephyr operating system.

### 4. Common
* Initial version of the shared infrastructure used by the RTP, OTA and
  FWUAL libraries (status codes, OSAL, net_crypto, platform and keystore
  abstractions, datastore abstraction, protobuf support).

### 5. Tests
* Initial unit and component test suites for the RTP and OTA libraries.
