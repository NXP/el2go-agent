# Linux RTP Build and Installation Guide

This document describes how to build the `el2go_rtp_lib` on Linux platforms
equipped with the NXP EdgeLock Secure Enclave (ELE), and lists the main
compile-time configuration options available for the library.

---

## Table of Contents

1. [Overview](#overview)
2. [Build Methods](#build-methods)
3. [Yocto Build](#yocto-build)
4. [Standalone Build (Manual Configuration)](#standalone-build-manual-configuration)
5. [CMake Build Options](#cmake-build-options)
6. [Testing](#testing)

---

## Overview

`el2go_rtp_lib` is the EdgeLock 2GO Remote Trust Provisioning (RTP) agent
library. It connects a device to the EdgeLock 2GO cloud service over mTLS and
provisions cryptographic objects (keys, certificates, blobs) into the device
secure storage.

The library is designed to be portable across build systems -- its source files
and link dependencies are shared between all builds; only the target definition
and installation rules differ. This document covers building for Linux on
devices equipped with the NXP EdgeLock Secure Enclave (ELE).

---

## Build Methods

The EL2GO RTP library can be built using two approaches:

### Yocto Build System (Recommended for Production)

When integrated into the i.MX Linux OS BSP, the Yocto build system automatically handles:

- Dependency resolution and compilation
- Cross-compilation toolchain configuration
- Installation to the target filesystem

This is the recommended approach for production deployments.

### Standalone Build (Manual Configuration)

For development, testing, or custom integration scenarios, the library can be
built independently outside of Yocto. This approach requires:

- Manual installation and configuration of the cross-compilation toolchain
- Building or providing all required dependencies
- Explicit configuration of library paths and build options

Common use cases:

- Internal development and debugging
- Continuous Integration (CI) pipeline integration

---

## Yocto Build

A BitBake recipe for the EL2GO agent is provided in the `meta-imx` layer, which
is part of the NXP i.MX Linux BSP release. It invokes the plain CMake build
described in [Standalone Build (Manual Configuration)](#standalone-build-manual-configuration)
using the Yocto SDK sysroot and cross-compiler that are available in the
build environment.

Refer to the `.bb` recipe files under
`meta-imx/meta-imx-sdk/recipes-security/iot-agent/` for the full set of recipe
variables and `EXTRA_OECMAKE` options used in the Yocto integration.

---

## Standalone Build (Manual Configuration)

### Build Tools

| Tool | Description |
|------|-------------|
| CMake | Available from your Linux distribution or [cmake.org](https://cmake.org/download/) |
| aarch64 cross-compiler | Standalone toolchain |

#### Toolchain

The EL2GO RTP library targets ARM-based processors, specifically the 64-bit
ARM (aarch64) architecture. A 64-bit GNU ARM cross-compilation toolchain is
therefore required. A CMake toolchain file (`scripts/linux/aarch64_toolchain.cmake`)
is provided in the repository to configure the compiler, linker, and sysroot
paths for all build components. Pass its path via `-DCMAKE_TOOLCHAIN_FILE`
when invoking CMake directly, or pass the toolchain installation directory
via `toolpath=<dir>` when using the `scripts/linux/configure.sh` and
`scripts/linux/build.sh` scripts, which derive the toolchain file themselves.

### External Dependencies

| Dependency | Description |
|------------|-------------|
| [NXP SMW (Secure Middleware)](https://github.com/nxp-imx/imx-smw) | The Security Middleware Library (SMW) provides a unified API to interact with the i.MX Secure Subsystems |
| [mbedTLS](https://github.com/nxp-imx/mbedtls/) | Based on upstream mbedTLS with modifications to use the PSA API implemented by SMW, enabling use of the i.MX secure storage for cryptographic operations |

### Build steps

The build is driven by two scripts located in `scripts/linux/`:

- `configure.sh` -- installs the toolchain, builds and exports mbedTLS and SMW,
  then configures the CMake project.
- `build.sh` -- performs individual actions: `build`, `install`, `package`, etc.

> **Note:** Both scripts must be run from the repository root directory.

> **Note:** The build system locates mbedTLS through `pkg-config` rather than a CMake `find_package` call. `configure.sh` sets `PKG_CONFIG_PATH` automatically. When integrating the library into another build system or invoking CMake manually, ensure `PKG_CONFIG_PATH` points to the directory containing the mbedTLS `.pc` files:
> ```bash
> export PKG_CONFIG_PATH=[MbedTLS export path]/usr/lib/pkgconfig:$PKG_CONFIG_PATH
> ```

#### Step 1 -- Configure (install dependencies and generate build system)

This script builds the project dependencies and configures the CMake project.
It assumes that the sources for the dependencies listed in the table below are
already available as sibling directories relative to this repository. The
toolchain is downloaded automatically by the script if not already present.

**Required source directories:**

| Source | Default path | Description |
|--------|-------------|-------------|
| [NXP SMW (Secure Middleware)](https://github.com/nxp-imx/imx-smw) | `../smw` | SMW library source. SMW's own dependencies must also be present; see the SMW repository for details |
| [mbedTLS](https://github.com/nxp-imx/mbedtls/) | `../mbedtls` | Modified mbedTLS source (see [External Dependencies](#external-dependencies)) |

```bash
./scripts/linux/configure.sh <build_dir> <smw_subsystem> [toolpath=<dir>] [testing] [ota]
```

| Argument | Required | Description |
|----------|----------|-------------|
| `build_dir` | Yes | Output build directory (will contain SMW export and build artifacts) |
| `smw_subsystem` | Yes | Comma-separated SMW subsystem(s): `ele`, `tee`, `tee,ele`, `tee,seco` |
| `toolpath=<dir>` | No | Path to the aarch64 toolchain installation (default: `/toolchains`) |
| `testing` | No | Enable unit test build (`BUILD_TESTING=ON`) |
| `ota` | No | Enable OTA library build (`BUILD_OTA=ON`) |

**Example:**

```bash
./scripts/linux/configure.sh /opt/build tee,ele toolpath=/opt/toolchains
```

#### Step 2 -- Build

```bash
./scripts/linux/build.sh build out=<build_dir>
```

**Example:**

```bash
./scripts/linux/build.sh build out=/opt/build
```

#### Step 3 -- Install

```bash
./scripts/linux/build.sh install out=<build_dir> dest=<install_dir>
```

| Argument | Required | Description |
|----------|----------|-------------|
| `out=<dir>` | Yes | Build directory (same as used in configure and build steps) |
| `dest=<dir>` | No | Installation destination directory |
| `testing` | No | Also install unit test binaries |

**Example:**

```bash
./scripts/linux/build.sh install out=/opt/build dest=/opt/install
```

---

## CMake Build Options

The following options apply to both the standalone and Yocto builds.

### Build options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `CMAKE_TOOLCHAIN_FILE` | path | -- | Path to the CMake toolchain file (e.g., `scripts/linux/aarch64_toolchain.cmake`) |
| `TOOLCHAIN_PATH` | path | -- | Path to the aarch64 cross-compiler installation directory |
| `CMAKE_BUILD_TYPE` | string | `Release` | Build type: `Release` or `Debug` |
| `CMAKE_INSTALL_PREFIX` | path | `/usr` | Installation prefix for headers and libraries |
| `NXP_SMW_DIR` | path | -- | Path to the NXP SMW cmake config directory (from the SMW export tree) |
| `BUILD_SHARED_LIBS` | bool | `ON` | Build shared libraries |
| `BUILD_APPLICATIONS` | bool | `ON` | Build sample applications |
| `BUILD_OTA` | bool | `OFF` | Also build the OTA library and applications. On Linux, the OTA build compiles and links successfully, but several OS-specific integration points are stub implementations only; OTA is not yet functionally supported on Linux and this option is intended for build validation and unit testing, not production use |
| `BUILD_TESTING` | bool | `OFF` | Build unit tests |
| `VERBOSE` | int | `2` | Trace verbosity level. Enables `ENABLE_TRACE` and sets `TRACE_LEVEL`. In Release mode values above 2 are capped to 2.<br>`0` -- none (all output suppressed)<br>`1` -- error<br>`2` -- info (default)<br>`3` -- debug<br>`4` -- verbose<br>`5` -- extra |
| `EL2GO_RTP_REQUEST_CRL` | bool | `ON` | Request a Certificate Revocation List during RTP provisioning |
| `NET_CRYPTO_SSL_READ_TIMEOUT_MS` | int | `60000` | Maximum time in milliseconds that a single TLS record read may block waiting for data from the EdgeLock 2GO server. Increase this value on slow or high-latency connections |

### Pluggable Backends

The EL2GO RTP library uses a pluggable backend architecture to stay portable
across different hardware platforms and operating systems. Each backend is
selected at CMake configure time and compiled in statically. New backends can
be added in the future without changing the core library API.

| CMake option | Default (Linux) | Description |
|--------------|----------------|-------------|
| `PLATFORM` | `smw` | Hardware platform abstraction. Controls how the library interacts with the secure subsystem (e.g., key provisioning, UUID retrieval). Currently `smw` (NXP Secure Middleware) is the only supported backend for Linux |
| `CRYPTO_BACKEND` | `mbedtls` | TLS/crypto library used for the mTLS connection to the EdgeLock 2GO server. Currently `mbedtls` is the only supported backend |
| `KEYSTORE` | `psa` | Keystore backend used to store and retrieve provisioned cryptographic objects. Currently `psa` (PSA Crypto / ITS via SMW) is the only supported backend for Linux |

### Installed artifacts

After `cmake --install`, the following are placed under the install prefix:

```
lib/
    libel2go_rtp.so
    cmake/el2go-agent/el2go_rtp/
        el2go_rtp-targets.cmake
        el2go_rtp-config.cmake
        el2go_rtp-config-version.cmake
include/el2go-agent/
    rtp/el2go_rtp.h
    rtp/el2go_rtp_config.h
    rtp/el2go_rtp_certificates.h
    rtp/el2go_rtp_claimcode.h
    rtp/el2go_rtp_timing.h
    common/el2go_datastore.h
    common/el2go_keystore.h
    common/el2go_platform.h
    common/el2go_status.h
    common/el2go_version.h
```

The library exports a CMake package under the `el2go::` namespace. Downstream
projects can consume it with:

```cmake
find_package(el2go_rtp REQUIRED)
target_link_libraries(my_app PRIVATE el2go::el2go_rtp)
```

---

## Testing

Unit tests are built as two separate executables:

- `el2go_unit_tests_public` -- exercises the library's public API only.
- `el2go_unit_tests_internal` -- exercises internal implementation details not
  exposed through the public API.

Both executables are registered with CTest, and can also be invoked directly
as standalone programs with command-line options to select or skip specific
test suites.

### Building the tests

Unit tests are gated behind the `BUILD_TESTING` CMake option (`OFF` by
default). Enable it either via the `configure.sh` script or directly through
CMake.

**Using the scripts:**

```bash
./scripts/linux/configure.sh /opt/build tee,ele toolpath=/opt/toolchains testing
./scripts/linux/build.sh build out=/opt/build testing
```

**Using CMake directly:**

```bash
cmake -S . -B /opt/build -DBUILD_TESTING=ON ...
cmake --build /opt/build --target build_tests
```

> **Note:** Unit tests are built with the same toolchain, dependencies
> (SMW, mbedTLS), and target architecture (aarch64) as the rest of the
> project.

### Installing the tests

Test binaries and their generated `CTestTestfile.cmake` can be installed to a
target filesystem/rootfs (e.g., for on-target execution) using the
`install_tests` target, or via the `build.sh install` script with the
`testing` argument:

```bash
./scripts/linux/build.sh install out=/opt/build dest=/opt/install testing
```

This installs the test executables under `<dest>/usr/bin` and the CTest
registration files under `<dest>/usr/share/el2go/tests`.

### Running the tests with CTest

On the target hardware, run `ctest`:

```bash
ctest --test-dir /usr/share/el2go/tests --output-on-failure
```

Useful CTest options:

| Option | Description |
|--------|--------------|
| `-R <regex>` | Run only tests whose name matches `<regex>` (e.g., `-R unit_public_el2go_rtp`) |
| `-L <label>` | Run only tests with a matching label (e.g., `-L public`, `-L internal`, `-L el2go_rtp`) |
| `-N` | List the tests that would run, without running them |
| `--output-on-failure` | Print test output when a test fails |

**Examples:**

```bash
# List all registered tests
ctest --test-dir /usr/share/el2go/tests -N

# Run only the public API tests
ctest --test-dir /usr/share/el2go/tests -L public --output-on-failure

# Run only the RTP-related tests (public and internal)
ctest --test-dir /usr/share/el2go/tests -R el2go_rtp --output-on-failure
```

> **Note:** OTA-related tests (`fwual`, `ota_lib`, `ota_agent_core`,
> `ota_agent_advanced`) are only registered when `BUILD_OTA=ON`, and are
> `DISABLED` by default.

### Running the test executables directly

The test executables can also be run directly, which is useful for debugging
a specific suite or passing suite filters that are not exposed through CTest.
On the target filesystem they are available under `/usr/bin`:

```bash
# Run all public API tests
/usr/bin/el2go_unit_tests_public

# Run all internal tests
/usr/bin/el2go_unit_tests_internal
```

**Command-line options:**

| Option | Description |
|--------|--------------|
| `-s, --suite=<name>` | Run only tests from the specified suite (`el2go_rtp`, `datastore`, `keystore`, `platform`, `net_crypto`, `fwual`, `ota_lib`, `ota_agent_core`, `ota_agent_advanced`) |
| `-k, --skip=<list>` | Comma-separated list of suites to skip |
| `-a, --all` | Run all tests (default) |
| `-h, --help` | Show the help message |

**Examples:**

```bash
# Run only the el2go_rtp suite
/usr/bin/el2go_unit_tests_internal --suite=el2go_rtp

# Run all suites except net_crypto and keystore
/usr/bin/el2go_unit_tests_internal --skip=net_crypto,keystore
```

---
