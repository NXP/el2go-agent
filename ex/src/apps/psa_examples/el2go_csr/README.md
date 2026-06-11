# EdgeLock 2GO Certificate Signing Request (CSR)

This sample application demonstrates how to generate Certificate Signing Requests (CSR) and verify X.509 certificates on an MCU device using PSA Crypto APIs. The application is designed to work with a Host Tool for seamless integration into production workflows.

The application supports two operational modes:
- **CSR Generation Mode**: Generates a new key pair (or uses an existing one) and creates a CSR that can be sent to a Certificate Authority (CA) for signing.
- **Certificate Verification Mode**: Verifies an X.509 certificate received from an external source against the corresponding PSA key stored on the device.

Additional information about EdgeLock 2GO X.509 Certificate Service for MCUs can be found in AN14838 under the following link https://www.nxp.com/webapp/sps/download/license.jsp?colCode=AN14838&appType=file1&DOWNLOAD_ID=null.

## Prerequisites

- Active [EdgeLock 2GO](https://www.edgelock2go.com) account
- [MbedTLS](https://github.com/Mbed-TLS/mbedtls) source (version 3.x)
- CMake >= 3.15 and a compatible C toolchain (e.g., ARM GCC, IAR, KEIL MDK)
- A Host Tool capable of reading/writing device memory (e.g., J-Link Commander or OpenOCD)
- Any serial terminal 

## Overview

The application flow consists of the following steps:

1. Platform and OS initialization (`platform_init()`, `os_init()`)
2. PSA Crypto initialization (`psa_crypto_init()`)
3. Parse the configuration block (TLV format) provided by the Host Tool at a defined memory location (`el2go_csr_conf_data`)
4. Verify configuration block integrity with the defined algorithm 
5. Execute the requested operation:
   - **CSR Generation**: Generate/retrieve PSA key, create CSR, write to memory
   - **Certificate Verification**: Read certificate from memory, verify against PSA key via challenge-response
6. Write operation status code to memory (`el2go_spsdk_status`) for Host Tool retrieval

## Repository Structure

```
ex/src/apps/psa_examples/el2go_csr/
├── app/
│   ├── inc/
│   │   |── el2go_csr.h              # Main application header (defines, includes)
|   |   └── el2go_csr_tlv_parser.h   # TLV configuration block definitions
│   └── src/
│       ├── el2go_csr.c              # Application entry point (main)
│       └── el2go_csr_tlv_parser.c   # TLV configuration block parser
├── common/
│   ├── inc/
│   │   |── csr_util.h               # CSR/certificate utility API
|   |   └── bytes_utils.h            # Helper functions for byte manipulation operations
│   └── src/
│       └── csr_util.c               # CSR generation and certificate verification logic
├── osal/
│   ├── inc/
│   │   └── el2go_csr_osal.h         # OS abstraction layer API
│   ├── baremetal/                   # Baremetal OSAL implementation
│   └── zephyr/                      # Zephyr OSAL implementation
├── pal/
│   ├── inc/                         # Platform abstraction layer headers (APIs to implement)
│   │   ├── el2go_csr_platform.h
│   │   ├── el2go_csr_memory.h
│   │   ├── el2go_csr_psa_key.h
│   │   ├── el2go_csr_pal_util.h
│   │   ├── el2go_csr_challenge.h
│   │   └── el2go_csr_console.h
│   └── boards/
│       ├── my_board/                # Template board port (starting point for new boards)
│       └── frdmmcxe31b/             # Reference NXP board port (working implementation)
├── port/
│   └── el2go_csr_mbedtls_user_config.h  # MbedTLS configuration
└── CMakeLists.txt                   # Standalone CMake build system
```

## Preparing the Application

### 1. Clone the el2go-agent repository from GitHub

```bash
git clone https://github.com/NXP/el2go-agent.git
```

> **Note:** MbedTLS version **3.x** is required. When cloning MbedTLS, ensure you check out a 3.x release tag. Additionally, the following PSA header files must be present in the MbedTLS include path, as they are required by the application:
> - `psa/error.h`
> - `psa/internal_trusted_storage.h`
> - `psa/storage_common.h`
>
> If these headers are not provided by your MbedTLS version or platform SDK, you must supply them separately and ensure they are reachable via the include directories configured in your board's `CMakeLists.txt`.

### 2. Create your board port

Copy the `my_board` template directory and rename it to match your target board (replace `my_board` with `<your_board>` throughout)

> **Note:** `my_board` is a dummy showcase template. It provides the correct file structure and stub implementations but does not target any real hardware. See the [Porting Guide](#porting-guide) section for what you need to implement.

### 3. **[OPTIONAL]** Configure the target OS

Currently, only **baremetal** execution is supported. Zephyr and other OS targets are planned for future releases. The OS can be configured via CMake:

```bash
-DEL2GO_CSR_OS=baremetal
```

### 4. **[OPTIONAL]** Configure logging level

Adjust the logging verbosity by modifying the CMake cache variable `EL2GO_CSR_LOG_LEVEL` during build:

```bash
-DEL2GO_CSR_LOG_LEVEL=LOG_DEBUG
```

Available levels are:
- `LOG_ERROR`: Only error messages
- `LOG_WARNING`: Warning and error messages
- `LOG_INFO`: Informational messages, warnings, and errors (default)
- `LOG_DEBUG`: Debug messages, info, warnings, and errors
- `LOG_TRACE`: All messages including verbose trace information

Alternatively, override the default directly in `pal/inc/el2go_csr_console.h`:

```c
#ifndef CSR_LOG_LEVEL
#define CSR_LOG_LEVEL LOG_INFO
#endif
```

### 5. **[OPTIONAL]** Configure the CSR subject name

The default subject name is defined in `common/inc/csr_util.h`:

```c
#define CSR_SUBJECT_CN  "FRDM-MCXE31B"
#define CSR_SUBJECT_O   "NXP"
#define CSR_SUBJECT_C   "NL"
```

Override these at build time to match your device identity:

```bash
-DCSR_SUBJECT_CN="MyDevice" -DCSR_SUBJECT_O="MyCompany" -DCSR_SUBJECT_C="DE"
```

Or define `CSR_SUBJECT_NAME` directly as a compile definition to provide a fully custom subject string.

### 6. Build the application

Configure and build using CMake. The following cache variables are required:

| Variable | Description |
|----------|-------------|
| `EL2GO_CSR_BOARD` | Name of your board directory under `pal/boards/` |
| `EL2GO_CSR_MBEDTLS_PATH` | Path to the MbedTLS source directory |
| `CMAKE_TOOLCHAIN_FILE` | Path to your cross-compilation toolchain file |

Any additional variables (e.g., SDK path) are defined in your board-specific `CMakeLists.txt` and passed accordingly.

```bash
cmake -S ex/src/apps/psa_examples/el2go_csr \
      -G <generator> \
      -B build \
      -DCMAKE_TOOLCHAIN_FILE=<path/to/your/toolchain.cmake> \
      -DEL2GO_CSR_BOARD=<your_board> \
      -DEL2GO_CSR_MBEDTLS_PATH=<path/to/mbedtls> \
      [<board-specific variables>]

cmake --build build
```

> **Note:** Board-specific CMake variables (e.g., a path to your vendor SDK) are defined in `pal/boards/<your_board>/CMakeLists.txt`. Refer to `pal/boards/my_board/CMakeLists.txt` for the annotated template.

### 7. Connect the Host Tool and flash the binaries to the target board

Connect your debug probe / Host Tool to the board and open a serial terminal with your UART communication settings and load the configuration block binary to the predefined memory location. Additionally, use your Host Tool to download the application binary to the target.

## Running the Application

The application is controlled by the Host Tool. The configuration data is written to the memory location pointed to by `el2go_csr_conf_data`, and the operation status is returned via `el2go_spsdk_status`, which is mapped to a specific memory address for the Host Tool to retrieve.

### CSR Generation Mode

When the configuration block specifies CSR generation, the application will:

1. Parse the key ID and operation type from the configuration
2. Generate a new PSA key or use an existing one. Based on the TLV field `device_operation` and if a PSA key already exists under the specified PSA key ID
3. Generate a CSR using the PSA key
4. Write the CSR to the specified destination memory address

Example log output (with `EL2GO_CSR_LOG_LEVEL` set to `LOG_TRACE`):

```
[INFO] ########### EdgeLock2GO Certificate Signing Request Application ###########
[DEBUG] CSR has been generated! Writing to memory now...
[DEBUG] Generated CSR:-----BEGIN CERTIFICATE REQUEST-----
MIIBIjCByQIBADBnMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExEjAQBgNVBAcM
...
-----END CERTIFICATE REQUEST-----
[TRACE] Returning to main function from generate_cert_sign_req subroutine.
[INFO] CSR generation completed successfully!
[DEBUG] Returning status code of operation
[INFO] ########### EdgeLock2GO Certificate Signing Request App. EXIT ###########
```

Example log output (with default `EL2GO_CSR_LOG_LEVEL` set to `LOG_INFO`):

```
[INFO] ########### EdgeLock2GO Certificate Signing Request Application ###########
[INFO] CSR generation completed successfully!
[INFO] ########### EdgeLock2GO Certificate Signing Request App. EXIT ###########
```

### X.509 Certificate Storage

When the configuration block specifies certificate storage/verification, the application will:

1. Parse the key ID and certificate source address from the configuration
2. Read the X.509 certificate from the configuration block specified memory location
3. Verify the certificate's public key matches the PSA key by generating a signature using the private key and verifying it using the public key embedded in the certificate (challenge-response mechanism)
4. Return the verification status

Example log output (with default `EL2GO_CSR_LOG_LEVEL` set to `LOG_INFO`):

```
[INFO] ########### EdgeLock2GO Certificate Signing Request Application ###########
[INFO] Certificate verification and storage completed successfully!
[INFO] ########### EdgeLock2GO Certificate Signing Request App. EXIT ###########
```

### Status Codes

The application returns status codes to the Host Tool via the `el2go_spsdk_status` memory location:

| Status Code | Value | Description |
|-------------|-------|-------------|
| `SPSDK_STATUS_CODE_SUCCESS` | `0x3BBBA12D` | Operation completed successfully |
| `SPSDK_STATUS_CODE_INIT` | `0xDEADBEEF` | Initial value before application runs |

For all other status codes, refer to the relevant module in the codebase depending on where the failure occurred — e.g., the TLV parser (`el2go_csr_tlv_parser.h`), the memory PAL (`el2go_csr_memory.h`), or PSA Crypto error codes (`psa/crypto_values.h`).

## Integration with the Host Tool

The typical workflow between the Host Tool and the device is:

1. Host Tool prepares the configuration block in TLV format
2. Host Tool writes the configuration block to the device memory address of `el2go_csr_conf_data`
3. Host Tool triggers application execution
4. Application processes the request and writes results to memory
5. Host Tool reads the CSR and the status code from device memory

The memory addresses for `el2go_csr_conf_data` and `el2go_spsdk_status` are defined in the board-specific PAL implementation. These addresses must be communicated to the Host Tool so it knows where to write the configuration block and where to read the result.

## Configuration Block Format

The configuration block uses a TLV (Type-Length-Value) format with BER-encoded length fields and integrity verification. The application supports two distinct configuration block types, identified by their magic number.

### CSR Generation Block

Used when requesting a CSR to be generated on the device.

| Field | Tag ID | Description |
|-------|--------|-------------|
| Magic | `0x40` | Magic value identifying CSR generation mode |
| Version | `0x41` | Configuration block version number |
| Device Operation | `0x42` | Operation type (generate new key or use existing) |
| Key ID | `0x43` | PSA key identifier |
| CSR Destination Address | `0x44` | Memory address where the generated CSR will be written |
| Integrity Algorithm | `0x47` | Algorithm used for integrity verification |
| Integrity Value | `0x48` | Checksum over all preceding fields |

### X.509 Certificate Storage Block

Used when requesting an X.509 certificate to be verified and stored on the device.

| Field | Tag ID | Description |
|-------|--------|-------------|
| Magic | `0x40` | Magic value identifying certificate storage mode |
| Version | `0x41` | Configuration block version number |
| Device Operation | `0x42` | Operation type |
| Key ID | `0x43` | PSA key identifier |
| Certificate Source Address | `0x45` | Memory address where the X.509 certificate is located |
| Certificate Source Size | `0x46` | Size of the X.509 certificate in bytes |
| Integrity Algorithm | `0x47` | Algorithm used for integrity verification |
| Integrity Value | `0x48` | Checksum over all preceding fields |

### Integrity Verification

The configuration block integrity is verified using the algorithm specified in the `Integrity Algorithm` field. Currently supported algorithms:

| Algorithm ID | Algorithm | Output Size |
|--------------|-----------|-------------|
| `1` | CRC32 | 4 bytes |

---

## Porting Guide

To port the application to a new board, you must implement the **Platform Abstraction Layer (PAL)** and optionally adapt the **OS Abstraction Layer (OSAL)**. All PAL headers are located in `pal/inc/`. The `my_board` template in `pal/boards/my_board/` provides stub implementations as a starting point.

The following sections describe each interface that must be implemented.

---

### PAL: `el2go_csr_platform.h` — Platform Initialization

**File to implement:** `pal/boards/<your_board>/el2go_csr_platform.c`

```c
platform_status_t platform_init(void);
```

This is the first function called in `main()`. It must initialize all hardware and software components required before the application can run. This typically includes:

- System clock initialization (e.g., `SystemInit()`, PLL setup)
- UART/debug console initialization (required for log output)
- PSA Crypto backend initialization (e.g., hardware security element, ITS/flash storage driver)
- Any other board-specific peripheral setup

**Return values:**
- `kStatus_PLATFORM_INIT_SUCCESS` (`0xADDEF992`) — initialization succeeded
- `kStatus_PLATFORM_INIT_FAILED` (`0xBB321844`) — initialization failed; the application will abort and write this value to `el2go_spsdk_status`

For a reference implementation, see `pal/boards/frdmmcxe31b/el2go_csr_platform.c`.

---

### PAL: `el2go_csr_memory.h` — Memory Read/Write

**File to implement:** `pal/boards/<your_board>/el2go_csr_flash_memory.c`

This is the most critical PAL component. It abstracts all memory access and exposes two symbols that the application uses to communicate with the Host Tool:

```c
/* Pointer to the configuration block written by the Host Tool */
extern uint8_t* const el2go_csr_conf_data;

/* Pointer to the status code location read by the Host Tool */
extern uint32_t* const el2go_spsdk_status;
```

These two symbols **must** be defined in your memory implementation. Their addresses must be communicated to the Host Tool so it knows where to write the configuration block and where to read the result.

You must also implement the following functions:

```c
csr_mem_status_t mem_read(uint32_t addr, uint8_t *buffer, size_t size);
csr_mem_status_t mem_write(uint32_t addr, const uint8_t *data, size_t size);
```

**`mem_read`** reads `size` bytes from the memory address `addr` into `buffer`. This is used to:
- Read the X.509 certificate from memory (certificate verification mode)
- Read the existing status code before writing (to avoid unnecessary flash writes)

**`mem_write`** writes `size` bytes from `data` to the memory address `addr`. This is used to:
- Write the generated CSR to the destination address
- Write the operation status code to `el2go_spsdk_status`

For all return values, refer to the `csr_mem_status_t` enum defined in `pal/inc/el2go_csr_memory.h`.

**Important considerations for flash-based implementations:**
- Flash memory typically requires an erase before write. Your `mem_write` must handle sector erase internally.
- The `el2go_spsdk_status` write is optimized: the application reads the existing value first and only writes if it has changed, to avoid unnecessary flash wear.
- The configuration block size is fixed at **124 bytes** (`EL2GO_CSR_CONF_DATA_SIZE`). Ensure the memory region reserved for `el2go_csr_conf_data` is at least this size.
- Choose memory addresses that do not conflict with your linker sections, ITS storage, or other firmware regions.

For a template flash implementation, see `pal/boards/my_board/el2go_csr_flash_memory.c`.

---

### PAL: `el2go_csr_psa_key.h` — PSA Key Attributes

**File to implement:** `pal/boards/<your_board>/el2go_csr_psa_key.c`

```c
void fill_key_attributes(psa_key_attributes_t *attr, psa_key_id_t *key_id);
```

This function fills the PSA key attributes used when generating or accessing the key for CSR generation. It is called by `generate_key()` in `csr_util.c`.

The following attributes must be configured:
- **Key ID** — use the key ID parsed from the configuration block
- **Lifetime** — the key must persist across resets; use `PSA_KEY_LIFETIME_PERSISTENT` or a platform-specific persistent lifetime if your platform uses a hardware-backed key store (e.g., a secure element)
- **Usage flags** — must include at minimum sign-hash and sign-message capabilities
- **Algorithm** — the signing algorithm used for CSR generation and certificate verification (e.g., ECDSA with SHA-256)
- **Key type** — the key pair type matching your chosen algorithm (e.g., ECC P-256)
- **Key bits** — the key size in bits matching your chosen key type

> **Note:** The specific algorithm, key type, and key size are suggestions based on the reference implementation. These can be adapted to match your platform's capabilities and CA requirements, as long as the key attributes remain consistent with the challenge-response configuration in `get_challenge_response_config()`.

> **Important:** The application uses **persistent PSA keys** (`PSA_KEY_LIFETIME_PERSISTENT`). This requires a properly configured Internal Trusted Storage (ITS) layer backed by MbedTLS. Ensure that the MbedTLS ITS implementation is initialized in `platform_init()` and that the underlying storage (e.g., flash) is correctly configured before `psa_crypto_init()` is called. Without a working ITS layer, key generation and retrieval will fail.

For a reference implementation, see `pal/boards/my_board/el2go_csr_psa_key.c`.

---

### PAL: `el2go_csr_pal_util.h` — Message Digest Algorithm

**File to implement:** `pal/boards/<your_board>/el2go_csr_pal_util.c`

```c
mbedtls_md_type_t get_msg_digest_algo(void);
```

Returns the MbedTLS message digest algorithm used for CSR generation. This is called by `generate_csr()` in `csr_util.c` to set the signature hash algorithm on the CSR.

For most platforms, return `MBEDTLS_MD_SHA256`. Only change this if your platform's PSA Crypto backend does not support SHA-256 or if a different digest is required by your CA.

---

### PAL: `el2go_csr_challenge.h` — Certificate Verification Configuration

**File to implement:** `pal/boards/<your_board>/el2go_csr_challenge.c`

```c
const challenge_response_config_t *get_challenge_response_config(void);
```

Returns a pointer to the challenge-response configuration used during X.509 certificate verification. The `verify_certificate()` function in `csr_util.c` uses this configuration to:

1. Generate a random challenge of `challenge_size` bytes
2. Hash the challenge using `hash_alg`
3. Sign the hash using the device's private key with `sig_alg`
4. Extract the public key from the received X.509 certificate
5. Import the public key as a temporary PSA key of type `key_type`
6. Verify the signature using the imported public key

The `challenge_response_config_t` structure:

```c
typedef struct {
    size_t challenge_size;      /* Size of the random challenge in bytes */
    psa_algorithm_t hash_alg;   /* PSA hash algorithm */
    psa_algorithm_t sig_alg;    /* PSA signature algorithm */
    psa_key_type_t key_type;    /* Public key type for verification */
    size_t max_hash_size;       /* Maximum hash output size in bytes */
    size_t max_sig_raw_size;    /* Maximum raw signature size in bytes */
    size_t max_pub_key_size;    /* Maximum public key size in bytes */
} challenge_response_config_t;
```

This configuration must be consistent with the key attributes set in `fill_key_attributes()`.

---

### PAL: `el2go_csr_integrity_verifier.h` — Integrity Verification

**File to implement:** `pal/boards/<your_board>/el2go_csr_integrity_verifier.c`

```c
csr_integrity_verifier_t verify_integrity(uint8_t *data, size_t size,
                                           const uint8_t *checksum,
                                           integrity_algorithms_t algo);
```

This function verifies the integrity of the configuration block before the application processes it. It is called in `main()` after TLV parsing.

- `data`: Pointer to the configuration block data (all fields preceding the integrity value)
- `size`: Number of bytes to verify (determined by the operation mode: `CSR_GEN_TOTAL_FIXED_FIELDS_LEN` or `CERT_STORAGE_TOTAL_FIXED_FIELDS_LEN`)
- `checksum`: Pointer to the expected checksum bytes parsed from the TLV
- `algo`: The integrity algorithm identifier (currently only `CRC_32 = 0x1` is supported)

**Return values:**
- `kStatus_CSR_INT_VERIFY_SUCCESS` (`0x100A23BE`) — integrity check passed
- `kStatus_CSR_INT_VERIFY_INVALID_ARG` (`0x187B33BF`) — null pointer or invalid argument
- `kStatus_CSR_INT_VERIFY_FAILED` (`0xFDD7653A`) — checksum mismatch

The MCU implementation and the Host Tool must be synchronized on the integrity algorithm parameters (e.g., polynomial, initial value, final XOR, reflection settings). If your platform has a hardware CRC peripheral, you may use it instead of a software implementation, as long as it is configured to produce results identical to what the Host Tool expects. See `pal/boards/frdmmcxe31b/el2go_csr_integrity_verifier.c` for an example using the NXP hardware CRC module.

> **Important:** Any mismatch between the MCU and Host Tool integrity algorithm parameters will cause `"Configuration data integrity verification failed!"`.

---

### PAL: `el2go_csr_bsp.h` — Board Support Package (BSP) Header

**File to implement:** `pal/boards/<your_board>/inc/el2go_csr_bsp.h`

This header provides the board-specific `PRINTF` and `SCANF` macro definitions used by the OSAL layer for console I/O. It must define:

```c
#define PRINTF(fmt_s, ...)  /* your board's printf equivalent */
#define SCANF(fmt_s, ...)   /* your board's scanf equivalent */
```

For most embedded platforms, wrap your UART-based debug console output here. For example, if your SDK provides `DbgConsole_Printf`:

```c
#include "your_debug_console.h"
#define PRINTF(fmt_s, ...)  DbgConsole_Printf(fmt_s, ##__VA_ARGS__)
#define SCANF(fmt_s, ...)   DbgConsole_Scanf(fmt_s, ##__VA_ARGS__)
```

The `my_board` template defaults to standard `printf`/`scanf`, which is suitable for platforms with a semihosting or UART-backed `libc`:

```c
#include <stdio.h>
#define PRINTF(fmt_s, ...)  printf(fmt_s, ##__VA_ARGS__)
#define SCANF(fmt_s, ...)   scanf(fmt_s, ##__VA_ARGS__)
```

---

### PAL: `el2go_csr_mbedtls_user_config_board.h` — Board-Specific MbedTLS Configuration

**File to implement:** `pal/boards/<your_board>/inc/el2go_csr_mbedtls_user_config_board.h`

This header provides board-specific MbedTLS feature enablement macros. It acts as an overlay on top of the root `port/el2go_csr_mbedtls_user_config.h`, which is the main MbedTLS configuration file used for the build. The root config does not include the board header, but can be added like followingly: 

```c
/* in port/el2go_csr_mbedtls_user_config.h */
#include "el2go_csr_mbedtls_user_config_board.h" 
```

Use this file to enable any MbedTLS modules that your platform requires but that are not already enabled in the root config. 

---

### OSAL: `el2go_csr_osal.h` — OS Initialization

**File:** `osal/baremetal/src/el2go_csr_osal.c` (already provided, no changes needed for baremetal)

```c
os_status_t os_init(void);
```

For baremetal targets, the provided implementation is a no-op (`nop` instruction) that returns `kStatus_OS_INIT_SUCCESS`. No changes are needed unless your platform requires OS-level initialization before the application runs.

---

### Board CMakeLists.txt

**File to implement:** `pal/boards/<your_board>/CMakeLists.txt`

The board-specific `CMakeLists.txt` must provide three things to the parent build system:

1. **`EL2GO_CSR_BOARD_SOURCES`** (PARENT_SCOPE): List of all `.c` files in your board directory
2. **`EL2GO_CSR_BOARD_INCLUDE_DIRS`** (PARENT_SCOPE): List of board-specific include directories
3. **`el2go_csr_board_sdk`** (CMake target): A `STATIC` or `INTERFACE` library that encapsulates your vendor SDK

```cmake
cmake_minimum_required(VERSION 3.15)

# Path to your vendor SDK
set(BOARD_SDK_PATH "" CACHE PATH "Path to the board/vendor SDK")

# Step 1: Export board sources
file(GLOB _board_sources CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/*.c")
set(EL2GO_CSR_BOARD_SOURCES
    ${_board_sources}
    PARENT_SCOPE
)

set(EL2GO_CSR_BOARD_INCLUDE_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}/inc
    PARENT_SCOPE
)

# Step 2: Create the SDK wrapper target
add_library(el2go_csr_board_sdk STATIC)

target_sources(el2go_csr_board_sdk PRIVATE
    ${BOARD_SDK_PATH}/startup/startup_<your_mcu>.c
    # ... add all required SDK sources
)

target_include_directories(el2go_csr_board_sdk PUBLIC
    ${BOARD_SDK_PATH}/include
    # ... add all required SDK include paths
)

target_compile_definitions(el2go_csr_board_sdk PUBLIC
    CPU_<YOUR_MCU>
    # ... add chip-specific defines
)

# Step 3: Linker script
# Export the linker script path to the parent CMakeLists.txt via PARENT_SCOPE.
# The root CMakeLists.txt passes it to the executable via target_link_options.
set(EL2GO_LINKER_SCRIPT
    ${BOARD_SDK_PATH}/linker/<your_mcu>.ld
    PARENT_SCOPE
)
```

Refer to `pal/boards/my_board/CMakeLists.txt` for the full annotated template.

---

### Porting Checklist

| # | File | Function / Symbol | 
|---|------|-------------------|
| 1 | `el2go_csr_platform.c` | `platform_init()` |
| 2 | `el2go_csr_flash_memory.c` | `mem_read()`, `mem_write()`, `el2go_csr_conf_data`, `el2go_spsdk_status` |
| 3 | `el2go_csr_psa_key.c` | `fill_key_attributes()` |
| 4 | `el2go_csr_pal_util.c` | `get_msg_digest_algo()` |
| 5 | `el2go_csr_challenge.c` | `get_challenge_response_config()` |
| 6 | `el2go_csr_integrity_verifier.c` | `verify_integrity()` |
| 7 | `inc/el2go_csr_bsp.h` | `PRINTF`, `SCANF` macros |
| 8 | `CMakeLists.txt` | `el2go_csr_board_sdk` target, `EL2GO_CSR_BOARD_SOURCES`, `EL2GO_CSR_BOARD_INCLUDE_DIRS`, `EL2GO_LINKER_SCRIPT` |

---

## Troubleshooting

1. **"Platform initialization failed!"**
   - Ensure `platform_init()` correctly initializes the PSA Crypto backend and ITS storage
   - Check that the hardware security element (if present) is properly configured

2. **"Initialization of crypto HW failed!"**
   - `psa_crypto_init()` returned an error — verify your PSA Crypto backend is correctly linked and initialized in `platform_init()`

3. **"Failed to parse configuration block data!"**
   - Verify the configuration block format matches the expected TLV structure
   - Ensure the Host Tool is writing valid configuration data to the correct memory address

4. **"Configuration data integrity verification failed!"**
   - The integrity checksum does not match — verify the Host Tool and MCU are synchronized on the integrity algorithm parameters
   - Ensure the configuration block was not corrupted during the write

5. **"PSA key generation failed!"**
   - Verify the key ID is within the valid PSA key ID range (`PSA_KEY_ID_USER_MIN` to `PSA_KEY_ID_USER_MAX`)
   - Check that persistent key storage (ITS) is correctly initialized in `platform_init()`

6. **"CSR generation failed!"**
   - Verify MbedTLS is correctly configured with `MBEDTLS_USE_PSA_CRYPTO` and `MBEDTLS_PSA_CRYPTO_CONFIG`
   - Check that `get_msg_digest_algo()` returns a supported algorithm

7. **"Certificate verification failed!"**
   - The certificate's public key does not match the PSA key — verify the correct key ID is specified in the configuration block
   - Ensure the challenge-response configuration in `get_challenge_response_config()` is consistent with `fill_key_attributes()`

8. **"Writing generated CSR to memory failed!"**
   - Check that the destination address specified in the configuration block is valid and writable
   - For flash targets, ensure the destination address is not in a write-protected region

9. **"x.509 certificate size exceeds maximum allowed size!"**
   - The certificate size exceeds `MAX_X509_CERT_SIZE` (2048 bytes)
   - Check the certificate being provided or increase `MAX_X509_CERT_SIZE` in `app/inc/el2go_csr.h`

10. **"Memory allocation for x.509 certificate verification failed!"**
    - Insufficient heap memory — increase heap size in your linker configuration or reduce certificate size
