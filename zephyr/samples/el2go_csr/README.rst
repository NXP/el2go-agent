.. _el2go_csr:

EL2GO CSR Application
######################

Overview
********

This sample application shows how to generate a Certificate Signing Request (CSR) on an MCU
device and verify an X.509 certificate issued by the EdgeLock 2GO X.509 Certificate Service
against the corresponding on-device key, using PSA Crypto APIs and the ELS PKC hardware crypto
driver.

The application supports two operational modes, selected by the configuration block written by
the Host Tool:

- CSR Generation: generates (or reuses) a PSA key pair and creates a CSR that can be submitted to
  a Certificate Authority (CA) for signing.
- Certificate Verification: verifies an X.509 certificate received from an external source against
  the corresponding PSA key stored on the device via a challenge-response mechanism.

The application is controlled by a Host Tool rather than user interaction. At startup, it reads a
TLV-encoded configuration block from a fixed flash location, verifies its integrity via CRC32,
performs the requested operation and writes a status code (and, in CSR generation mode, the
generated CSR) back to fixed flash locations for the Host Tool to retrieve.

This sample runs directly against the on-chip ELS PKC hardware crypto driver; unlike the RTP
Agent, MQTT Demo and Import Blob samples, there is no Trusted Firmware-M (TF-M) Secure/Non-secure
split for this application. PSA keys are stored persistently in the ELS (S50, RFC3394 wrapped)
key location, and PSA ITS is backed by the Zephyr Secure Storage subsystem (ZMS) on the
``its_partition`` declared in the board overlay (``0x08840000``, 128 KB).

The source code for this application can be found at:
:zephyr_file:`modules/lib/nxp_iot_agent/applications/el2go_csr/app/src/el2go_csr.c`.
This Zephyr sample is a thin wrapper (board selection, Zephyr OSAL, and a Zephyr flash-driver-based
memory PAL) around the shared, platform-agnostic application logic, which is documented in full,
including the Porting Abstraction Layer (PAL) interface, in
:zephyr_file:`modules/lib/nxp_iot_agent/applications/el2go_csr/README.md`.
Note that the board list, CMake options and defaults described there refer to the standalone
(non-Zephyr) build; for the Zephyr build, the values in this document apply.

Additional information about EdgeLock 2GO X.509 Certificate Service for MCUs can be found in AN14838.

Requirements
************

- FRDM-RW612 or RD-RW612-BGA board
- USB-C (FRDM-RW612) or Micro-USB (RD-RW612-BGA) cable
- Personal Computer

Prerequisites
*************

- Active EdgeLock 2GO account (https://www.nxp.com/products/security-and-authentication/secure-service-2go-platform/edgelock-2go:EDGELOCK-2GO)
- A Host Tool capable of reading/writing device flash memory (e.g. a J-Link based tool or SPSDK blhost)
- Any serial communicator

Prepare the Demo
****************

1.  [Optional] The CSR subject name fields are defined in
    :zephyr_file:`modules/lib/nxp_iot_agent/applications/el2go_csr/common/inc/csr_util.h`:
    ``#define CSR_SUBJECT_CN "EL2GO CSR EXAMPLE"``
    ``#define CSR_SUBJECT_O "NXP"``
    ``#define CSR_SUBJECT_C "NL"``

    The resulting default subject is ``CN=EL2GO CSR EXAMPLE,O=NXP,C=NL``. Adjust these to match your device identity
    before building the application. Alternatively, define ``CSR_SUBJECT_NAME`` as a compile definition to provide a
    fully custom subject string (e.g. ``"CN=MyDevice,O=MyCompany,C=DE"``), in which case the three macros above are ignored.

2.  [Optional] The console log verbosity is controlled by ``CSR_LOG_LEVEL``, defined in
    :zephyr_file:`modules/lib/nxp_iot_agent/applications/el2go_csr/pal/inc/el2go_csr_console.h`.
    For the Zephyr build it defaults to ``LOG_TRACE`` (all messages). Available levels are
    ``LOG_ERROR``, ``LOG_WARNING``, ``LOG_INFO``, ``LOG_DEBUG`` and ``LOG_TRACE``.

3.  Build the application.

4.  Connect the USB-C (FRDM-RW612) or Micro-USB (RD-RW612-BGA) cable to the PC host and the MCU-Link USB port
    (J10 [FRDM-RW612] or J7 [RD-RW612-BGA]) on the board.

5.  Open a serial terminal with the following settings:

    - 115200 baud rate
    - 8 data bits
    - No parity
    - One stop bit
    - No flow control

6.  Flash the application to the board using west flash command.

7.  Using the Host Tool, write a TLV-encoded configuration block to the predefined flash location
    (see RW612 Flash Layout and Configuration Block Format below), then reset the board or
    otherwise trigger the application to run. In certificate verification mode, the X.509 certificate
    must also be written to flash before the reset.

8.  Using the Host Tool, read back the status code (and, in CSR generation mode, the generated CSR from the
    CSR destination address) once the application has printed its EXIT message.

RW612 Flash Layout
*******************

The QSPI flash on RW612 is memory-mapped (XIP) at ``0x08000000``. This sample reserves one
dedicated 4 KB sector within it for the configuration block and status code:

=============================================== =========== =========
Region                                          XIP Address Size
=============================================== =========== =========
Configuration block (``el2go_csr_conf_data``)   0x088B0000  124 bytes
Free space (usable as CSR destination)          0x088B007C  3968 bytes
Status code (``el2go_spsdk_status``)            0x088B0FFC  4 bytes
=============================================== =========== =========

All addresses fall within the same 4 KB sector (``0x088B0000``-``0x088B0FFF``); a write to any of
them triggers a read-modify-erase-write of the whole sector, since the underlying Zephyr flash
driver API does not support partial sector updates. Make sure this sector does not overlap any
other partition in your board's flash layout.

The memory PAL (:zephyr_file:`modules/lib/nxp_iot_agent/applications/el2go_csr/pal/zephyr/rw612/el2go_csr_zephyr_memory.c`)
only accepts writes inside this sector. Consequently, the CSR destination address requested in the
configuration block must lie in the free space between the configuration block and the status code
(``0x088B007C``-``0x088B0FFB``) and the CSR must fit in it (a PEM CSR for a P-256 key is typically
below 600 bytes); any other address results in a memory error status code. Reads (configuration
block, X.509 certificate) are done directly through the XIP window and may target any mapped
flash address.

The addresses are fixed at compile time (``EL2GO_CSR_FLASH_SECTOR_OFFSET`` in the memory PAL) and must
match the values used by the Host Tool.

Configuration Block Format
***************************

The configuration block is a 124 byte TLV (Type-Length-Value) structure written by the Host Tool
to a fixed flash location before the application runs. The magic value present in the block
determines which of the two operations is performed.

Encoding rules:

- Each field is encoded as ``tag (1 byte) | length (BER) | value``. Lengths below 128 use the short
  form (1 byte); longer values use the BER long form (``0x8N`` followed by N length bytes, N <= 4).
- Multi-byte integer values are big-endian.
- Every required field must be present exactly once; unknown tags are skipped (forward compatible).
- The Integrity Value field must be the last field; parsing stops after it. Any optional field
  (e.g. Encoding) must therefore be placed before it.
- The CRC32 is computed over all bytes from the start of the block up to and including the tag and
  length bytes of the Integrity Value field (i.e. everything except the 4 CRC value bytes themselves).
  The algorithm is standard CRC-32 (IEEE 802.3, reflected polynomial ``0xEDB88320``, initial value and
  final XOR ``0xFFFFFFFF``).
- Unused bytes after the Integrity Value field up to 124 bytes are ignored.

CSR Generation block (magic ``"el2gocsrgen"``):

======================= ====== ====== ===================================================
Field                   Tag ID Length Description
======================= ====== ====== ===================================================
Magic                   0x40   11     ASCII ``el2gocsrgen`` (no null terminator), identifies CSR generation mode
Version                 0x41   2      Configuration block version number
Device Operation        0x42   1      Generate new key (0x02) or use existing key (0x01)
Key ID                  0x43   4      PSA key identifier
CSR Destination Address 0x44   4      Flash address the generated CSR is written to (see RW612 Flash Layout)
Encoding                0x49   1      Optional: PEM (0x01, default) or DER (0x02)
Integrity Algorithm     0x47   4      Integrity algorithm identifier (CRC32 = 1)
Integrity Value         0x48   4      CRC32 over all preceding bytes, must be the last field
======================= ====== ====== ===================================================

With Device Operation 0x02 an existing key with the same ID is destroyed and a new key is generated;
with 0x01 an existing key is reused, or a new one is generated if none exists. Keys are ECC P-256
(secp256r1) key pairs with ECDSA SHA-256 sign usage. When DER encoding is selected, the CSR is written
to flash but not printed on the console.

X.509 Certificate Verification block (magic ``"el2gocertstr"``):

======================== ====== ====== ===================================================
Field                    Tag ID Length Description
======================== ====== ====== ===================================================
Magic                    0x40   12     ASCII ``el2gocertstr`` (no null terminator), identifies certificate verification mode
Version                  0x41   2      Configuration block version number
Device Operation         0x42   1      Operation type
Key ID                   0x43   4      PSA key identifier of the key the certificate was issued for
Certificate Source Addr  0x45   4      Flash (XIP) address of the X.509 certificate
Certificate Source Size  0x46   4      Size of the X.509 certificate in bytes (max. 2048)
Integrity Algorithm      0x47   4      Integrity algorithm identifier (CRC32 = 1)
Integrity Value          0x48   4      CRC32 over all preceding bytes, must be the last field
======================== ====== ====== ===================================================

The application returns the operation outcome to the Host Tool via a dedicated status flash
location:

================================ ========== =============================================
Status Code                      Value      Description
================================ ========== =============================================
SPSDK_STATUS_CODE_SUCCESS        0x3BBBA12D Operation completed successfully
SPSDK_STATUS_CODE_INIT           0xDEADBEEF Initial value before the application runs
================================ ========== =============================================

Any other value indicates a failure in a specific module; the most common ones are:

================================ ========== =============================================
Status Code                      Value      Description
================================ ========== =============================================
kStatus_CSR_INVALID_FORMAT       0x33D978FF Malformed TLV field (wrong length, duplicate field)
kStatus_CSR_NOT_SUPPORTED        0xA8093E10 Unsupported integrity algorithm or encoding
kStatus_CSR_CONF_BUF_SIZE_ERR    0x39274EFA TLV field exceeds the 124 byte configuration block
kStatus_CSR_TLV_FIELD_MISSING    0x6B1F4A82 Required TLV field missing
kStatus_CSR_INT_VERIFY_FAILED    0xFDD7653A CRC32 mismatch
kStatus_CSR_MEM_INVALID_ARG      0x9DD210C5 Write outside the reserved flash sector
================================ ========== =============================================

PSA Crypto failures are returned as the (negative) ``psa_status_t`` value. Refer to the corresponding
status enums in the source code (``el2go_csr_tlv_parser.h``, ``el2go_csr_memory.h``,
``el2go_csr_integrity_verifier.h``, ``el2go_csr_platform.h``) for the complete list.

Building, Flashing and Running
*******************************

.. zephyr-app-commands::
   :zephyr-app: modules/lib/nxp_iot_agent/zephyr/samples/el2go_csr
   :board: <board>
   :goals: build flash
   :compact:

Sample Output
=============

CSR generation, with the configuration block requesting generation of a new PSA key pair
(``LOG_TRACE`` level, abridged):

.. code-block:: console

    [TRACE] Platform (RW612 Zephyr) has been initialised successfully.
    [INFO] ########### EdgeLock2GO Certificate Signing Request Application ###########
    [TRACE] Verifying data integrity using CRC-32 algorithm
    [DEBUG] Computed CRC32: 0x1A2B3C4D, Expected CRC32: 0x1A2B3C4D
    [TRACE] PSA key generated successfully!
    [DEBUG] CSR has been generated! Writing to memory now...
    [DEBUG] Generated CSR:-----BEGIN CERTIFICATE REQUEST-----
    ...
    -----END CERTIFICATE REQUEST-----
    [TRACE] Returning to main function from generate_cert_sign_req subroutine.
    [INFO] CSR generation completed successfully!
    [DEBUG] Returning status code of operation
    [INFO] ########### EdgeLock2GO Certificate Signing Request App. EXIT ###########

X.509 certificate verification, with the configuration block pointing at a certificate written to
flash by the Host Tool (abridged):

.. code-block:: console

    [INFO] ########### EdgeLock2GO Certificate Signing Request Application ###########
    [DEBUG] Computed CRC32: 0x5E6F7A8B, Expected CRC32: 0x5E6F7A8B
    [DEBUG] x.509 certificate has been read successfully from memory! Verifying keypair...
    [TRACE] Returning to main function from verify_recv_x509_cert subroutine.
    [INFO] Certificate verification and storage completed successfully!
    [DEBUG] Returning status code of operation
    [INFO] ########### EdgeLock2GO Certificate Signing Request App. EXIT ###########
    