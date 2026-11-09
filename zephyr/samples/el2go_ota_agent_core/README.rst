.. _el2go_ota_agent_core:

EL2GO OTA Agent Core Application
#################################

Overview
********

This sample application shows how to use the EdgeLock 2GO OTA service to check for, download and
apply firmware updates to an MCU device using MCUboot.

The agent runs a minimal single-threaded update flow: it connects to the EdgeLock 2GO OTA server,
periodically polls for available updates, and when one is found, downloads the firmware package
over a mutually-authenticated TLS (mTLS) connection, hands the image to the Firmware Update
Abstraction Layer (FWUAL), verifies it, and reboots the device so that MCUboot can swap in the new
image. All agent logic runs on the main thread; there is no scheduler, retry/backoff policy, or
persisted agent state, this is intentionally the minimal reference flow. See the EL2GO OTA Agent
Advanced sample (:ref:`el2go_ota_agent_advanced`) for those additional features.

The connection to the OTA server always uses mutual TLS:

- The server certificate is verified against the trusted root CA certificate compiled into the
  sample (see step 3 below).
- The device authenticates with an mTLS client key and certificate which must already be provisioned
  in secure storage before running this sample (see step 4 below). The sample only references them by
  object ID; it never imports or provisions them.

This sample runs directly against the on-chip ELS PKC hardware crypto driver; unlike the RTP
Agent, MQTT Demo and Import Blob samples, there is no Trusted Firmware-M (TF-M) Secure/Non-secure
split for this application. It uses sysbuild to build the MCUboot bootloader image together with
the application image in a single ``west build`` invocation; MCUboot is required for the
downloaded image to be swapped in and, if it fails to boot, reverted.

The source code for this application can be found at:
:zephyr_file:`modules/lib/nxp_iot_agent/applications/ota_agents/el2go_ota_agent_core/src/main.c`.

Requirements
************

- FRDM-RW612 or RD-RW612-BGA board
- USB-C (FRDM-RW612) or Micro-USB (RD-RW612-BGA) cable
- Personal Computer
- Wi-Fi access point with connectivity to the OTA server

Prerequisites
*************

- Active EdgeLock 2GO account (https://www.nxp.com/products/security-and-authentication/secure-service-2go-platform/edgelock-2go:EDGELOCK-2GO)
- An EdgeLock 2GO OTA server endpoint reachable from the device, with a firmware update campaign configured
- An mTLS client key pair and X.509 certificate for the device, provisioned to secure storage (e.g. with the
  EL2GO RTP Agent sample (:ref:`el2go_rtp_agent`) or the EL2GO Import Blob sample (:ref:`el2go_import_blob`), built for the
  non-TF-M board target so that the credentials are stored in the same Zephyr Secure Storage ``its_partition``)
- Any serial communicator

Flash Layout
************

The application and the MCUboot image use the following partitions (from :file:`boards/<board>_rw612.overlay` and
:file:`sysbuild/boards/<board>.overlay`, both of which must be kept in sync):

=================================== =========== ======= ====================================================
Partition                           XIP Address Size    Description
=================================== =========== ======= ====================================================
``boot_partition``                  0x08000000  board   MCUboot (board default partition)
``slot0_partition`` (image-0)       0x08040000  4 MB    Primary application slot
``slot1_partition`` (image-1)       0x08440000  4 MB    Secondary slot, receives the downloaded image
``its_partition``                   0x08840000  128 KB  PSA ITS (Zephyr Secure Storage), holds the mTLS credentials
``storage_partition``               0x08860000  8 KB    FWUAL update state (NVS)
``ota_status_partition``            0x08862000  8 KB    Pending OTA status report, survives the update reboot
=================================== =========== ======= ====================================================

When flashing the application, make sure the ``its_partition`` is not erased, otherwise the provisioned mTLS
credentials are lost.

.. _el2go_ota_agent_core_its:

Credentials and secure storage (PSA ITS)
****************************************

The OTA agents never create credentials. The mTLS client key and certificate are provisioned beforehand by the
EL2GO RTP Agent (:ref:`el2go_rtp_agent`) or the EL2GO Import Blob sample (:ref:`el2go_import_blob`). The OTA agent
reads the certificate with ``psa_export_key`` by object ID and uses the key by its key ID (see
:zephyr_file:`modules/lib/nxp_iot_agent/libs/el2go_ota_lib/src/cred/psa/`). This storage is the only link between
the provisioning app and the OTA app:

.. code-block:: text

   RTP agent / import blob  ->  its_partition (key, certificate)  ->  OTA agent

Where the credentials are stored (non-TF-M RW612 targets):

- Zephyr Secure Storage is used as PSA ITS, with the ZMS backend, in the ``its_partition`` (128 KB at
  ``0x08840000``, see the Flash Layout table above). The RTP agent, MQTT demo, Import Blob, CSR, OTA agent core and
  OTA agent advanced samples all use this same partition.

Which files configure it:

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - File
     - Content
   * - :file:`boards/<board>_rw612.overlay` (every sample)
     - Chosen node ``zephyr,secure-storage-its-partition = &its_partition`` and the ``its_partition`` definition
   * - :file:`sysbuild/boards/<board>.overlay` (OTA samples only)
     - The MCUboot copy of the partition table; must stay in sync with the application overlay
   * - :file:`prj.conf` (OTA samples and CSR sample)
     - ``CONFIG_SECURE_STORAGE=y``, ``CONFIG_SECURE_STORAGE_ITS_STORE_IMPLEMENTATION_ZMS=y``, ``CONFIG_ZMS=y``
   * - :file:`boards/<board>_rw612.conf` (RTP agent, MQTT demo, Import Blob)
     - ``CONFIG_SECURE_STORAGE_ITS_STORE_IMPLEMENTATION_ZMS=y`` and the ITS size settings (non-TF-M board targets)

The RTP agent, MQTT demo, OTA agent core and OTA agent advanced samples use identical
``CONFIG_SECURE_STORAGE_ITS_MAX_DATA_SIZE=2944`` and ``CONFIG_SECURE_STORAGE_ITS_STORE_ZMS_SECTOR_SIZE=8192``.
The Import Blob sample uses ``CONFIG_SECURE_STORAGE_ITS_MAX_DATA_SIZE=1024`` and does not set the sector size (known
difference). The CSR sample sets neither the maximum data size nor the sector size (known difference). The ITS
settings should be kept identical between the applications that share the partition.

Rules:

- Do not erase, move or resize the ``its_partition`` between running the RTP agent (or Import Blob) and the OTA agent.
- Do not erase the ``its_partition`` when flashing the OTA agent (see Flash Layout above).
- The object IDs configured in this sample (``CONFIG_EL2GO_OTA_CLIENT_KEY_OBJECT_ID`` and
  ``CONFIG_EL2GO_OTA_CLIENT_CERT_OBJECT_ID``, see step 4 below) must match the object IDs of the objects provisioned on
  EdgeLock 2GO.
- In the non-TF-M variant, ITS has no runtime isolation; see :ref:`el2go_rtp_agent_its_isolation`.

.. _el2go_ota_agent_core_mcuboot:

MCUboot configuration
*********************

Swap using move must be enabled on both sides: ``SB_CONFIG_MCUBOOT_MODE_SWAP_USING_MOVE=y`` (sysbuild) and
``CONFIG_BOOT_SWAP_USING_MOVE=y`` (MCUboot image). MCUboot then logs ``Starting swap using move algorithm``.
In addition, ``CONFIG_BOOT_PREFER_SWAP_OFFSET=n`` must be set explicitly in :file:`sysbuild/mcuboot.conf`.

.. list-table::
   :header-rows: 1
   :widths: 40 20 15 25

   * - Option
     - File
     - Value
     - Meaning
   * - ``SB_CONFIG_BOOTLOADER_MCUBOOT``
     - :file:`sysbuild.conf`
     - ``y``
     - Build MCUboot together with the application
   * - ``SB_CONFIG_BOOT_SIGNATURE_KEY_FILE``
     - :file:`sysbuild.conf`
     - ``root-rsa-2048.pem``
     - Signing key (MCUboot module test key)
   * - ``SB_CONFIG_MCUBOOT_MODE_SWAP_USING_MOVE``
     - :file:`sysbuild.conf`
     - ``y``
     - Sysbuild side of swap using move
   * - ``CONFIG_BOOT_SWAP_USING_MOVE``
     - :file:`sysbuild/mcuboot.conf`
     - ``y``
     - MCUboot image side of swap using move
   * - ``CONFIG_BOOT_SIGNATURE_TYPE_RSA``
     - :file:`sysbuild/mcuboot.conf`
     - ``y``
     - RSA signature type
   * - ``CONFIG_BOOT_PREFER_SWAP_OFFSET``
     - :file:`sysbuild/mcuboot.conf`
     - ``n``
     - Must be explicitly disabled
   * - ``CONFIG_MCUBOOT_DOWNGRADE_PREVENTION``
     - :file:`sysbuild/mcuboot.conf`
     - ``y``
     - Downgrade prevention enabled
   * - ``CONFIG_MCUBOOT_DOWNGRADE_PREVENTION_SECURITY_COUNTER``
     - :file:`sysbuild/mcuboot.conf`
     - ``n``
     - Version based rollback protection (see below)
   * - ``CONFIG_MCUBOOT_BOOTUTIL_LIB``, ``CONFIG_BOOTLOADER_MCUBOOT``, ``CONFIG_IMG_MANAGER``, ``CONFIG_STREAM_FLASH``
     - :file:`prj.conf`
     - ``y``
     - Application side MCUboot support

MCUboot runs the new image in test mode: ``fwual_activate()`` requests the upgrade with ``BOOT_UPGRADE_TEST``
(:zephyr_file:`modules/lib/nxp_iot_agent/libs/fwual/mcuboot/fwual_mcuboot.c`), so the swap is temporary until the
agent calls ``fwual_confirm()`` after the reboot. An image that is not confirmed is reverted by MCUboot on the next
reset.

Additionally, :file:`sysbuild.cmake` appends :file:`sysbuild/mcuboot.overlay` and
:file:`sysbuild/boards/<board>.overlay` to ``mcuboot_DTC_OVERLAY_FILE``; :file:`sysbuild/mcuboot.overlay` sets
``zephyr,code-partition = &boot_partition``.

Rollback protection in this sample is version based: the version of the new image (the
:zephyr_file:`modules/lib/nxp_iot_agent/zephyr/samples/el2go_ota_agent_core/VERSION` file) must be higher than the
version of the running image. The security counter based variant is used by the EL2GO OTA Agent Advanced sample
(:ref:`el2go_ota_agent_advanced`).

Prepare the Demo
****************

1.  Provide the EdgeLock 2GO OTA server hostname and port:

    in :zephyr_file:`modules/lib/nxp_iot_agent/zephyr/samples/el2go_ota_agent_core/prj.conf`
    ``CONFIG_EL2GO_OTA_SERVER_HOST="YOUR_HOSTNAME"``
    ``CONFIG_EL2GO_OTA_SERVER_PORT=443``

    The hostname is empty by default and must be set. The sample sets the port to 443 (the Kconfig default is 50051).
    These can also be overridden at runtime (Linux, or Zephyr with ``CONFIG_BOOTARGS``) by passing
    them as command-line arguments: ``<hostname> [port]``.

2.  Provide the Wi-Fi access point credentials:

    in :zephyr_file:`modules/lib/nxp_iot_agent/zephyr/samples/el2go_ota_agent_core/prj.conf`
    ``CONFIG_EL2GO_NET_WIFI_SSID=""``
    ``CONFIG_EL2GO_NET_WIFI_PSK=""``

3.  Provide the trusted root CA certificate of the OTA server. The server certificate is always verified; the
    connection fails if the certificate does not chain to this root CA:

    in :zephyr_file:`modules/lib/nxp_iot_agent/include/ota/el2go_ota_certificates.h`
    ``#define EL2GO_OTA_TRUSTED_ROOT_CA_CERT`` - DER-encoded root CA (or root CA + intermediate CA concatenated), as a hexadecimal byte array
    ``#define EL2GO_OTA_TRUSTED_ROOT_CA_CERT_SIZE``

    The certificate shipped with the sample is a dummy ECC root CA ("OTA Dummy Root CA Prod ECC") and must be replaced
    with the root CA of your OTA server.

4.  Provide the object IDs of the mTLS client key and certificate already provisioned in secure storage:

    in :zephyr_file:`modules/lib/nxp_iot_agent/zephyr/samples/el2go_ota_agent_core/prj.conf`
    ``CONFIG_EL2GO_OTA_CLIENT_KEY_OBJECT_ID=0x3010``
    ``CONFIG_EL2GO_OTA_CLIENT_CERT_OBJECT_ID=0x3021``

    The values shown are the defaults. They must match the object IDs of the key and certificate provisioned on
    EdgeLock 2GO (see :ref:`el2go_ota_agent_core_its`). The client certificate must be DER-encoded.
    If the credentials are not found, ``el2go_ota_init()`` fails with a certificate or authentication error.

5.  [Optional] Adjust the update-check polling interval and status-report retry count:

    in :zephyr_file:`modules/lib/nxp_iot_agent/zephyr/samples/el2go_ota_agent_core/prj.conf`
    ``CONFIG_EL2GO_OTA_POLL_INTERVAL_S`` - interval between update checks (default 30 s)
    ``CONFIG_EL2GO_OTA_CORE_REPORT_MAX_RETRIES`` - attempts to deliver the pending status report after the update
    reboot (default 3); the agent waits one poll interval between attempts

    The download chunk size can be adjusted with ``CONFIG_EL2GO_OTA_CHUNK_SIZE`` (default 4096 bytes).

6.  [Optional] The verbosity of the EL2GO library logs is controlled by ``CONFIG_EL2GO_LIB_LOG_LEVEL``
    (0 = off, 1 = error (sample default), 2 = info, 3 = debug, 4 = verbose, 5 = extra).
    mbedTLS internal debug output can additionally be enabled with ``CONFIG_EL2GO_MBEDTLS_DEBUG_ENABLE=y``.

7.  Build the application. This sample uses sysbuild to build and sign the application image
    together with MCUboot; the signing key is the default sysbuild/MCUboot RSA-2048 test key
    (``root-rsa-2048.pem``, set with ``SB_CONFIG_BOOT_SIGNATURE_KEY_FILE`` in :file:`sysbuild.conf`).
    For production use, replace this key before deployment.

8.  Connect the USB-C (FRDM-RW612) or Micro-USB (RD-RW612-BGA) cable to the PC host and the MCU-Link USB port
    (J10 [FRDM-RW612] or J7 [RD-RW612-BGA]) on the board.

9.  Open a serial terminal with the following settings:

    - 115200 baud rate
    - 8 data bits
    - No parity
    - One stop bit
    - No flow control

10. Flash the application to the board using west flash command.

11. Prepare an update image: increase the version in
    :zephyr_file:`modules/lib/nxp_iot_agent/zephyr/samples/el2go_ota_agent_core/VERSION` (e.g. ``VERSION_MINOR = 2``),
    rebuild, and upload the signed application image (``build/el2go_ota_agent_core/zephyr/zephyr.signed.bin``)
    to the OTA campaign. The new image version must be higher than the running one (see
    :ref:`el2go_ota_agent_core_mcuboot`), and the image must be signed with the same key.

12. On the next poll after the OTA campaign carrying the newer firmware version becomes available, the device will
    automatically download and apply the update, reboot via MCUboot, and confirm the new image. If the new image fails
    to confirm (e.g. it cannot reach the OTA server), MCUboot reverts to the previous image on the next reset.

Building, Flashing and Running
*******************************

.. zephyr-app-commands::
   :zephyr-app: modules/lib/nxp_iot_agent/zephyr/samples/el2go_ota_agent_core
   :board: <board>
   :goals: build flash
   :west-args: --sysbuild
   :compact:

For example:

.. code-block:: console

   west build --sysbuild -b frdm_rw612 modules/lib/nxp_iot_agent/zephyr/samples/el2go_ota_agent_core -- \
       -DCONFIG_EL2GO_OTA_SERVER_HOST=\"my-ota-server.example.com\" \
       -DCONFIG_EL2GO_NET_WIFI_SSID=\"my_ssid\" -DCONFIG_EL2GO_NET_WIFI_PSK=\"my_password\"
   west flash

Sample Output
=============

The output below is abridged; the section headers are added for readability and are not printed
by the application.

.. code-block:: console

    [0000s] MCUBOOT I: Image version: v1.1.0
    [0003s] *** Booting Zephyr OS build 95926e7bf4b8 ***
    [0003s] [INFO] ==== OTA AGENT CORE SAMPLE ====
    [0003s] [INFO] 1.1.0
    [0003s] [DONE] fwual_init()
    [0003s] [INFO] fwual state: 0
    [0003s] [DONE] fwual_get_caps()
    [0019s] [DONE] el2go_app_net_init()
    [0019s] [DONE] el2go_ota_init()

    --- Connect (mTLS) ---
    [0020s] [DONE] el2go_ota_connect()
    [0020s] [INFO] connected to my-ota-server.example.com:443
    [0020s] [INFO] entering update-check loop (poll: 30000 ms)

    --- Check for updates ---
    [0020s] [INFO] checking for updates...
    [0021s] [DONE] el2go_ota_check_for_updates()
    [0021s] [INFO] update available: id=..., packages=1

    --- Download, finalize, verify, activate ---
    [0038s] [INFO] downloading image 0, size 1412776 bytes
    [0070s] [DONE] el2go_ota_download_package()
    [0070s] [DONE] fwual_finalize_image()
    [0072s] [DONE] fwual_verify_image()
    [0072s] [DONE] fwual_commit_session()
    [0072s] [DONE] fwual_activate()
    [0072s] [DONE] fwual_close_session()
    [0072s] [INFO] Download and Handoff Complete
    [0072s] [INFO] STATUS_SUCCESS scheduled
    [0072s] [INFO] activating update...

    --- Reboot, MCUboot swap, confirm ---
    [0073s] MCUBOOT I: Starting swap using move algorithm.
    [0153s] MCUBOOT I: Image version: v1.2.0
    [0157s] *** Booting Zephyr OS build 95926e7bf4b8 ***
    [0157s] [INFO] ==== OTA AGENT CORE SAMPLE ====
    [0157s] [INFO] 1.2.0
    [0157s] [INFO] fwual state: 5
    [0169s] [DONE] el2go_ota_connect()
    [0169s] [INFO] new firmware validated - confirming image
    [0169s] [DONE] fwual_confirm()
    [0169s] [DONE] el2go_ota_report_pending_status()
    [0169s] [INFO] checking for updates...
    [0169s] [DONE] el2go_ota_check_for_updates()
    [0169s] [INFO] No update available - staying idle
