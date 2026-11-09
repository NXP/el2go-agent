.. _el2go_ota_agent_advanced:

EL2GO OTA Agent Advanced Application
#####################################

Overview
********

This sample application shows how to use the EdgeLock 2GO OTA service to check for, download and
apply firmware updates to an MCU device using MCUboot, with the additional scheduling, retry and
persistence features expected of a production-grade agent.

It builds on the EL2GO OTA Agent Core flow (:ref:`el2go_ota_agent_core`) by adding:

- A scheduler with a configurable poll cadence, exponential backoff on failure, and an immediate
  check trigger when the network comes up
- A blackout/defer policy that can postpone applying an update outside an allowed maintenance window
- Download and status-report retries
- Persisted agent state (NVS) so an interrupted update, or an update awaiting post-boot
  confirmation, can be reconciled correctly across a reboot or power loss
- Diagnostics that are mirrored to the console and persisted to a dedicated flash ring buffer, so
  the log of the previous session survives reboot, power loss and firmware rollback, and can be
  replayed on the next boot
- MCUboot downgrade prevention based on a security counter (optional VERSION based downgrade prevention)

By default the agent synchronizes time over SNTP at startup (needed for the blackout policy and certificate validity checks),
reconciles any FWUAL state left over from a previous boot, and then hands control to the scheduler, which drives
all further update checks.

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
:zephyr_file:`modules/lib/nxp_iot_agent/applications/ota_agents/el2go_ota_agent_advanced/src/main.c`.
The scheduler, policy and updater logic is located in the same directory (``scheduler.c``, ``policy.c``, ``updater.c``).

Requirements
************

- FRDM-RW612 or RD-RW612-BGA board
- USB-C (FRDM-RW612) or Micro-USB (RD-RW612-BGA) cable
- Personal Computer
- Wi-Fi access point with connectivity to the OTA server and an SNTP server

Prerequisites
*************

- Active EdgeLock 2GO account (https://www.nxp.com/products/security-and-authentication/secure-service-2go-platform/edgelock-2go:EDGELOCK-2GO)
- An EdgeLock 2GO OTA server endpoint reachable from the device, with a firmware update campaign configured
- An mTLS client key pair and X.509 certificate for the device, provisioned to secure storage (e.g. with the
  EL2GO RTP Agent sample (:ref:`el2go_rtp_agent`) built for the non-TF-M board target so that the credentials
  are stored in the same Zephyr Secure Storage ``its_partition``)
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
``agent_state_partition``           0x08864000  8 KB    Persisted agent state (NVS)
``log_partition`` (diag_log)        0x08866000  16 KB   Persistent diagnostics ring buffer
=================================== =========== ======= ====================================================

When flashing the application, make sure the ``its_partition`` is not erased, otherwise the provisioned mTLS
credentials are lost.

How the credentials get into the ``its_partition``, which files configure it and which rules apply is described in the
EL2GO OTA Agent Core sample (:ref:`el2go_ota_agent_core_its`).

.. _el2go_ota_agent_advanced_mcuboot:

MCUboot configuration
*********************

The MCUboot configuration (swap using move, signature type, test mode upgrade and the ``sysbuild.cmake`` overlays) is
the same as in the EL2GO OTA Agent Core sample and is described in :ref:`el2go_ota_agent_core_mcuboot`. This sample
differs only in the following options:

.. list-table::
   :header-rows: 1
   :widths: 40 20 15 25

   * - Option
     - File
     - Value
     - Meaning
   * - ``CONFIG_MCUBOOT_DOWNGRADE_PREVENTION_SECURITY_COUNTER``
     - :file:`sysbuild/mcuboot.conf`
     - ``y``
     - Security counter based rollback protection (core: ``n``)
   * - ``CONFIG_MCUBOOT_EXTRA_IMGTOOL_ARGS``
     - :file:`prj.conf`
     - ``"--security-counter 2"``
     - Security counter written into the signed image by imgtool (not set in core)

Rollback protection can be configured in two ways:

- Version based: the version of the new image (the ``VERSION`` file) must be higher than the version of the running
  image. This is the variant used by the EL2GO OTA Agent Core sample (:ref:`el2go_ota_agent_core`), with
  ``CONFIG_MCUBOOT_DOWNGRADE_PREVENTION_SECURITY_COUNTER=n``.
- Security counter based (this sample): the counter of the new image (imgtool ``--security-counter N``) must be higher
  than the counter on the device, otherwise the image is rejected regardless of the version.

Prepare the Demo
****************

1.  Provide the EdgeLock 2GO OTA server hostname and port:

    in :zephyr_file:`modules/lib/nxp_iot_agent/zephyr/samples/el2go_ota_agent_advanced/prj.conf`
    ``CONFIG_EL2GO_OTA_SERVER_HOST="YOUR_HOSTNAME"``
    ``CONFIG_EL2GO_OTA_SERVER_PORT=443``

    The hostname is empty by default and must be set. The sample sets the port to 443 (the Kconfig default is 50051).
    These can also be overridden at runtime (Linux, or Zephyr with ``CONFIG_BOOTARGS``) by passing
    them as command-line arguments: ``<hostname> [port]``.

2.  Provide the Wi-Fi access point credentials:

    in :zephyr_file:`modules/lib/nxp_iot_agent/zephyr/samples/el2go_ota_agent_advanced/prj.conf`
    ``CONFIG_EL2GO_NET_WIFI_SSID=""``
    ``CONFIG_EL2GO_NET_WIFI_PSK=""``

3.  Provide the trusted root CA certificate of the OTA server. The server certificate is always verified; the
    connection fails if the certificate does not chain to this root CA:

    in :zephyr_file:`modules/lib/nxp_iot_agent/include/ota/el2go_ota_certificates.h`
    ``#define EL2GO_OTA_TRUSTED_ROOT_CA_CERT`` - DER-encoded root CA (or root CA + intermediate CA concatenated), as a hexadecimal byte array
    ``#define EL2GO_OTA_TRUSTED_ROOT_CA_CERT_SIZE``

    The certificate shipped with the sample is a dummy ECC root CA ("OTA Dummy Root CA Prod ECC") and must be replaced
    with the root CA of your OTA server. The same header is used by the EL2GO OTA Agent Core sample.

4.  Provide the object IDs of the mTLS client key and certificate already provisioned in secure storage:

    in :zephyr_file:`modules/lib/nxp_iot_agent/zephyr/samples/el2go_ota_agent_advanced/prj.conf`
    ``CONFIG_EL2GO_OTA_CLIENT_KEY_OBJECT_ID=0x3010``
    ``CONFIG_EL2GO_OTA_CLIENT_CERT_OBJECT_ID=0x3021``

    The values shown are the defaults. They must match the object IDs of the key and certificate provisioned on
    EdgeLock 2GO (see :ref:`el2go_ota_agent_core_its`). The client certificate must be DER-encoded.
    If the credentials are not found, ``el2go_ota_init()`` fails with a certificate or authentication error.

5.  [Optional] Adjust the scheduler and retry behavior:

    in :zephyr_file:`modules/lib/nxp_iot_agent/zephyr/samples/el2go_ota_agent_advanced/prj.conf`

    ================================================ ============= ================ ================================================
    Option                                           Sample value  Kconfig default  Description
    ================================================ ============= ================ ================================================
    ``CONFIG_EL2GO_OTA_ADV_POLL_INTERVAL_S``         10            3600             Base interval between update checks
    ``CONFIG_EL2GO_OTA_ADV_RETRY_INITIAL_BACKOFF_S`` 5             60               Initial backoff delay after a failed check, doubled on each failure
    ``CONFIG_EL2GO_OTA_ADV_RETRY_MAX_BACKOFF_S``     30            3600             Maximum backoff delay
    ``CONFIG_EL2GO_OTA_ADV_DOWNLOAD_MAX_RETRIES``    3             3                Maximum download retry attempts
    ``CONFIG_EL2GO_OTA_ADV_REPORT_MAX_RETRIES``      3             5                Maximum status-report retry attempts
    ================================================ ============= ================ ================================================

    The sample values in :file:`prj.conf` are chosen for demonstration and testing; increase them for a real deployment
    (or remove them from the prj.conf to fall back to the Kconfig defaults).

6.  [Optional] Adjust the blackout/defer policy and SNTP time-sync settings:

    ``CONFIG_EL2GO_OTA_ADV_BLACKOUT_START_HOUR`` / ``CONFIG_EL2GO_OTA_ADV_BLACKOUT_END_HOUR`` -
    UTC hour window during which updates are deferred (default ``0``/``0``, disabled; the window wraps midnight if END < START,
    e.g. 22-4 = 22:00 to 04:00)
    ``CONFIG_EL2GO_OTA_ADV_DEFER_WINDOW_S`` - minimum seconds between update attempts (default 100, 0 = disabled)
    ``CONFIG_EL2GO_OTA_ADV_TIME_SYNC_MAX_CYCLES`` / ``CONFIG_EL2GO_OTA_ADV_TIME_SYNC_RETRY_DELAY_MS`` -
    SNTP sync retry budget at boot (default 10 cycles, 5000 ms apart) before the agent proceeds without a valid time
    ``CONFIG_EL2GO_TIME_SNTP_SERVER`` - SNTP server hostname (default ``pool.ntp.org``)

    If no valid time is available, the agent proceeds with degraded certificate validity checks and the blackout
    policy is not applied.

7.  [Optional] Adjust the diagnostics:

    ``CONFIG_EL2GO_OTA_DIAG_DUMP_ON_BOOT=y`` - replay the diagnostics log persisted in ``log_partition`` (previous session)
    to the console at boot (default ``n``)
    ``CONFIG_EL2GO_OTA_DIAG_MIN_LEVEL`` - minimum level of the messages persisted to the ring buffer (default 0, all)
    ``CONFIG_EL2GO_LIB_LOG_LEVEL`` - verbosity of the EL2GO library logs
    (0 = off, 1 = error (sample default), 2 = info, 3 = debug, 4 = verbose, 5 = extra)

8.  Build the application. This sample uses sysbuild to build and sign the application image
    together with MCUboot; the signing key is the default sysbuild/MCUboot RSA-2048 test key
    (``root-rsa-2048.pem``, set with ``SB_CONFIG_BOOT_SIGNATURE_KEY_FILE`` in :file:`sysbuild.conf`).
    For production use, replace this key before deployment. The MCUboot options, including the security counter
    based downgrade prevention, are described in :ref:`el2go_ota_agent_advanced_mcuboot`.

9.  Connect the USB-C (FRDM-RW612) or Micro-USB (RD-RW612-BGA) cable to the PC host and the MCU-Link USB port
    (J10 [FRDM-RW612] or J7 [RD-RW612-BGA]) on the board.

10. Open a serial terminal with the following settings:

    - 115200 baud rate
    - 8 data bits
    - No parity
    - One stop bit
    - No flow control

11. Flash the application to the board using west flash command.

12. Prepare an update image: increase the version in
    :zephyr_file:`modules/lib/nxp_iot_agent/zephyr/samples/el2go_ota_agent_advanced/VERSION` (e.g. ``VERSION_MINOR = 2``)
    and the security counter in :file:`prj.conf` (e.g. ``CONFIG_MCUBOOT_EXTRA_IMGTOOL_ARGS="--security-counter 3"``,
    see :ref:`el2go_ota_agent_advanced_mcuboot`), rebuild, and upload the
    signed application image (``build/el2go_ota_agent_advanced/zephyr/zephyr.signed.bin``) to the OTA campaign.
    The image must be signed with the same key.

13. On the next scheduled check after the OTA campaign carrying the newer firmware version becomes available, the device will
    automatically download and apply the update, reboot via MCUboot, and confirm the new image. If
    the device loses power or network connectivity mid-update, the persisted agent state ensures
    the correct outcome (resume, report failure, or roll back) is reconciled on the next boot.

Building, Flashing and Running
*******************************

.. zephyr-app-commands::
   :zephyr-app: modules/lib/nxp_iot_agent/zephyr/samples/el2go_ota_agent_advanced
   :board: <board>
   :goals: build flash
   :west-args: --sysbuild
   :compact:

For example:

.. code-block:: console

   west build --sysbuild -b frdm_rw612 modules/lib/nxp_iot_agent/zephyr/samples/el2go_ota_agent_advanced -- \
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
    [0003s] [INFO] ==== OTA AGENT ADVANCED SAMPLE ====
    [0003s] [INFO] 1.1.0
    [0003s] [DONE] fwual_init()
    [0003s] [INFO] fwual state: 0
    [0003s] [DONE] fwual_get_caps()
    [0019s] [DONE] el2go_app_net_init()
    [0019s] [DONE] el2go_ota_init()

    --- Connect (mTLS) ---
    [0020s] [DONE] el2go_ota_connect()
    [0020s] [INFO] connected to my-ota-server.example.com:443
    [0020s] [INFO] starting scheduler (base interval: 10 s)

    --- Check for updates ---
    [0020s] [INFO] checking for updates...
    [0020s] [DONE] el2go_ota_check_for_updates()
    [0020s] [INFO] update available: id=... packages=1

    --- Download, finalize, verify, activate ---
    [0038s] [INFO] downloading image 0 (1421936 bytes)
    [0065s] [DONE] el2go_ota_download_package()
    [0065s] [DONE] fwual_finalize_image()
    [0067s] [DONE] fwual_verify_image()
    [0067s] [DONE] fwual_commit_session()
    [0067s] [DONE] fwual_activate()
    [0067s] [DONE] fwual_close_session()
    [0067s] [INFO] download and handoff complete
    [0067s] [DONE] el2go_ota_schedule_status_report()
    [0067s] [INFO] activating update...

    --- Reboot, MCUboot swap, confirm ---
    [0067s] MCUBOOT I: Starting swap using move algorithm.
    [0148s] MCUBOOT I: Image version: v1.2.0
    [0153s] *** Booting Zephyr OS build 95926e7bf4b8 ***
    [0153s] [INFO] ==== OTA AGENT ADVANCED SAMPLE ====
    [0153s] [INFO] 1.2.0
    [0153s] [INFO] fwual state: 5
    [0167s] [DONE] el2go_ota_connect()
    [0167s] [INFO] new firmware validated - confirming image
    [0167s] [DONE] fwual_confirm()
    [0167s] [DONE] el2go_ota_report_pending_status()
    [0167s] [INFO] checking for updates...
    [0167s] [DONE] el2go_ota_check_for_updates()
    [0167s] [INFO] no update available - staying idle

When the blackout or defer policy postpones an update, ``OTA policy: BLACKOUT (...)`` or ``OTA policy: DEFER (...)``
is printed; after a failed check, ``scheduler backoff: next check in <n> s`` is printed.
