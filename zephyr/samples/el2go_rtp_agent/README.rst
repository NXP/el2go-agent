.. _el2go_rtp_agent:

EL2GO RTP Agent Application
###########################

Overview
********

This sample application shows how to use the EdgeLock 2GO service to provisioning keys and certificates to an MCU device.
Those keys and certificates can then be used to establish mutual-authenticated TLS connections to cloud services such as AWS or Azure.

The application can be built in two variants, selected by the board target:

- Trusted Firmware-M (TF-M) variant (``frdm_rw612/rw612/ns`` or ``rd_rw612_bga/rw612/ns``): the application is based on the
  TF-M project which allows the execution in a Trusted Execution Environment. The example is split in two parts: TF-M core and
  RootOfTrust services are running in Secure Processing Environment (SPE), while the application itself is running in
  Non-secure Processing Environment (NSPE). The settings are taken from :file:`boards/<board>_rw612_ns.conf` and
  :file:`boards/<board>_rw612_ns.overlay`.
- Non-TF-M variant (``frdm_rw612`` or ``rd_rw612_bga``): PSA Crypto is provided by mbedTLS with the ELS PKC driver and PSA ITS
  is backed by the Zephyr Secure Storage subsystem (ZMS) on the ``its_partition`` declared in
  :file:`boards/<board>_rw612.overlay`. The settings are taken from :file:`boards/<board>_rw612.conf`. Partition address,
  size and ITS settings are described in the EL2GO OTA Agent Core sample (:ref:`el2go_ota_agent_core_its`).

Unless stated otherwise, the steps below apply to both variants; steps marked [TF-M] are only relevant for the
``/ns`` board targets.

.. _el2go_rtp_agent_its_isolation:

.. note::

   In the non-TF-M variant, PSA ITS (Zephyr Secure Storage) does not offer runtime protection like TF-M does: there is
   no isolated Secure Processing Environment, so the ITS content is accessible to any code running on the device.
   It is therefore recommended to use only S50-internal keys, i.e. keys which are stored and used inside the ELS (S50)
   and never leave it in plain form.

It supports two modes for registering a device at the EdgeLock 2GO service:

- UUID registration (default): At startup, the demo prints the UUID which can be used for manual registration (whitelisting)
  of the device in a device group
- Claiming: The EL2GO Claimcode Encryption sample (:ref:`el2go_claimcode_encryption`) must be run before, which will store
  a claim code blob in the flash memory. The EL2GO RTP Agent sample will present the claim code to the EdgeLock 2GO service
  and automatically register the device.

The objects provisioned by this sample are stored in PSA storage (in the non-TF-M variant, the ``its_partition``).
The EL2GO OTA agent samples (:ref:`el2go_ota_agent_core`, :ref:`el2go_ota_agent_advanced`) read their mTLS client
key and certificate from there; see :ref:`el2go_ota_agent_core_its`.

The agent initializes the network once and then runs the provisioning sequence in a loop, started from an OSAL thread
(``osal_start_task``). After each iteration it waits ``AGENT_LOOP_DELAY_MS`` (2 s, defined in
:zephyr_file:`modules/lib/nxp_iot_agent/applications/el2go_rtp_agent/inc/el2go_rtp_agent_config.h`), so the log line
``Start`` repeats while the network initialization and its ``DEVICE_INIT_TIME`` are printed only once. The stack size of
this thread is set with ``CONFIG_OSAL_TASK_STACK_SIZE`` (default 32768, defined in
:zephyr_file:`modules/lib/nxp_iot_agent/zephyr/Kconfig`). Lowering it below the default can cause a silent stack
overflow (USAGE FAULT) without any console output.

After provisioning, the agent can optionally verify the provisioned credentials by connecting to AWS and/or Azure over
MQTT (see step 4 below).

The device on which the example is run must have secure boot enabled, otherwise the blob verification and
decryption keys can't be derived.

The TF-M variant supports both BL2 enabled and BL2 disabled bootloader modes. More information can be found in the BL2-related
section below or in the TF-M documentation at the following link
(https://trustedfirmware-m.readthedocs.io/en/latest/design_docs/booting/tfm_secure_boot.html).

The source code for this application can be found at:
:zephyr_file:`modules/lib/nxp_iot_agent/applications/el2go_rtp_agent/src/el2go_rtp_agent_demo.c`.

Requirements
************

- FRDM-RW612 or RD-RW612-BGA board
- USB-C (FRDM-RW612) or Micro-USB (RD-RW612-BGA) cable
- Personal Computer
- Wi-Fi access point with internet access

Prerequisites
*************

- Active EdgeLock 2GO account (https://www.nxp.com/products/security-and-authentication/secure-service-2go-platform/edgelock-2go:EDGELOCK-2GO)
- Any serial communicator

Setup of the EdgeLock 2GO platform
**********************************

The documentation which explains how to setup the EdgeLock 2GO Account to

- Create a device group and whitelist the device UUID
- Create and copy a claim code for the device group
- Create secure objects
- Assign the secure objects to the device group

can be found on the Edgelock 2GO web interface under the "Documentation" tab.

Prepare the Demo
****************

The configuration options below are Kconfig symbols. Values set in :file:`prj.conf` (or passed with ``-D<SYMBOL>=<value>``
on the ``west build`` command line) take precedence over the fallback ``#define`` values in the C sources.

1.  Provide the EdgeLock 2GO URL for the account (can be found in the "Admin" section). This step is mandatory;
    the hostname is empty by default and provisioning fails without it:

    in :zephyr_file:`modules/lib/nxp_iot_agent/zephyr/samples/el2go_rtp_agent/prj.conf`
    ``CONFIG_EL2GO_RTP_EDGELOCK2GO_HOSTNAME="YOUR_HOSTNAME"``
    ``CONFIG_EL2GO_RTP_EDGELOCK2GO_PORT=443``

    If ``CONFIG_EL2GO_RTP_EDGELOCK2GO_HOSTNAME`` is left empty in the prj.conf, the value can be set as environment variable
    using the same name CONFIG_EL2GO_RTP_EDGELOCK2GO_HOSTNAME; the value in prj.conf has most precedence.
    The fallback define ``EL2GO_RTP_EDGELOCK2GO_HOSTNAME`` in
    :zephyr_file:`modules/lib/nxp_iot_agent/include/rtp/el2go_rtp_config.h` is only used for non-Zephyr builds.

2.  Provide the Wi-Fi access point credentials:

    in :zephyr_file:`modules/lib/nxp_iot_agent/zephyr/samples/el2go_rtp_agent/prj.conf`
    ``CONFIG_EL2GO_NET_WIFI_SSID=""``
    ``CONFIG_EL2GO_NET_WIFI_PSK=""``

    If these are set in the prj.conf, then they will override the value of the defines
    in :zephyr_file:`modules/lib/nxp_iot_agent/applications/common/network/zephyr/wifi/el2go_app_net_wifi.c`
    (``#define EL2GO_NET_WIFI_SSID "WIFI SSID"`` and ``#define EL2GO_NET_WIFI_PSK "WIFI Password"``).
    Furthermore, if the prj.conf values are left empty, these values can be set as environment variables using the same
    names CONFIG_EL2GO_NET_WIFI_SSID and CONFIG_EL2GO_NET_WIFI_PSK; the values in prj.conf have most precedence.

3.  [Optional] In case you want to use the "Claiming" registration method, enable claim code injection in the prj.conf:

    ``CONFIG_EL2GO_RTP_CLAIMCODE_INJECT=y``

    This option compiles the flash claim code import into the keystore and maps to
    ``EL2GO_RTP_CLAIMCODE_INJECT_ENABLED`` in
    :zephyr_file:`modules/lib/nxp_iot_agent/applications/el2go_rtp_agent/inc/el2go_rtp_agent_config.h`;
    changing the define directly has no effect.

    The flash address where the claim code is read from is set to 0x088A0000 by default.
    The location can be changed with the following option (make sure to keep it aligned with
    ``CONFIG_CLAIM_CODE_INFO_ADDRESS`` configured in the EL2GO Claimcode Encryption sample):

    ``CONFIG_EL2GO_RTP_CLAIMCODE_FLASH_ADDRESS=0x088A0000``

    The claim code blob must not be erased when flashing this application. After a successful import, the console shows
    ``Claimcode imported into psa its with object id 0x...``.

4.  [Optional] In case you want to use provisioned ECC key pairs and corresponding X.509 certificates
    to execute TLS mutual-authentication and MQTT message exchange with AWS and/or Azure clouds after provisioning,
    enable the MQTT verification in the prj.conf:

    ``CONFIG_EL2GO_RTP_MQTT_VERIFY=y``
    ``CONFIG_EL2GO_RTP_MQTT_$SERVER$=y``

    In addition, the following options should be set to the object ID as defined at EdgeLock 2GO service:

    ``CONFIG_EL2GO_RTP_MQTT_$SERVER$_KEY_ID=0x00004000``
    ``CONFIG_EL2GO_RTP_MQTT_$SERVER$_CERT_ID=0x00004001``

    where ``$SERVER$`` is ``AWS`` or ``AZURE``. These options map to ``AWS_ENABLE``/``AZURE_ENABLE``,
    ``$SERVER$_SERVICE_KEY_PAIR_ID`` and ``$SERVER$_SERVICE_DEVICE_CERT_ID`` in
    :zephyr_file:`modules/lib/nxp_iot_agent/applications/common/mqtt/el2go_mqtt_config.h`.

    By default, MQTT verification is disabled. Two ready-made overlays enable it for both clouds, with the object IDs
    ``0x00004000``/``0x00004001`` (AWS) and ``0x00004100``/``0x00004101`` (Azure):

    - :file:`overlay-el2go-whitelisting-mqtt-rw61x.conf`: UUID registration + MQTT verification
    - :file:`overlay-el2go-claimcode-mqtt-rw61x.conf`: claim code injection + MQTT verification

    Use them with ``-DOVERLAY_CONFIG=<overlay>``; comment out ``CONFIG_EL2GO_RTP_MQTT_AWS`` or ``CONFIG_EL2GO_RTP_MQTT_AZURE``
    in the overlay to disable one of the clouds.

    The other server dependent macros (``AWS_HOSTNAME``, ``AZURE_ID_SCOPE``, ``AZURE_GLOBAL_DEVICE_ENDPOINT`` and the root CA
    certificates) are set in :zephyr_file:`modules/lib/nxp_iot_agent/applications/common/mqtt/el2go_mqtt_config.h`;
    their meaning can be found in the AWS/Azure documentation.

    When creating the secure objects on EdgeLock 2GO, Custom policies should be chosen.
    Additionally for the ECC key pair following options should be selected:

    - Device Lifecycle should match the lifecycle of the device on which the application will run
    - Permitted algorithm should be set to ECDSA SHA 256
    - SIGN HASH usage should be selected

    For the X.509 certificate following options should be selected:

    - Device Lifecycle should match the lifecycle of the device on which the application will run
    - EXPORT usage should be selected

5.  [Optional] Adjust the logging:

    - ``CONFIG_EL2GO_LIB_LOG_LEVEL``: verbosity of the EL2GO library logs
      (0 = off, 1 = error, 2 = info (sample default), 3 = debug, 4 = verbose, 5 = extra)
    - ``CONFIG_EL2GO_RTP_ENABLE_DEBUG`` / ``CONFIG_EL2GO_RTP_ENABLE_TRACE``: additional application debug/trace output
    - ``CONFIG_EL2GO_TIME_MEASUREMENT``: performance timing output (enabled by default)
    - ``CONFIG_EL2GO_MBEDTLS_DEBUG_ENABLE``: mbedTLS internal debug output

6.  [Optional] In order to maximize the ITS performance, the maximum supported blob size is limited.

    [TF-M] The maximum supported blob size is set to 2908 bytes. In case you want to support bigger blobs
    (8K is the maximum size supported by PSA), you need to change the following three variables:

    in :zephyr_file:`modules/tee/tf-m/trusted-firmware-m/platform/ext/target/nxp/<board>/config_tfm_target.h`
    ``#define CRYPTO_ENGINE_BUF_SIZE 0x8000``
    ``#define ITS_MAX_ASSET_SIZE     3 * 0xC00``

    in :zephyr_file:`modules/tee/tf-m/trusted-firmware-m/platform/ext/target/nxp/<board>/partition/flash_layout.h`
    ``#define TFM_HAL_ITS_SECTORS_PER_BLOCK (3)``

    [Non-TF-M only] The maximum ITS entry size is set in :file:`boards/<board>_rw612.conf`
    (``CONFIG_SECURE_STORAGE_ITS_MAX_DATA_SIZE``); keep it identical in the applications that share the
    ``its_partition`` (see :ref:`el2go_ota_agent_core_its`).

7.  [Optional] [TF-M] EdgeLock 2GO applications support two boot modes:

    - BL2 enabled (default): The ROM bootloader first jumps to the BL2 image, which authenticates the signed SPE and NSPE images
    - BL2 disabled: The ROM bootloader jumps directly to the SPE image

    To select the BL2 disabled mode, additional configuration options must be passed to the command line when building the application:

    - CONFIG_TFM_BL2: Indicates whether the BL2 build is enabled or disabled; should be set to 'n'
    - CONFIG_FLASH_BASE_ADDRESS: Must point to the address where the NSPE starts. For BL2 disabled, this should be set to 0x080A0000
    - DTC_OVERLAY_FILE: Should point to the board-specific ``_ns`` overlay file provided in the nxp_iot_agent repository

    For example for the rd_rw612_bga board, use the following arguments:
    ``-DCONFIG_TFM_BL2=n -DCONFIG_FLASH_BASE_ADDRESS=0x080A0000 -DDTC_OVERLAY_FILE="boards/rd_rw612_bga_rw612_ns.overlay"``

    For the frdm_rw612 board, use ``boards/frdm_rw612_rw612_ns.overlay`` instead.

8.  To properly derive die-individual encryption and authentication keys used for provisioning of EdgeLock 2GO Secure Objects,
    the secure boot mode should be enabled and the hash of the OEM FW Authentication key (RKTH) loaded in the One Time Programming (OTP) fuses
    of the device. The enablement of secure boot requires the application image downloaded to the chip to be signed with the OEM FW Authentication key.
    Additionaly, if the example is supposed to run in the OEM CLOSED life cycle (typical for production SW),
    the image needs to be encrypted with the OEM FW encryption key and loaded as an Secure Binary container (SB3.1).
    Details on how to enable secure boot, sign and encrypt the image, deal with different lifecycles are included
    in the Application note AN13813 "Secure boot on RW61x", downloadable from
    https://www.nxp.com/products/wireless-connectivity/wi-fi-plus-bluetooth-plus-802-15-4/wireless-mcu-with-integrated-tri-radio-1x1-wi-fi-6-plus-bluetooth-low-energy-5-3-802-15-4:RW612
    in the "Secure Files" section.

    [TF-M] Zephyr build process supports automated signing and merging of images which will allow the example to run on secure boot enabled sample
    in OEM OPEN lifecycle; encryption and SB3.1 container creation are not covered. As already described in the introduction,
    the example is split in SPE and NSPE images, for this reason some extra steps needs to be done to create the image which can run on the device:

    1. The bootheader needs to be removed from the SPE image
    2. The resulting image from first step has to be merged with the NSPE image
    3. The resulting image from step 2 must be signed with the OEM FW authentication key

    The automated signing and merging process requires SPSDK to be installed and configured on the host PC (SPSDK documentation:
    https://spsdk.readthedocs.io/en/1.6.1/usage/installation.html). After the SPSDK is successfully installed and the path to its executable correctly set
    under the PATH environmental variable, some configuration variables needs to be set for automated signing and merging enablement:

    - CONFIG_EL2GO_SIGN_USING_NXPIMAGE: should be enabled (set to y), it will enable automated signing and merging
    - CONFIG_EL2GO_PRIVATE_KEY: this should include the path to the PEM file including the OEM FW authentication key
    - CONFIG_EL2GO_CERT_BLOCK: this should include the path to YAML file which in turns points to the corresponding OEM FW authentication key certificate PEM files.
      The YAML file can be created using SPSDK command described under: https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html#nxpimage-cert-block-get-template.
      From the created template all the fields can be deleted, except:

      - family: leave the value defined in template
      - useIsk: should be set to false
      - signPrivateKey: path to the PEM file including the OEM FW authentication key (same file as defined in CONFIG_EL2GO_PRIVATE_KEY)
      - rootCertificateXFile: 4 variables with X ranging from 0 to 3 which should include path to the 4 PEM certificates corresponding OEM FW authentication key

    For more details about the keys/certificates described in the readme, always refer to the Application Note AN13813 "Secure boot on RW61x".
    There are 2 ways to define the variables and allow Zephyr build command to automatically merge and sign the image:

    1. In prj.conf file:
       ``CONFIG_EL2GO_SIGN_USING_NXPIMAGE=y``
       ``CONFIG_EL2GO_PRIVATE_KEY="PATH_TO_YOUR_KEY_PEM_FILE"``
       ``CONFIG_EL2GO_CERT_BLOCK="PATH_TO_YOUR_CERTIFICATE_YML_FILE"``
    2. If not set in prj.conf file, then set as environment variable using the same names:
       CONFIG_EL2GO_PRIVATE_KEY, CONFIG_EL2GO_CERT_BLOCK, CONFIG_EL2GO_SIGN_USING_NXPIMAGE.
       Please set them to same value as you would in prj.conf file.

    In case both are set, the variables in the prj.conf will take precedence.
    The automated signing is only performed for the ``frdm_rw612/rw612/ns`` and ``rd_rw612_bga/rw612/ns`` board targets.

    The automated image signing process supports both BL2 enabled and BL2 disabled modes.
    When BL2 is enabled, the signature is calculated and appended by the SPSDK image tool to the merged image, which includes the BL2, SPE, and NSPE images.
    When BL2 is disabled, only the SPE and NSPE images are merged before the signature is computed and appended.

9.  Build the application.

10. Connect the USB-C (FRDM-RW612) or Micro-USB (RD-RW612-BGA) cable to the PC host and the MCU-Link USB port
    (J10 [FRDM-RW612] or J7 [RD-RW612-BGA]) on the board.

11. Open a serial terminal with the following settings:

    - 115200 baud rate
    - 8 data bits
    - No parity
    - One stop bit
    - No flow control

12. Flash the application to the board: as explained in the section 8, in typical production use case the example is encrypted
    in a SB3.1 container. Follow the Application note AN13813 "Secure boot on RW61x" to check how to download the container to the device.

    In case the example is running on a device in OEM OPEN lifecycle the merged and signed image can be downloaded with the west flash command through JLink.
    An alternative is the usage of the SPSDK blhost application which is documented under https://spsdk.readthedocs.io/en/stable/examples/blhost/blhost.html.

Building, Flashing and Running
******************************

.. zephyr-app-commands::
   :zephyr-app: modules/lib/nxp_iot_agent/zephyr/samples/el2go_rtp_agent
   :board: <board>
   :goals: build flash
   :compact:

For example, to build the TF-M variant for the FRDM-RW612 board with claim code injection and MQTT verification:

.. code-block:: console

   west build -b frdm_rw612/rw612/ns modules/lib/nxp_iot_agent/zephyr/samples/el2go_rtp_agent -- \
       -DOVERLAY_CONFIG=overlay-el2go-claimcode-mqtt-rw61x.conf \
       -DCONFIG_EL2GO_RTP_EDGELOCK2GO_HOSTNAME=\"<company>.device-link.edgelock2go.com\" \
       -DCONFIG_EL2GO_NET_WIFI_SSID=\"my_ssid\" -DCONFIG_EL2GO_NET_WIFI_PSK=\"my_password\"

For the non-TF-M variant, use ``-b frdm_rw612`` (or ``-b rd_rw612_bga``).

Sample Output
=============

TF-M variant, UUID registration without MQTT verification:

.. code-block:: console

    Booting TF-M v2.1.0
    [WRN] This device was provisioned with dummy keys. This device is NOT SECURE
    [Sec Thread] Secure image initializing!
    [INF][PS] Encryption alg: 0x5500200
    [INF][Crypto] Provision entropy seed...
    [INF][Crypto] Provision entropy seed... complete.
    Wi-Fi cau temperature : 27
    MAC Address: MY_MAC_ADDRESS
    PKG_TYPE: BGA
    Set BGA tx power table data
    *** Booting Zephyr OS build b9f5bf039849 ***
    Connecting to SSID 'WIFI SSID' ...
    PKG_TYPE: BGA
    Set BGA tx power table data
    Using WIFI 4 (802.11n/HT) @ 2.4GHz (Channel 6, -66 dBm)
    Using IPv4 address 172.20.10.4 @ Gateway 172.20.10.1 (DHCP)
    Successfully connected to WIFI
    Performance timing: DEVICE_INIT_TIME : 11950ms
    Start
    UID in hex format: MY_UUID
    UID in decimal format: MY_DECIMAL_UUID
    Updating device configuration from [MY_EL2GO_ID.device-link.staging.edgelock2go.com]:[443].
    Update status report:
      The device update was successful (0x0001: SUCCESS)
      The correlation-id for this update is 80c501f1-c13d-4eb5-8229-45e55f014c39.
      Status for remote trust provisioning: 0x0001: SUCCESS.
        On endpoint 0x70000010, for object 0x00004000, status: 0x0002: SUCCESS_NO_CHANGE.
        On endpoint 0x70000010, for object 0x00004001, status: 0x0002: SUCCESS_NO_CHANGE.
        On endpoint 0x70000010, for object 0x00004100, status: 0x0002: SUCCESS_NO_CHANGE.
        On endpoint 0x70000010, for object 0x00004101, status: 0x0002: SUCCESS_NO_CHANGE.
    Performance timing: ENTIRE_SESSION_TIME : 3872ms
            Performance timing: AGENT_INIT_TIME : 124ms
            Performance timing: TLS_PREP_TIME : 126ms
            Performance timing: NETWORK_CONNECT_TIME : 1305ms
            Performance timing: PROCESS_PROVISION_TIME : 2260ms
            CRL_TIME : [56ms] and COMMAND_TXRX_TIME : [0ms] included in PROCESS_PROVISION_TIME

On the first provisioning run, objects are reported with ``0x0001: SUCCESS`` instead of ``0x0002: SUCCESS_NO_CHANGE``.
With claim code injection enabled, ``Claimcode imported into psa its with object id 0x...`` and
``Performance timing: CLAIMCODE_INJECT_TIME`` are printed before the provisioning. With MQTT verification enabled, the
provisioning output is followed by the AWS/Azure connection output shown in the EL2GO MQTT Demo sample (:ref:`el2go_mqtt_demo`).
In the non-TF-M variant the TF-M boot messages are not printed.

The output above shows one iteration. After it, the agent waits ``AGENT_LOOP_DELAY_MS`` and starts the next iteration,
which prints ``Start`` again and repeats the provisioning output; the network initialization lines and
``DEVICE_INIT_TIME`` are not repeated.
