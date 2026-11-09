.. _el2go_mqtt_demo:

EL2GO MQTT Demo
###############

Overview
********

This sample application shows how to use MQTT connections to cloud services such as AWS or Azure with preprovisioned keys
and certificates from the EdgeLock 2GO service.

The application can be built in two variants, selected by the board target:

- Trusted Firmware-M (TF-M) variant (``frdm_rw612/rw612/ns`` or ``rd_rw612_bga/rw612/ns``): the application is based on the
  TF-M project which allows the execution in a Trusted Execution Environment. The example is split in two parts: TF-M core and
  RootOfTrust services are running in Secure Processing Environment (SPE), while the application itself is running in
  Non-secure Processing Environment (NSPE). The settings are taken from :file:`boards/<board>_rw612_ns.conf`.
- Non-TF-M variant (``frdm_rw612`` or ``rd_rw612_bga``): PSA Crypto is provided by mbedTLS with the ELS PKC driver and PSA ITS
  is backed by the Zephyr Secure Storage subsystem (ZMS) on the ``its_partition`` declared in
  :file:`boards/<board>_rw612.overlay`. The settings are taken from :file:`boards/<board>_rw612.conf`.

Unless stated otherwise, the steps below apply to both variants; steps marked [TF-M] are only relevant for the
``/ns`` board targets. The keys and certificates must have been provisioned with the same variant, since the two
variants use different ITS storage backends.

.. note::

   In the non-TF-M variant, PSA ITS (Zephyr Secure Storage) does not offer runtime protection like TF-M does: there is
   no isolated Secure Processing Environment, so the ITS content is accessible to any code running on the device.
   It is therefore recommended to use only S50-internal keys, i.e. keys which are stored and used inside the ELS (S50)
   and never leave it in plain form.

The device on which the example is run must have secure boot enabled, otherwise the blob verification and
decryption keys can't be derived.

The TF-M variant supports both BL2 enabled and BL2 disabled bootloader modes. More information can be found in the BL2-related
section below or in the TF-M documentation at the following link
(https://trustedfirmware-m.readthedocs.io/en/latest/design_docs/booting/tfm_secure_boot.html).

The source code for this application can be found at:
:zephyr_file:`modules/lib/nxp_iot_agent/applications/el2go_mqtt_demo/src/el2go_mqtt_client.c`.
The MQTT connection logic shared with the EL2GO RTP Agent sample is located in
:zephyr_file:`modules/lib/nxp_iot_agent/applications/common/mqtt`.

Requirements
************

- FRDM-RW612 or RD-RW612-BGA board
- USB-C (FRDM-RW612) or Micro-USB (RD-RW612-BGA) cable
- Personal Computer
- Wi-Fi access point with internet access

Prerequisites
*************

- Any serial communicator
- EdgeLock 2GO keypairs and certificates for AWS and/or Azure already imported to the device (ITS).
  This can be achieved via offline provisioning (with the el2go_import_blob sample, see :ref:`el2go_import_blob`) or via online
  provisioning (with the el2go_rtp_agent sample, see :ref:`el2go_rtp_agent`). Please refer to their respective readmes on
  how to perform the provisioning and import.
- An AWS IoT Core endpoint and/or an Azure IoT Hub Device Provisioning Service (DPS) instance, configured to accept the
  device certificates provisioned by EdgeLock 2GO.

ATTENTION: It is important not to erase the ITS part of the flash when flashing this application,
as this is where the EdgeLock 2GO objects are stored:

- [TF-M] 0x083C0000 to 0x083E0000
- [Non-TF-M only] 0x08840000 to 0x08860000 (``its_partition`` in :file:`boards/<board>_rw612.overlay`)

Prepare the Demo
****************

1.  Provide the EdgeLock 2GO object IDs of the keys and certificates already imported to the device. These are Kconfig
    options which can be set in the prj.conf (the AWS and Azure connections are both enabled by default in this sample):

    ``CONFIG_EL2GO_RTP_MQTT_AWS=y``
    ``CONFIG_EL2GO_RTP_MQTT_AWS_KEY_ID=0x00004000``
    ``CONFIG_EL2GO_RTP_MQTT_AWS_CERT_ID=0x00004001``
    ``CONFIG_EL2GO_RTP_MQTT_AZURE=y``
    ``CONFIG_EL2GO_RTP_MQTT_AZURE_KEY_ID=0x00004100``
    ``CONFIG_EL2GO_RTP_MQTT_AZURE_CERT_ID=0x00004101``

    Set ``CONFIG_EL2GO_RTP_MQTT_AWS=n`` or ``CONFIG_EL2GO_RTP_MQTT_AZURE=n`` to disable the respective connection.
    If the key and certificate IDs are not set, the Kconfig defaults (``0x83000101``/``0x83000102`` for AWS,
    ``0x83000211``/``0x83000212`` for Azure) are used. The IDs shown above are the ones set by the
    :file:`overlay-el2go-rw61x.conf` overlay used by the Twister tests.

    Optionally, the MQTT client ID (AWS) and the DPS registration ID (Azure) can be set explicitly; if left empty
    (default), they are derived from the Common Name of the device leaf certificate:

    ``CONFIG_EL2GO_RTP_MQTT_AWS_CLIENT_ID=""``
    ``CONFIG_EL2GO_RTP_MQTT_AZURE_REGISTRATION_ID=""``

    When creating the secure objects on EdgeLock 2GO, Custom policies should be chosen.
    Additionally for the ECC key pair following options should be selected:

    - Device Lifecycle should match the lifecycle of the device on which the application will run
    - Permitted algorithm should be set to ECDSA SHA 256
    - SIGN HASH usage should be selected

    For the X.509 certificate following options should be selected:

    - Device Lifecycle should match the lifecycle of the device on which the application will run
    - EXPORT usage should be selected

2.  Provide the AWS and/or Azure connection parameters:

    in :zephyr_file:`modules/lib/nxp_iot_agent/applications/common/mqtt/el2go_mqtt_config.h`
    ``#define AWS_HOSTNAME`` - AWS IoT Core endpoint of your account
    ``#define AZURE_ID_SCOPE`` - ID scope of your Azure DPS instance
    ``#define AZURE_GLOBAL_DEVICE_ENDPOINT`` - Azure DPS global endpoint

    The same file also contains the root CA certificates used to verify the AWS (``AWS_ROOT_SERVER_CERT``) and
    Azure (``AZURE_ROOT_SERVER_CERT``) servers. The settings of these macros are server dependent and their meaning
    can be found in the AWS/Azure documentation.

3.  Provide the Wi-Fi access point credentials:

    in :zephyr_file:`modules/lib/nxp_iot_agent/zephyr/samples/el2go_mqtt_demo/prj.conf`
    ``CONFIG_EL2GO_NET_WIFI_SSID=""``
    ``CONFIG_EL2GO_NET_WIFI_PSK=""``

    If these are set in the prj.conf, then they will override the value of the defines
    in :zephyr_file:`modules/lib/nxp_iot_agent/applications/common/network/zephyr/wifi/el2go_app_net_wifi.c`
    (``#define EL2GO_NET_WIFI_SSID "WIFI SSID"`` and ``#define EL2GO_NET_WIFI_PSK "WIFI Password"``).
    Furthermore, if the prj.conf values are left empty, these values can be set as environment variables using the same
    names CONFIG_EL2GO_NET_WIFI_SSID and CONFIG_EL2GO_NET_WIFI_PSK; the values in prj.conf have most precedence.

4.  [Optional] The verbosity of the EL2GO library logs is controlled by ``CONFIG_EL2GO_LIB_LOG_LEVEL``
    (0 = off, 1 = error, 2 = info (sample default), 3 = debug, 4 = verbose, 5 = extra).
    mbedTLS internal debug output can additionally be enabled with ``CONFIG_EL2GO_MBEDTLS_DEBUG_ENABLE=y``.

5.  [Optional] [TF-M] EdgeLock 2GO applications support two boot modes:

    - BL2 enabled (default): The ROM bootloader first jumps to the BL2 image, which authenticates the signed SPE and NSPE images
    - BL2 disabled: The ROM bootloader jumps directly to the SPE image

    To select the BL2 disabled mode, additional configuration options must be passed to the command line when building the application:

    - CONFIG_TFM_BL2: Indicates whether the BL2 build is enabled or disabled; should be set to 'n'
    - CONFIG_FLASH_BASE_ADDRESS: Must point to the address where the NSPE starts. For BL2 disabled, this should be set to 0x080A0000
    - DTC_OVERLAY_FILE: Should point to a board-specific ``_ns`` overlay file which places the NSPE image at 0x000A0000

    This sample does not provide its own ``_ns`` overlay; the overlay of the EL2GO RTP Agent sample can be reused.
    For example for the rd_rw612_bga board, use the following arguments:
    ``-DCONFIG_TFM_BL2=n -DCONFIG_FLASH_BASE_ADDRESS=0x080A0000 -DDTC_OVERLAY_FILE="<path_to_nxp_iot_agent>/zephyr/samples/el2go_rtp_agent/boards/rd_rw612_bga_rw612_ns.overlay"``

    For the frdm_rw612 board, use ``frdm_rw612_rw612_ns.overlay`` instead.

6.  To properly derive die-individual encryption and authentication keys used for provisioning of EdgeLock 2GO Secure Objects,
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

7.  Build the application.

8.  Connect the USB-C (FRDM-RW612) or Micro-USB (RD-RW612-BGA) cable to the PC host and the MCU-Link USB port
    (J10 [FRDM-RW612] or J7 [RD-RW612-BGA]) on the board.

9.  Open a serial terminal with the following settings:

    - 115200 baud rate
    - 8 data bits
    - No parity
    - One stop bit
    - No flow control

10. Flash the application to the board: as explained in the section 6, in typical production use case the example is encrypted
    in a SB3.1 container. Follow the Application note AN13813 "Secure boot on RW61x" to check how to download the container to the device.

    In case the example is running on a device in OEM OPEN lifecycle the merged and signed image can be downloaded with the west flash command through JLink.
    An alternative is the usage of the SPSDK blhost application which is documented under https://spsdk.readthedocs.io/en/stable/examples/blhost/blhost.html.

Building, Flashing and Running
******************************

.. zephyr-app-commands::
   :zephyr-app: modules/lib/nxp_iot_agent/zephyr/samples/el2go_mqtt_demo
   :board: <board>
   :goals: build flash
   :compact:

For example, to build the TF-M variant for the FRDM-RW612 board with the object IDs from the Twister overlay:

.. code-block:: console

   west build -b frdm_rw612/rw612/ns modules/lib/nxp_iot_agent/zephyr/samples/el2go_mqtt_demo -- \
       -DOVERLAY_CONFIG=overlay-el2go-rw61x.conf \
       -DCONFIG_EL2GO_NET_WIFI_SSID=\"my_ssid\" -DCONFIG_EL2GO_NET_WIFI_PSK=\"my_password\"

For the non-TF-M variant, use ``-b frdm_rw612`` (or ``-b rd_rw612_bga``).

Sample Output
=============

TF-M variant (abridged):

.. code-block:: console

    Booting TF-M v2.1.0
    [WRN] This device was provisioned with dummy keys. This device is NOT SECURE
    [Sec Thread] Secure image initializing!
    [INF][PS] Encryption alg: 0x5500200
    [INF][Crypto] Provision entropy seed...
    [INF][Crypto] Provision entropy seed... complete.
    Wi-Fi cau temperature : 34
    MAC Address: MY_MAC_ADDRESS
    PKG_TYPE: BGA
    Set BGA tx power table data
    *** Booting Zephyr OS build b9f5bf039849 ***
    [00:00:00.010,000] <inf> el2go_mqtt_demo: EL2GO MQTT demo starting ...
    Connecting to SSID 'WIFI SSID' ...
    Using WIFI 6 (802.11ax/HE) @ 5GHz (Channel 149, -52 dBm)
    Using IPv4 address 172.20.10.4 @ Gateway 172.20.10.1 (DHCP)
    Successfully connected to WIFI
    [00:00:12.120,000] <inf> el2go_mqtt_demo: Network ready. Starting MQTT credential verification ...
    Attempting to connect to service 'awstest-0000000000c4d709-0000' ...
    Received MQTT event CONNACK
    Successfully published
    Successfully published
    Successfully published
    Successfully published
    Received MQTT event DISCONNECT
    Attempting to register service 'azuretest-0000000000c4d70a-0000' ...
    Received MQTT event CONNACK
    Received MQTT event SUBACK
    Received MQTT event PUBLISH
    Device State is now ASSIGNING
    Received MQTT event PUBLISH
    Device State is now ASSIGNING
    Received MQTT event PUBLISH
    Device State is now ASSIGNED
    Received MQTT event DISCONNECT
    Attempting to connect to service 'azuretest-0000000000c4d70a-0000' ...
    Received MQTT event CONNACK
    Successfully published
    Successfully published
    Successfully published
    Successfully published
    Received MQTT event DISCONNECT
    [00:00:31.450,000] <inf> el2go_mqtt_demo: EL2GO MQTT Client successfully finished

In the non-TF-M variant the TF-M boot messages are not printed. In case of an error,
``<err> el2go_mqtt_demo: EL2GO MQTT demo failed (rc=<code>)`` is printed.