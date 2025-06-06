.. _el2go_agent:

EL2GO Agent Application
#######################

Overview
********

This sample application shows how to use the EdgeLock 2GO service to provisioning keys and certificates to an MCU device.
Those keys and certificates can then be used to establish mutual-authenticated TLS connections to cloud services such as AWS or Azure.

The application is based on the Trusted Firmware-M (TF-M) project which allows the execution in a Trusted Execution Environment.
The example is split in two parts: TF-M core and RootOfTrust services are runnig in Secure Processing Environment (SPE),
while the application itself is running in Non-secure Processing Environment (NSPE).

It supports two modes for registering a device at the EdgeLock 2GO service:
- UUID registration: At startup, the demo prints the UUID which can be used for manual registration
- Claiming: The EL2GO Claimcode Encryption sample must be run before, which will store a claim code blob
in the flash memory. The EL2GO Agent sample will present the claim code to the EdgeLock 2GO service
and automatically register the device.

The device on which the example is run must have secure boot enabled, otherwise the blob verification and
decryption keys can't be derived.

The source code for this application can be found at:
:zephyr_file:`modules/lib/nxp_iot_agent`.

Requirements
************

- FRDM-RW612 or RD-RW61X-BGA board
- USB-C (FRDM-RW612) or Micro-USB (RD-RW61X-BGA) cable
- Personal Computer

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
1.  Provide the EdgeLock 2GO URL for the account (can be found in the "Admin" section):

    in :zephyr_file:`modules/lib/nxp_iot_agent/inc/nxp_iot_agent_config.h`
    ``#define EDGELOCK2GO_HOSTNAME``

    This value can optionally also be set in the prj.conf like this:
    ``CONFIG_EDGELOCK2GO_HOSTNAME="YOUR_HOSTNAME"``
    If it's set in the prj.conf, then it will override the value of define
    in :zephyr_file:`modules/lib/nxp_iot_agent/inc/nxp_iot_agent_config.h`.
    Furthermore, this value can be set as environment variables, but the value in prj.conf has
    most precedence. Set as environment variable using same name CONFIG_EDGELOCK2GO_HOSTNAME.

2.  Provide the Wi-Fi access point credentials:

    in :zephyr_file:`modules/lib/nxp_iot_agent/ex/src/network/iot_agent_network_zephyr_wifi.c`
    ``#define AP_SSID``
    ``#define AP_PASSWORD``
    
    These values can optionally also be set in the prj.conf like this:
    ``CONFIG_AP_SSID="YOUR_SSID"``
    ``CONFIG_AP_PASSWORD="YOUR_PASSWORD"``
    If these are set in the prj.conf, then it will override the value of defines
    in :zephyr_file:`modules/lib/nxp_iot_agent/ex/src/network/iot_agent_network_zephyr_wifi.c`.
    Furthermore, these values can be set as environment variables, but the values in prj.conf have
    most precedence. Set as environment variable using same names CONFIG_AP_SSID and CONFIG_AP_PASSWORD.

3.  [Optional] In case you want to use the "Claiming" registration method, enable the corresponding macro:

    in :zephyr_file:`modules/lib/nxp_iot_agent/ex/inc/iot_agent_demo_config.h`
    ``#define IOT_AGENT_CLAIMCODE_INJECT_ENABLE 1``

    This value can optionally also be set in the prj.conf like this:
    ``CONFIG_IOT_AGENT_CLAIMCODE_INJECT_ENABLE=y``
    If it's set in the prj.conf, then it will override the value of define
    in :zephyr_file:`modules/lib/nxp_iot_agent/ex/inc/iot_agent_demo_config.h`.

    The flash address where the claim code will be written to is set to 0x084A0000 by default.
    The location can be changed by altering the following variable (make sure to keep it aligned with
    the address configured in the EL2GO Claimcode Encryption sample):

    in :zephyr_file:`modules/lib/nxp_iot_agent/ex/src/utils/iot_agent_claimcode_inject.c`
    ``#define CLAIM_CODE_INFO_ADDRESS``

4.  [Optional] In case you want to use provisioned ECC key pairs and corresponding X.509 certificates
    to execute TLS mutual-authentication and MQTT message exchange with AWS and/or Azure clouds, enable the corresponding macro:

    in :zephyr_file:`modules/lib/nxp_iot_agent/ex/inc/iot_agent_demo_config.h`
    ``#define IOT_AGENT_MQTT_ENABLE 1``

    In the same file, the following macros should be set to the object ID as defined at EdgeLock 2GO service:
    ``#define $SERVER$_SERVICE_KEY_PAIR_ID``
    ``#define $SERVER$_SERVICE_DEVICE_CERT_ID``

    These values can optionally also be set in the prj.conf like this:
    ``CONFIG_IOT_AGENT_MQTT_ENABLE=y``
    ``CONFIG_$SERVER$_SERVICE_KEY_PAIR_ID=0x081000``
    ``CONFIG_$SERVER$_SERVICE_DEVICE_CERT_ID=0x080100``
    If these are set in the prj.conf, then it will override the value of defines
    in :zephyr_file:`modules/lib/nxp_iot_agent/ex/inc/iot_agent_demo_config.h`.

    The settings of other macros are server dependent and their meaning can be found in the AWS/Azure documentation.
    By default, the demo is executing a connection to both clouds when IOT_AGENT_MQTT_ENABLE is enabled;
    To enable or disable them individually, use the AWS_ENABLE and AZURE_ENABLE macros respectively.

5.  [Optional] In order to maximize the TF-M ITS performance, the maximum supported blob size is set to 2908 bytes. In case
    you want to support bigger blobs (8K is the maximum size supported by PSA), you need to change the following three variables:

    in :zephyr_file:`modules/tee/tf-m/trusted-firmware-m/platform/ext/target/nxp/<board>/config_tfm_target.h`
    ``#define CRYPTO_ENGINE_BUF_SIZE 0x8000``
    ``#define ITS_MAX_ASSET_SIZE     3 * 0xC00``

    in :zephyr_file:`modules/tee/tf-m/trusted-firmware-m/platform/ext/target/nxp/<board>/partition/flash_layout.h`
    ``#define TFM_HAL_ITS_SECTORS_PER_BLOCK (3)``

6.  To properly derive die-individual encryption and authentication keys used for provisioning of EdgeLock 2GO Secure Objects,
    the secure boot mode should be enabled and the hash of the OEM FW Authentication key (RKTH) loaded in the One Time Programming (OTP) fuses
    of the device. The enablement of secure boot requires the application image downloaded to the chip to be signed with the OEM FW Authentication key.
    Additionaly, if the example is supposed to run in the OEM CLOSED life cycle (typical for production SW),
    the image needs to be encrypted with the OEM FW encryption key and loaded as an Secure Binary container (SB3.1).
    Details on how to enable secure boot, sign and encrypt the image, deal with different lifecycles are included
    in the Application note AN13813 "Secure boot on RW61x", downloadable from
    https://www.nxp.com/products/wireless-connectivity/wi-fi-plus-bluetooth-plus-802-15-4/wireless-mcu-with-integrated-tri-radio-1x1-wi-fi-6-plus-bluetooth-low-energy-5-3-802-15-4:RW612
    in the "Secure Files" section.

    Zephyr build process supports automated signing and merging of images which will allow the example to run on secure boot enabled sample
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
    For more details about the keys/certificates described in the readme, always refer to the Application Note AN13813 "Secure boot on RW61x"
    There are 2 ways to define the variables and allow Zephyr build command to automatically merge and sign the image:
    1. In prj.conf file:
    ``CONFIG_EL2GO_SIGN_USING_NXPIMAGE=y``
    ``CONFIG_EL2GO_PRIVATE_KEY="PATH_TO_YOUR_KEY_PEM_FILE"``
    ``CONFIG_EL2GO_CERT_BLOCK="PATH_TO_YOUR_CERTIFICATE_YML_FILE"``
    2. If not set in prj.conf file, then set as environment variable using the same names: 
       CONFIG_EL2GO_PRIVATE_KEY,CONFIG_EL2GO_CERT_BLOCK,CONFIG_EL2GO_SIGN_USING_NXPIMAGE.
       Please set them to same value as you would in prj.conf file.
    In case both are set, the variables in the prj.conf will take precedence.

7.  Build the application.

8.  Connect the USB-C (FRDM-RW612) or Micro-USB (RD-RW61X-BGA) cable to the PC host and the MCU-Link USB port
    (J10 [FRDM-RW612] or J7 [RD-RW61X-BGA]) on the board.

9.  Open a serial terminal with the following settings:
    - 115200 baud rate
    - 8 data bits
    - No parity
    - One stop bit
    - No flow control

10. Flash the application to the board: as explained in the section 6, in typical production use case the example is encrypted
    in a SB3.1 container. Follow the Application note AN13813 "Secure boot on RW61x" to check how to dowload the container to the device.

    In case the example is running on a device in OEM OPEN lifecycle the merged and signed image can be downloaded west flash command through JLink.
    An alterantive is the usage of the SPSDK blhost application which is decoumented under https://spsdk.readthedocs.io/en/stable/examples/blhost/blhost.html.

Building, Flashing and Running
******************************

.. zephyr-app-commands::
   :zephyr-app: modules/lib/nxp_iot_agent/zephyr/samples/el2go_agent
   :board: <board>
   :goals: build flash
   :compact:

Sample Output
=============

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
    Found configuration data for 0 services.
    Performance timing: ENTIRE_SESSION_TIME : 3872ms
            Performance timing: AGENT_INIT_TIME : 124ms
            Performance timing: TLS_PREP_TIME : 126ms
            Performance timing: NETWORK_CONNECT_TIME : 1305ms
            Performance timing: PROCESS_PROVISION_TIME : 2260ms
            CRL_TIME : [56ms] and COMMAND_TXRX_TIME : [0ms] included in PROCESS_PROVISION_TIME
