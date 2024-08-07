.. _el2go_mqtt_demo:

EL2GO MQTT Demo
###############

Overview
********

This sample application shows how to use MQTT connections to cloud services such as AWS or Azure with preprovisioned keys
and certificates from the EdgeLock 2GO service.

The device on which the example is run must have secure boot enabled, otherwise the blob verification and
decryption keys can't be derived.

The source code for this application can be found at:
:zephyr_file:`modules/lib/nxp_iot_agent/ex/src/apps/el2go_mqtt_client.c`.

Requirements
************

- FRDM-RW612 or RD-RW61X-BGA board
- USB-C (FRDM-RW612) or Micro-USB (RD-RW61X-BGA) cable
- Personal Computer

Prerequisites
*************

- Any serial communicator
- EdgeLock 2GO keypairs and certificates for AWS and/or Azure already imported to the device (ITS).
  This can be achieved via offline provisioning (with th el2go_import_blob sample) or via online
  provisioning (with the el2go_agent sample). Please refer to their repspective readmes on
  how to perform the provisioning and import.

ATTENTION: It is important not to erase the ITS part of the flash (0x83C0000 to 0x83E0000) when flashing this application,
as this is where the EdgeLock 2GO objects are stored.

Prepare the Demo
****************

1.  Provide the EdgeLock 2GO object IDs of the keys and certificates already imported to the device as well as the
    AWS and/or Azure connection parameters in :zephyr_file:`modules/lib/nxp_iot_agent/ex/inc/iot_agent_demo_config.h`
    (the relevant macros are enclosed by "doc: MQTT required modification - start" and "doc: MQTT required modification - end").
    Details on the different configuration options are explained in the file.

2.  Provide the Wi-Fi access point credentials:

    in :zephyr_file:`modules/lib/nxp_iot_agent/ex/src/network/iot_agent_network_zephyr_wifi.c`
    ``#define AP_SSID``
    ``#define AP_PASSWORD``

3.  To correctly run the example, the secure boot mode on the device needs to be enabled. The bootheader needs to be removed
    from the SPE image, it has to be merged with the NSPE image and the resulting image must be signed with the OEM key.
    Additionaly, if the example is supposed to run in the OEM CLOSED life cycle, the image needs to be encrypted with
    the OEM FW encryption key and loaded as an SB3.1 container.
    Details on how to execute these steps can be found in the Application note AN13813 "Secure boot on RW61x", downloadable from
    https://www.nxp.com/products/wireless-connectivity/wi-fi-plus-bluetooth-plus-802-15-4/wireless-mcu-with-integrated-tri-radio-1x1-wi-fi-6-plus-bluetooth-low-energy-5-3-802-15-4:RW612
    in the "Secure Files" section.

4.  Build the application.

5.  Connect the USB-C (FRDM-RW612) or Micro-USB (RD-RW61X-BGA) cable to the PC host and the MCU-Link USB port
    (J10 [FRDM-RW612] or J7 [RD-RW61X-BGA]) on the board.

6.  Open a serial terminal with the following settings:
    - 115200 baud rate
    - 8 data bits
    - No parity
    - One stop bit
    - No flow control

7.  Flash the application to the board. In case the image is signed, the base address needs to be adjusted
    to 0x08001000.

Building, Flashing and Running
******************************

.. zephyr-app-commands::
   :zephyr-app: modules/lib/nxp_iot_agent/zephyr/samples/el2go_mqtt_demo
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
    Wi-Fi cau temperature : 34
    MAC Address: MY_MAC_ADDRESS
    PKG_TYPE: BGA
    Set BGA tx power table data 
    *** Booting Zephyr OS build b9f5bf039849 ***
    Connecting to SSID 'WIFI SSID' ...
    Using WIFI 6 (802.11ax/HE) @ 5GHz (Channel 149, -52 dBm)
    Using IPv4 address 172.20.10.4 @ Gateway 172.20.10.1 (DHCP)
    Successfully connected to WIFI
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
    EL2GO MQTT Client successfully finished
