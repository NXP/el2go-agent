.. _el2go_claimcode_encryption:

EL2GO Claimcode Encryption Application
######################################

Overview
********

This sample application shows how to create and store an encrypted claim code blob on MCU devices. It is meant to be used
together with the EL2GO RTP Agent sample (:ref:`el2go_rtp_agent`), which needs to be downloaded afterwards. It will read the
claim code blob and provide it to the EdgeLock 2GO service during device connection; the EdgeLock 2GO service will then decrypt
and validate the blob and claim the device if the corresponding claim code is found in one of the device groups.

The application performs the following steps:

1. Generates a random ECC key pair in the ELS (EdgeLock Secure Enclave) and derives a shared secret with the EdgeLock 2GO
   claim code public key (ECDH)
2. Derives encryption and MAC keys from the shared secret, encrypts the plain claim code (AES-CBC) and authenticates it (AES-CMAC)
3. Writes the resulting claim code blob to a fixed flash address using the ROM IAP API, in the following layout:
   ``{ uint8_t indicator[4] = "E2GC"; uint32_t size; uint8_t blob[size]; }``

This sample runs directly against the on-chip ELS PKC hardware; there is no Trusted Firmware-M (TF-M) Secure/Non-secure
split for this application.

The source code for this sample application can be found at:
:zephyr_file:`modules/lib/nxp_iot_agent/applications/el2go_claimcode_encryption/src/el2go_claimcode_encryption.c`.

Requirements
************

- FRDM-RW612 or RD-RW612-BGA board
- USB-C (FRDM-RW612) or Micro-USB (RD-RW612-BGA) cable
- Personal Computer

Prerequisites
*************

- Active EdgeLock 2GO account (https://www.nxp.com/products/security-and-authentication/secure-service-2go-platform/edgelock-2go:EDGELOCK-2GO)
- Any serial communicator

Setup of the EdgeLock 2GO platform
**********************************

The documentation which explains how to setup an EdgeLock 2GO account to

- Create a device group
- Create and copy a claim code for the device group
- Get the EdgeLock 2GO claim code public key (RW61x_Claiming_Public_Key)

can be found on the Edgelock 2GO web interface under the "Documentation" tab.

Prepare the Demo
****************

All the configuration options below are Kconfig symbols. Values set in :file:`prj.conf` (or passed with
``-D<SYMBOL>=<value>`` on the ``west build`` command line) always take precedence over the fallback ``#define``
values in the C sources; editing the C fallbacks alone has no effect in a Zephyr build.

1.  Provide the plain claim code string as created on the EdgeLock 2GO service:

    in :zephyr_file:`modules/lib/nxp_iot_agent/zephyr/samples/el2go_claimcode_encryption/prj.conf`
    ``CONFIG_EL2GO_CLAIMCODE_STRING="insert_claimcode_from_el2go"``

    The default value is a placeholder. The fallback for non-Zephyr builds is located in
    :zephyr_file:`modules/lib/nxp_iot_agent/applications/common/config/el2go_app_config.h`
    (``#define EL2GO_CLAIMCODE_STRING``).

2.  Provide the EdgeLock 2GO claim code public key as read from EdgeLock 2GO service
    (in the format of a hexadecimal byte array, 64 bytes, raw X||Y coordinates):

    in :zephyr_file:`modules/lib/nxp_iot_agent/include/rtp/el2go_rtp_claimcode.h`
    ``#define EL2GO_RTP_CLAIMCODE_PUBLIC_KEY_PROD``
    ``#define EL2GO_RTP_CLAIMCODE_PUBLIC_KEY_PROD_SIZE``

    The same header also contains a key for the EdgeLock 2GO sandbox environment
    (``EL2GO_RTP_CLAIMCODE_PUBLIC_KEY_SANDBOX``). The production key is used by default; to use the sandbox key instead,
    set the following option in the prj.conf:
    ``CONFIG_EL2GO_CLAIMCODE_USE_SANDBOX=y``

3.  [Optional] The flash address where the claim code will be written to is set to 0x088A0000 by default.
    The location can be changed with the following option (make sure to keep it aligned with
    ``CONFIG_EL2GO_RTP_CLAIMCODE_FLASH_ADDRESS`` configured in the EL2GO RTP Agent sample):

    in :zephyr_file:`modules/lib/nxp_iot_agent/zephyr/samples/el2go_claimcode_encryption/prj.conf`
    ``CONFIG_CLAIM_CODE_INFO_ADDRESS=0x088A0000``

    The address must be the start of a flash sector (4 KB) which is not used by any other image or partition, since the whole
    sector is erased before the blob is written. No devicetree partition is needed for this region.

4.  [Optional] The claim code encryption is implemented with the ELS PKC hardware backend, which is enabled by default
    (``CONFIG_EL2GO_CLAIMCODE_BACKEND_ELS_PKC=y``). When this option is disabled, a weak stub returning
    ``EL2GO_STATUS_NOT_IMPLEMENTED`` is linked instead and an alternative ``el2go_claimcode_encrypt()`` implementation
    must be provided by the application.

5.  [Optional] In case the example will be used in a device with secure boot mode enabled, the bootheader
    needs to be removed from the image and the resulting binary must be signed with the OEM key.
    Additionaly, if the example is supposed to run in the OEM CLOSED life cycle, the image needs to be encrypted with
    the OEM FW encryption key and loaded as an SB3.1 container.
    Details on how to execute these steps can be found in the Application note AN13813 "Secure boot on RW61x", downloadable from
    https://www.nxp.com/products/wireless-connectivity/wi-fi-plus-bluetooth-plus-802-15-4/wireless-mcu-with-integrated-tri-radio-1x1-wi-fi-6-plus-bluetooth-low-energy-5-3-802-15-4:RW612
    in the "Secure Files" section.

6.  Build the application.

7.  Connect the USB-C (FRDM-RW612) or Micro-USB (RD-RW612-BGA) cable to the PC host and the MCU-Link USB port
    (J10 [FRDM-RW612] or J7 [RD-RW612-BGA]) on the board.

8.  Open a serial terminal with the following settings:

    - 115200 baud rate
    - 8 data bits
    - No parity
    - One stop bit
    - No flow control

9.  Flash the application to the board using west flash command.

10. After the claim code information has been written to flash, build and flash the EL2GO RTP Agent sample with
    ``CONFIG_EL2GO_RTP_CLAIMCODE_INJECT=y`` (see :ref:`el2go_rtp_agent`). Make sure the flash region holding
    the claim code blob is not erased when flashing the agent.

Building, Flashing and Running
******************************

.. zephyr-app-commands::
   :zephyr-app: modules/lib/nxp_iot_agent/zephyr/samples/el2go_claimcode_encryption
   :board: <board>
   :goals: build flash
   :compact:

For example, to set the claim code directly from the command line:

.. code-block:: console

   west build -b frdm_rw612 modules/lib/nxp_iot_agent/zephyr/samples/el2go_claimcode_encryption -- \
       -DCONFIG_EL2GO_CLAIMCODE_STRING=\"my_claimcode\"

The Twister test configuration in :file:`sample.yaml` additionally applies :file:`overlay.conf`, which enables the Zephyr
shell (``devmem`` command) so that the written blob can be read back and compared against the console output.

Sample Output
=============

.. code-block:: console

    Enabling ELS... done
    Generating random ECC keypair... done
    Calculating shared secret... done
    Creating claimcode blob... done
    claimcode (*): *** dynamic data ***
    claimcode (*): *** dynamic data ***
    claimcode (*): *** dynamic data ***

    claimcode information written to flash at address 0x088a0000