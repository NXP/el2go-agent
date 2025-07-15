.. _el2go_import_blob:

EL2GO Import Blob Application
#############################

Overview
********

This sample application shows how to import encrypted EdgeLock 2GO secure object blobs from flash to the
ITS storage. The imported objects can then be validated by executing crypto operations.

The application is based on the Trusted Firmware-M (TF-M) project which allows the execution in a Trusted Execution Environment.
The example is split in two parts: TF-M core and RootOfTrust services are runnig in Secure Processing Environment (SPE),
while the application itself is running in Non-secure Processing Environment (NSPE).

The application requires to have encrypted EdgeLock 2GO secure object blobs loaded in flash. This can be achieved
using offline provisioning with the el2go_host application.

The source code for this application can be found at:
:zephyr_file:`modules/lib/nxp_iot_agent/ex/src/apps/psa_examples/el2go_import_blob`.

Requirements
************

- FRDM-RW612 or RD-RW612-BGA board
- USB-C (FRDM-RW612) or Micro-USB (RD-RW612-BGA) cable
- Personal Computer

Prerequisites
*************

- Active EdgeLock 2GO account (https://www.nxp.com/products/security-and-authentication/secure-service-2go-platform/edgelock-2go:EDGELOCK-2GO)
- Any serial communicator

Prepare the Demo
****************

1.  [Optional] By default the validation of the blobs is disabled. It can be enabled with the corresponding macro:

    in :zephyr_file:`modules/lib/nxp_iot_agent/ex/src/apps/psa_examples/el2go_import_blob/el2go_import_blob.h`
    ``#define VALIDATE_PSA_IMPORT_OPERATION 1`

    This value can optionally also be set in the prj.conf like this:
    ``CONFIG_VALIDATE_PSA_IMPORT_OPERATION=y``
    If its set in the prj.conf to true, then it will override the value of define
    in :zephyr_file:`modules/lib/nxp_iot_agent/ex/src/apps/psa_examples/el2go_import_blob/el2go_import_blob.h`.

    This provides an example on how the imported blobs can be used. Specifically, the example demonstrates:
    - AES-ECB message encryption with a 256-bit key.
    - ECDSA SHA 256 message signing.

    When creating the secure objects on EdgeLock 2GO, Custom policies should be chosen.
    Additionally for the AES key following options should be selected:
    - Device Lifecycle should match the lifecycle of the device on which the application will run
    - Permitted algorithm should be set to ECB NO PADDING
    - ENCRYPT usage should be selected
    For the ECC key pair following options should be selected:
    - Device Lifecycle should match the lifecycle of the device on which the application will run
    - Permitted algorithm should be set to ECDSA SHA 256
    - SIGN MESSAGE usage should be selected

2.  [Optional] In order to maximize the TF-M ITS performance, the maximum supported blob size is set to 2908 bytes. In case
    you want to support bigger blobs (8K is the maximum size supported by PSA), you need to change the following three variables:

    in :zephyr_file:`modules/tee/tf-m/trusted-firmware-m/platform/ext/target/nxp/<board>/config_tfm_target.h`
    ``#define CRYPTO_ENGINE_BUF_SIZE 0x8000``
    ``#define ITS_MAX_ASSET_SIZE     3 * 0xC00``

    in :zephyr_file:`modules/tee/tf-m/trusted-firmware-m/platform/ext/target/nxp/<board>/partition/flash_layout.h`
    ``#define TFM_HAL_ITS_SECTORS_PER_BLOCK (3)``

3.  To properly derive die-individual encryption and authentication keys used for provisioning of EdgeLock 2GO Secure Objects,
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

4.  Build the application.

5.  Connect the USB-C (FRDM-RW612) or Micro-USB (RD-RW612-BGA) cable to the PC host and the MCU-Link USB port
    (J10 [FRDM-RW612] or J7 [RD-RW612-BGA]) on the board.

6.  Open a serial terminal with the following settings:
    - 115200 baud rate
    - 8 data bits
    - No parity
    - One stop bit
    - No flow control

7.  Flash the application to the board: as explained in the section 3, in typical production use case the example is encrypted
    in a SB3.1 container. Follow the Application note AN13813 "Secure boot on RW61x" to check how to dowload the container to the device.

    In case the example is running on a device in OEM OPEN lifecycle the merged and signed image can be downloaded west flash command through JLink.
    An alterantive is the usage of the SPSDK blhost application which is decoumented under https://spsdk.readthedocs.io/en/stable/examples/blhost/blhost.html.

Building, Flashing and Running
******************************

.. zephyr-app-commands::
   :zephyr-app: modules/lib/nxp_iot_agent/zephyr/samples/el2go_import_blob
   :board: <board>
   :goals: build flash
   :compact:

Sample Output
=============

.. code-block:: console

    [WRN] This device was provisioned with dummy keys. This device is NOT SECURE
    [Sec Thread] Secure image initializing!
    Booting TF-M v2.0.0
    [INF][Crypto] Provisioning entropy seed... complete.
    *** Booting Zephyr OS build RW-v3.6.0-502-g01bce12e50d6 ***
    2 blob(s) imported from flash successfully

    Validate imported blobs

     Cipher encrypt passed!

     ECC sign passed!
