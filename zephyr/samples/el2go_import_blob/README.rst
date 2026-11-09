.. _el2go_import_blob:

EL2GO Import Blob Application
#############################

Overview
********

This sample application shows how to import encrypted EdgeLock 2GO secure object blobs from flash to the
ITS storage. The imported objects can then be validated by executing crypto operations.

The application can be built in two variants, selected by the board target:

- Trusted Firmware-M (TF-M) variant (``frdm_rw612/rw612/ns`` or ``rd_rw612_bga/rw612/ns``): the application is based on the
  TF-M project which allows the execution in a Trusted Execution Environment. The example is split in two parts: TF-M core and
  RootOfTrust services are running in Secure Processing Environment (SPE), while the application itself is running in
  Non-secure Processing Environment (NSPE). The settings are taken from :file:`boards/<board>_rw612_ns.conf` and
  :file:`boards/<board>_rw612_ns.overlay`.
- Non-TF-M variant (``frdm_rw612`` or ``rd_rw612_bga``): PSA Crypto is provided by mbedTLS with the ELS PKC driver and PSA ITS
  is backed by the Zephyr Secure Storage subsystem (ZMS) on the ``its_partition`` declared in
  :file:`boards/<board>_rw612.overlay`. The settings are taken from :file:`boards/<board>_rw612.conf`. The
  ``its_partition`` is located at ``0x08840000`` and is 128 KB in size (identical for both boards). The maximum ITS
  entry size is set with ``CONFIG_SECURE_STORAGE_ITS_MAX_DATA_SIZE=1024`` in
  :file:`boards/<board>_rw612.conf`. The other EL2GO samples
  (RTP agent, MQTT demo, OTA agents, CSR) use the same partition. Do not erase, move or resize it if you want to use
  the imported objects from them.

Unless stated otherwise, the steps below apply to both variants; steps marked [TF-M] are only relevant for the
``/ns`` board targets.

.. note::

   In the non-TF-M variant, PSA ITS (Zephyr Secure Storage) does not offer runtime protection like TF-M does: there is
   no isolated Secure Processing Environment, so the ITS content is accessible to any code running on the device.
   It is therefore recommended to use only S50-internal keys, i.e. keys which are stored and used inside the ELS (S50)
   and never leave it in plain form.

The imported objects are stored in PSA storage and can be used by other applications on the device. For example,
the EL2GO MQTT demo (:ref:`el2go_mqtt_demo`) and the OTA agent samples (:ref:`el2go_ota_agent_core`,
:ref:`el2go_ota_agent_advanced`) read their client key and certificate from there. This sample is an offline
alternative to the online provisioning done by the EL2GO RTP Agent (:ref:`el2go_rtp_agent`).

The application requires to have encrypted EdgeLock 2GO secure object blobs loaded in flash. This can be achieved
using offline provisioning with the el2go_host application.

The TF-M variant supports both BL2 enabled and BL2 disabled bootloader modes. More information can be found in the BL2-related
section below or in the TF-M documentation at the following link
(https://trustedfirmware-m.readthedocs.io/en/latest/design_docs/booting/tfm_secure_boot.html).

The source code for this application can be found at:
:zephyr_file:`modules/lib/nxp_iot_agent/applications/el2go_import_blob`.

Requirements
************

- FRDM-RW612 or RD-RW612-BGA board
- USB-C (FRDM-RW612) or Micro-USB (RD-RW612-BGA) cable
- Personal Computer

Prerequisites
*************

- Active EdgeLock 2GO account (https://www.nxp.com/products/security-and-authentication/secure-service-2go-platform/edgelock-2go:EDGELOCK-2GO)
- EdgeLock 2GO secure object blobs (offline provisioning) for the target device
- Any serial communicator

Prepare the Demo
****************

1.  Provide the location of the EdgeLock 2GO secure object blobs in flash. The blobs are read from a contiguous flash area
    which must match the address used when the blobs were written to the device:

    in :zephyr_file:`modules/lib/nxp_iot_agent/zephyr/samples/el2go_import_blob/prj.conf`
    ``CONFIG_BLOB_AREA=0x088B0000``
    ``CONFIG_BLOB_AREA_SIZE=0x2000``

    These Kconfig values (shown with their defaults) always take precedence over the fallback defines in
    :zephyr_file:`modules/lib/nxp_iot_agent/applications/el2go_import_blob/src/el2go_psa_import.h`.
    Make sure this area does not overlap the application image or the ITS partition, and that it is not erased
    when flashing the application.

2.  [Optional] By default the validation of the blobs is disabled. It can be enabled with the corresponding Kconfig options
    in the prj.conf:

    ``CONFIG_VALIDATE_PSA_IMPORT_MASTER_KEY=y``
    ``CONFIG_VALIDATE_PSA_IMPORT_KEY_PAIR=y``
    ``CONFIG_VALIDATE_PSA_IMPORT_CERT=y``

    Alternatively, all three options are enabled by the :file:`overlay-el2go-rw61x.conf` overlay
    (``-DOVERLAY_CONFIG=overlay-el2go-rw61x.conf``). ``CONFIG_VALIDATE_PSA_IMPORT_CERT`` depends on
    ``CONFIG_VALIDATE_PSA_IMPORT_KEY_PAIR``. The validation sources are only compiled when these options are set;
    changing the fallback ``#define`` values in
    :zephyr_file:`modules/lib/nxp_iot_agent/applications/el2go_import_blob/src/el2go_import_blob.h` alone has no effect.

    This provides an example of how the imported blobs can be used. Specifically, the example demonstrates:

    - AES-ECB message encryption with a 256 bit key
    - ECDSA SHA-256 message signing
    - x509 certificate parsing and extracting public key

    The validation uses fixed object IDs, defined in
    :zephyr_file:`modules/lib/nxp_iot_agent/applications/el2go_import_blob/src/el2go_import_blob.h`.
    The secure objects must be created on EdgeLock 2GO with these object IDs (or the defines adapted accordingly):

    ========================== ==========
    Secure object              Object ID
    ========================== ==========
    AES master key (256 bit)   0x00003000
    ECC key pair (NIST P-256)  0x00003001
    X.509 certificate          0x00003002
    ========================== ==========

    Important notes:

    - When creating the secure objects on EdgeLock 2GO, select Custom policies.
    - For the AES key, ensure:

      - Permitted algorithm is set to ECB NO PADDING.
      - Device Lifecycle matches the target device's lifecycle.
      - ENCRYPT usage is enabled

    - For the ECC key pair following options should be selected:

      - Device Lifecycle matches the target device's lifecycle.
      - Permitted algorithm should be set to ECDSA SHA 256
      - SIGN MESSAGE usage should be selected

    - For the Certificate, ensure:

      - Device Lifecycle matches the target device's lifecycle.
      - EXPORT usage is enabled
      - Certificate validation is only possible if key pair validation is also enabled.

3.  [Optional] In order to maximize the ITS performance, the maximum supported blob size is limited.

    [TF-M] The maximum supported blob size is set to 2908 bytes. In case you want to support bigger blobs
    (8K is the maximum size supported by PSA), you need to change the following three variables:

    in :zephyr_file:`modules/tee/tf-m/trusted-firmware-m/platform/ext/target/nxp/<board>/config_tfm_target.h`
    ``#define CRYPTO_ENGINE_BUF_SIZE 0x8000``
    ``#define ITS_MAX_ASSET_SIZE     3 * 0xC00``

    in :zephyr_file:`modules/tee/tf-m/trusted-firmware-m/platform/ext/target/nxp/<board>/partition/flash_layout.h`
    ``#define TFM_HAL_ITS_SECTORS_PER_BLOCK (3)``

    [Non-TF-M only] The maximum ITS entry size is set in :file:`boards/<board>_rw612.conf`
    (``CONFIG_SECURE_STORAGE_ITS_MAX_DATA_SIZE``, 1024 in this sample); the RTP agent, MQTT demo and OTA agent
    samples use 2944.

4.  [Optional] [TF-M] EdgeLock 2GO applications support two boot modes:

    - BL2 enabled (default): The ROM bootloader first jumps to the BL2 image, which authenticates the signed SPE and NSPE images
    - BL2 disabled: The ROM bootloader jumps directly to the SPE image

    To select the BL2 disabled mode, additional configuration options must be passed to the command line when building the application:

    - CONFIG_TFM_BL2: Indicates whether the BL2 build is enabled or disabled; should be set to 'n'
    - CONFIG_FLASH_BASE_ADDRESS: Must point to the address where the NSPE starts. For BL2 disabled, this should be set to 0x080A0000
    - DTC_OVERLAY_FILE: Should point to the board-specific ``_ns`` overlay file provided in the nxp_iot_agent repository

    For example for the rd_rw612_bga board, use the following arguments:
    ``-DCONFIG_TFM_BL2=n -DCONFIG_FLASH_BASE_ADDRESS=0x080A0000 -DDTC_OVERLAY_FILE="boards/rd_rw612_bga_rw612_ns.overlay"``

    For the frdm_rw612 board, use ``boards/frdm_rw612_rw612_ns.overlay`` instead.

5.  To properly derive die-individual encryption and authentication keys used for provisioning of EdgeLock 2GO Secure Objects,
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

6.  Build the application.

7.  Connect the USB-C (FRDM-RW612) or Micro-USB (RD-RW612-BGA) cable to the PC host and the MCU-Link USB port
    (J10 [FRDM-RW612] or J7 [RD-RW612-BGA]) on the board.

8.  Open a serial terminal with the following settings:

    - 115200 baud rate
    - 8 data bits
    - No parity
    - One stop bit
    - No flow control

9.  Flash the application to the board: as explained in the section 5, in typical production use case the example is encrypted
    in a SB3.1 container. Follow the Application note AN13813 "Secure boot on RW61x" to check how to download the container to the device.

    In case the example is running on a device in OEM OPEN lifecycle the merged and signed image can be downloaded with the west flash command through JLink.
    An alternative is the usage of the SPSDK blhost application which is documented under https://spsdk.readthedocs.io/en/stable/examples/blhost/blhost.html.

Building, Flashing and Running
******************************

.. zephyr-app-commands::
   :zephyr-app: modules/lib/nxp_iot_agent/zephyr/samples/el2go_import_blob
   :board: <board>
   :goals: build flash
   :compact:

For example, to build the TF-M variant for the FRDM-RW612 board with blob validation enabled:

.. code-block:: console

   west build -b frdm_rw612/rw612/ns modules/lib/nxp_iot_agent/zephyr/samples/el2go_import_blob -- \
       -DOVERLAY_CONFIG=overlay-el2go-rw61x.conf

For the non-TF-M variant, use ``-b frdm_rw612`` (or ``-b rd_rw612_bga``).

Sample Output
=============

TF-M variant with validation enabled:

.. code-block:: console

    [WRN] This device was provisioned with dummy keys. This device is NOT SECURE
    [Sec Thread] Secure image initializing!
    Booting TF-M v2.0.0
    [INF][Crypto] Provisioning entropy seed... complete.
    *** Booting Zephyr OS build RW-v3.6.0-502-g01bce12e50d6 ***
    3 blob(s) imported from flash successfully

    Validate imported blobs

     Cipher encrypt passed!

     ECC sign passed!
     Certificate in DER format: 3082018B30820132A003020102020708E07700000000300A06082A8648CE3D0403023073310C300A060355040A0C034E5850312A3028060355040B0C21456467654C6F636B32476F52656D6F74655470506C7567416E64547275737443413137303506035504030C2E783530395F696D5F63615F6E31312D303030303030303030303030326130322D30303030303030302D7645323030301E170D3235313131333137333035365A170D3335313131333137333035365A30143112301006035504030C096E313174656D70636E3059301306072A8648CE3D020106082A8648CE3D030107034200042BE9224D4C89CE5CD99CFCEC8E521394DE94B4D2A3F90BC54EE9289B2B86560397482446FD9CAB433A4ED8A5A5DD453F80CAD7A38466A66F2EFC99C950C39AC7A310300E300C0603551D130101FF04023000300A06082A8648CE3D040302034700304402200D2DFE0763A2567BFE11B793AABE5EF313D57ED59035A081881882B156A01AC3022024DAAC7FBFFE400979E6C66B8F17BAD848F72D1C7AAB6579691B0A4F2FC213C4
     Subject field in certificate is:CN=test_cn
     Issuer field in certificate is:O=NXP, OU=EdgeLock2GoRemoteTpPlugAndTrustCA, CN=x509_IC_-0000000000002a02-00000000-vE200
     Public_key: 042BE9224D4C89CE5CD99CFCEC8E521394DE94B4D2A3F90BC54EE9289B2B86560397482446FD9CAB433A4ED8A5A5DD453F80CAD7A38466A66F2EFC99C950C39AC7

In the non-TF-M variant the TF-M boot messages are not printed. Without validation enabled, the output ends after the
``blob(s) imported from flash successfully`` line. In case of an error, ``#### Import blob(s) from flash failed ####`` is printed.
