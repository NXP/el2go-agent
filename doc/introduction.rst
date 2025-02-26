..
    Copyright 2020, 2021, 2024-2025 NXP

    SPDX-License-Identifier: Apache-2.0


Introduction
======================================

EdgeLock 2GO is a cloud service by NXP for provisioning keys and credentials into devices equipped with SE050
and for easily onboarding the device into the cloud services of the user.
Please visit https://www.nxp.com/edgelock2go for more information.

The EdgeLock 2GO agent is the on-device counterpart of the EdgeLock 2GO cloud service. Its purpose
is to establish a secure connection to the EdgeLock 2GO service, report status of the device and update the
device with up-to-date credentials and configuration data. It handles credentials for authentication
at customer cloud services in cooperation with a secure keystore and manages configuration data/connection
information for these the cloud services.

Building and running the EdgeLock 2GO agent
============================================

Building / Compiling the EdgeLock 2GO agent
----------------------------------------------

The build instructions for the EdgeLock 2GO agent do not deviate from the build instructions already
introduced in section :ref:`building`. For convenience, the script
``<SE05X_root_folder>/simw-top/scripts/create_cmake_projects.py``
will generate bespoke CMake configurations with all CMake options set correctly for building the
EdgeLock2 GO agent for MCU-SDK (FRDMK64F, LPC55S69), and i.MX:

- KSDK: ``<SE05X_root_folder>/simw-top_build/simw-top-eclipse_arm_el2go``
- i.MX (native compilation): ``<SE05X_root_folder>/simw-top_build/imx_native_se050_t1oi2c_openssl_el2go``

Registering the device to the EdgeLock 2GO service
----------------------------------------------------

In order to connect your device to EdgeLock 2GO and provision the keys and credentials that you have configured,
you first need to register your device to your EdgeLock 2GO account. This can be done in different ways including:

- Registering your device UID into your EdgeLock 2GO account. You must first read-out the UID of your device.
  This can be achieved for example by executing the se05x_Get_Info executable that is part of this release. How to do
  this is described in more detail in :ref:`ex-se05x-info`.

- Injecting a claim code on the device, see :ref:`el2go_claimcodes`.

For more details, please refer to the EdgeLock 2GO documentation (AN12691).

Connecting the device to the EdgeLock 2GO service
--------------------------------------------------

For the connection to the EdgeLock 2GO cloud service, each account uses an individual hostname. You
can obtain this hostname in the company settings on the GUI of the EdgeLock 2GO cloud service. The
hostname can be picked up by the EdgeLock 2GO agent from different locations, please see also
:ref:`el2go_connection_parameters`.

Once you have registered your device or installed a claim code, you can simply connect your device
to the EdgeLock 2GO cloud service by calling the EdgeLock 2GO agent API. See
:ref:`el2go_usage_examples` for an example. During the connection to the EdgeLock 2GO cloud
service, the device will get provisioned with the credentials that you have configured. 
For more details, please refer to the EdgeLock 2GO documentation (AN12691).

OpenSSL engine/provider configuration
--------------------------------------------------

When using OpenSSL as library an abstraction of the OpenSSL cyptographic APIs to the Se05x secure element is required:
an example is the signature calculation used for authentication to the EdgeLock 2GO server done via a private key
preprovisioned in the Secure Element. To achieve the abstraction the following SSS libraries are used:

- OpenSSL 1.1.1: sss_engine

- OpenSS: 3.x: sssProvider


For OpenSSL 1.1.1 version the sss_engine is used for accessing Se05x functionality:

- Build the sss_engine library together with the el2go_agent application

- Add the path to the built library (libsss_engine.so) in the OpenSSL configuration file which is located under
``<SE05X_root_folder>/simw-top/nxp_iot_agent/ex/src/openssl_conf_v111.cnf`` in the dynamic_path variable of e4sss_section

- Add the environment varaible OPENSSL_CONF pointing to the changed openssl_conf_v111.cnf

For OpenSSL 3.x version the sssProvider is used for accessing Se05x functionality. The provider library is linked
to the el2go_agent application and is loaded during runtime using the OpenSSL feature of built-in provider support


Re-provisioning of objects
--------------------------------------------------

If during provisioning of one object the EdgeLock 2GO server finds an objects with same ID, will first delete
the object before provision the new one.
Now, the following consideration needs to be taken in place when deleting one object:

- the server doesn't know the DELETE permissions of the object on the device (which are defined through policies)

- the server can't read the policies using read attribute APDU since the READ persmissions might be disabled

To solve the issue, the server executes two DELETE operation, one unathenticated and one authenticated,
which covers most of possible object status on the device. Now, imagine that you have one object
where the unauthenticated DELETE is not allowed while the authenticated is, the first APDU will fail with the 6986 status word.
The server will ignore the error returnes status of the APDU and continue with provisioning, but on device a warning will be displayed
as can be seen in the log below. User can ignore this or similar warnings in case the final report shows success.:

``sss   :WARN :APDU Transaction Error: Command not allowed - access denied based on object policy (0x6986)``

Datastore / Keystore
======================================

For storage of credentials and configuration data two types of storage entities are available. A
keystore is used for storing sensitive information, typically private keys for a client
authentication, whereas a datastore is used for storing configuration data required for connecting
to a cloud service. Both are managed remotely from the EdgeLock 2GO cloud service. From the point of
view of the EdgeLock 2GO cloud service datastores and keystores are considered endpoints. The
EdgeLock 2GO cloud service sends messages to endpoints to set them up according to the
desired configuration.

After the device is configured/provisioned for a cloud service by the EdgeLock 2GO cloud service,
the relevant information can be extracted for usage in client software from the storages. The access
to the credentials is abstracted by using the :ref:`sss-apis`, configuration data is accessed using
a service descriptor struct object.

One keystore implementation is included for supporting the SE050. The EdgeLock 2GO cloud service
uses a direct APDU channel to read out from and insert objects into the secure element.

For the sake of demonstration, also two datastore implementations are part of this package. A
filesystem based datastore which uses files for storing the data delivered by the EdgeLock 2GO cloud
service is present in ``<SE05X_root_folder>/simw-top/nxp_iot_agent/*/nxp_iot_agent_datastore_fs.*``
(* stands for ``inc`` or ``src`` folder in the path and for ``h`` or ``c`` in the file name extension),
one that uses raw memory can be found in
``<SE05X_root_folder>/simw-top/nxp_iot_agent/*/nxp_iot_agent_datastore_plain.*``.

When writing contents to a datastore, EdgeLock 2GO cloud service protects the data with a checksum.
This allows the EdgeLock 2GO agent to check whether the data that is found inside a datastore is
valid/uncorrupted.


Connection to the EdgeLock 2GO cloud service
==============================================

This section gives a short overview of the communication channel between the EdgeLock 2GO agent and
the EdgeLock 2GO cloud service. The connection to the EdgeLock 2GO cloud service is always initiated
from the EdgeLock 2GO agent.


Transport layer security
----------------------------------------------------------

Communication between client and server is protected in a mutually authenticated TLS channel. The
TLS protocol versions TLS 1.2 and TLS 1.3 are supported. The supported ciphersuites are:

For TLS 1.2:

- TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
- TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
- TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
- TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
- TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
- TLS_DHE_RSA_WITH_AES_256_GCM_SHA384


For TLS 1.3:

- TLS_AES_128_GCM_SHA256
- TLS_AES_256_GCM_SHA384

Client authentication
----------------------------------------------------------

When using SE050 for authenticating at the EdgeLock 2GO cloud service, the client's private key as
well as the client certificate are stored on the secure element. SE050 comes with those credentials
already pre-installed from the NXP production site with predefined object identifiers.

There are two crypto libraries available to do the TLS handshake in combination with the SE050. It
is possible to use OpenSSL with an custom crypto engine (see :ref:`intro-openssl-engine`).
Alternatively mbedTLS with an alternative implementation for the SE050 can be used (see
:ref:`mbedTLS-alt`).

Server authentication
----------------------------------------------------------

The server is authenticated by using a certificate chain ultimately signed by an NXP root CA. There
are two different certificate chains available, one using ECC with the NIST P-384 curve, the other
chain uses RSA with 4096 bit keys. The trusted root CA certificates are included with the
distributed package of the NXP Plug & Trust Middleware (see also `Parameters for the connection to
EdgeLock 2GO cloud service`_).

The EdgeLock 2GO cloud service provides certificate revocation lists (CRLs) for the CA signing the
server certificates. The CRLs are transferred via TLS channel in order to avoid having to implement
another protocol (typically http) for retrieving the CRL. When using openssl as crypto library, the
CRL processing is skipped for openssl versions < 1.1.1.


Application layer protocol
----------------------------------------------------------

On the application layer, the EdgeLock 2GO cloud service sends protobuf messages (requests) to
individual endpoints which are handled by those. Depending on the endpoint type, different requests
are used. Requests to the EdgeLock 2GO agent itself are used for querying the presence of endpoints
and their supported features and managing the communication channel. Other requests directly address
reading data or writing contents of keystores and datastores.

For configuring an SE050 keystore, the EdgeLock 2GO cloud service uses APDU commands that are
directly forwarded to the secure element. If sensitive information is included or integrity
protection is required, APDUs can be encrypted. This way a secure end-to-end channel between the
EdgeLock 2GO cloud service and the secure element can be established.

For datastores the EdgeLock 2GO cloud service is able to perform read operations to retrieve the
current contents. Should it be necessary, an update of the datastore contents can be performed. The
EdgeLock 2GO cloud service always replaces the complete contents of the datastore. The first request
is an allocate operation, allowing the datastore to make sure memory for the contents is available.
It is followed by one or more write operations. If the datastore supports transactions, after the
last write, an additional commit operation is done to trigger an atomic update of the datastore
contents.

The definition of the protobuf application layer protocol can be found in
``<SE05X_root_folder>/simw-top/nxp_iot_agent/doc/protobuf``.

.. _el2go_connection_parameters:

Parameters for the connection to EdgeLock 2GO cloud service
---------------------------------------------------------------

The EdgeLock 2GO agent attempts to take hostname, port, a reference to the client key and client
certificate as well as a collection of trusted root ca certificates from a datastore that is
registered with a particular id. If a datastore with this id is registered and contains valid data
(checksum verification), then the EdgeLock 2GO agent uses its contents. If this is not the case, it
falls back to compile-time constants defined in
``<SE05X_root_folder>/simw-top/nxp_iot_agent/inc/nxp_iot_agent_config.h``.

For demonstration purposes, in the demo application in
``<SE05X_root_folder>/simw-top/nxp_iot_agent/ex/src/iot_agent_demo.c``, a datastore for the EdgeLock
2GO cloud service connection parameters is registered. It is filled at the first boot with the
compile-time constants from the configuration file.

In order to be able to mitigate a potential corruption of the keys of the trusted root certificates,
in case the connection parameters are taken from the datastore, the EdgeLock 2GO cloud service has
the opportunity to update the connection parameters remotely.

.. _el2go_claimcodes:

Claim Codes
======================================

A claim code allows registering the device into the user account automatically. Claim codes are created and managed from
the EdgeLock 2GO service. Please refer to the EdgeLock 2GO documentation (AN12691, section 5.3: 'Add a device
to the allowlist using claim codes') for more details.

To facilitate injection of claim code into device, a simple application capable of injecting and
deleting claim codes (el2go_claimcode_inject) is delivered in combination with the EdgeLock 2GO agent.
This application reads a claim code from a text file.

After the claim code was generated on EdgeLock 2GO service, the user has to create a .txt file (``claim.txt`` for example)
and copy the generated claim code value inside the file. Then, to inject the claim code copied in the file ``claim.txt``,
the following command can be used:

``./el2go_claimcode_inject claim.txt``

Application also supports deleting existing claim code from with the following command:

``./el2go_claimcode_inject --delete``


.. _el2go_offline_provisioning:
Offline Provisioning of Secure Objects
======================================

The EdgeLock 2GO agent supports managed provisioning of secure objects via secure TLS channel (see `Connection to the EdgeLock 2GO cloud service`_) between device and EdgeLock 2GO. EdgeLock 2GO also supports provisioning of secure objects without a connection from device
to EdgeLock 2GO (referred to as offline remote trust provisioning). Please refer to provisioning of secure objects in the EdgeLock 2GO documentation (AN12691, section 8.3: 'Offline secure object provisioning') for more details. 

To demonstrate offline remote trust provisioning, a simple client-server example capable of importing secure objects into device is delivered in combination with the EdgeLock 2GO agent. Communication between server-client is implemented by a simple TCP protocol. Below picture depicts a block diagram for offline remote trust provisioning.

- **Block diagram:**

.. image:: /offline_rtp_blockdiagram.jpeg
       :align: center
       :width: 270px


Offline Remote Trust Provisioning Server (RTP Server)
---------------------------------------------------------------
After configuring device and secure objects in your EdgeLock 2GO account, you have the possibility to download provisionings for the
device in the form of JSON file. For more details with regard to this step, please refer to EdgeLock 2GO documentation (AN12691,
section 8.3: 'Offline secure object provisioning'). The RTP Server application is meant to run on machine capable of connecting to EL2GO
and retrieving JSON files containing provisionings. For the sake of simplicity, the RTP Server is implemented in Java language
with minimal dependencies and source code is located under:

``<SE05X_root_folder>/simw-top/nxp_iot_agent/ex/tools/edge-lock-device-link-rtp-server``

Once the JSON file containing provisionings is downloaded from EL2GO, following commands can be used to build and run application.
Please note, it is expected to have maven installed on the machine.

Compile and create jar file:

``mvn package``

Print usage details of RTP Server:

``java -jar target/RtpServer.jar -h``

Print version details of RTP Server:

``java -jar target/RtpServer.jar -V``

Run RTP Server on specified port reading JSON files from specified directory:

``java -jar target/RtpServer.jar -d c:\el2go -p 7080``


Offline Remote Trust Provisioning Client (RTP Client)
---------------------------------------------------------------
The RTP Client application is meant to run on the MCU to which the secure element is connected. The build instructions for the RTP Client are similar to that of EdgeLock 2GO agent. The RTP Client application is implemented in C language and source code is located under:

``<SE05X_root_folder>/simw-top/nxp_iot_agent/ex/apps/remote_provisioning_client.c``

To start the RTP Client application, the following command can be used:

``./remote_provisioning_client.exe hostname port``
where:

- hostname = Hostname/IP address of machine on which RTP server is running
- port = Port on which RTP Server is listening

Once the RTP Client is connected, the RTP Server reads the UID of the secure element. The RTP Server parses all JSON files located at the given directory and finds all provisionings for this particular UID. These provisioning are then sent to RTP Client and imported to secure element.
