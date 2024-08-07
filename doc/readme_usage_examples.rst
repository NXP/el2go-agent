..
    Copyright 2020, 2021, 2024 NXP

    SPDX-License-Identifier: Apache-2.0
    
.. _el2go_usage_examples:

===========================================================
 EdgeLock 2GO Agent Examples
===========================================================

.. highlight:: shell

The usage of EdgeLock 2GO agent is demonstrated with the following example demo source code.
The source code example is taken from the following file
``<SE05X_root_folder>/simw-top/nxp_iot_agent/ex/src/iot_agent_demo.c``.

Initializaton of context and updating device configuration
----------------------------------------------
Initialization of contexts of EdgeLock 2GO agent its keystores and datastores

.. literalinclude:: ../ex/src/iot_agent_demo.c
   :language: cpp
   :start-after: doc: initialization of contexts - start
   :end-before: doc: initialization of contexts - end

Update device configuration:

.. literalinclude:: ../ex/src/iot_agent_demo.c
   :language: cpp
   :start-after: doc: update device configuration - start
   :end-before: doc: update device configuration - end

Iterate over configured services and access credentials and service configuration data:

.. literalinclude:: ../ex/src/iot_agent_demo.c
   :language: cpp
   :start-after: doc: iterating over services - start
   :end-before: doc: iterating over services - end

MQTT connection tests with Cloud Onboarding Provisioning
----------------------------------------------

The example shows how to trigger the MQTT connection tests to the services when they are provisioned
through the Cloud Onboaring Provisioning; the connection is triggered from following file:
``<SE05X_root_folder>/simw-top/nxp_iot_agent/ex/src/iot_agent_demo.c``

.. literalinclude:: ../ex/src/iot_agent_demo.c
   :language: cpp
   :start-after: doc: trigger MQTT connection - start
   :end-before: doc: trigger MQTT connection - end

In case of FreeRTOS platform as LPC55S or FRDM_K64F the MQTT FreeRTOS client will be used
for connection; implementation details can be found under
``<SE05X_root_folder>/simw-top/nxp_iot_agent/ex/src/utils/iot_agent_mqtt_freertos.c``:

.. literalinclude:: ../ex/src/utils/iot_agent_mqtt_freertos.c
   :language: cpp
   :start-after: doc: trigger MQTT connection freertos - start
   :end-before: doc: trigger MQTT connection freertos - end
   
In case of Open SSL platform as iMX6 or iMX8 the MQTT Paho client will be used for connection;
implementation details can be found under
``<SE05X_root_folder>/simw-top/nxp_iot_agent/ex/src/utils/iot_agent_mqtt_paho.c``:

.. literalinclude:: ../ex/src/utils/iot_agent_mqtt_paho.c
   :language: cpp
   :start-after: doc: trigger MQTT connection paho - start
   :end-before: doc: trigger MQTT connection paho - end

MQTT connection tests with Remote Trust Provisioning
----------------------------------------------

The example shows how to trigger the MQTT connection tests to the services when they are provisioned
through the Remote Trust Provisioning; the connection is triggered from following file:
``<SE05X_root_folder>/simw-top/nxp_iot_agent/ex/src/iot_agent_demo.c``

.. literalinclude:: ../ex/src/iot_agent_demo.c
   :language: cpp
   :start-after: doc: trigger MQTT connection RTP - start
   :end-before: doc: trigger MQTT connection RTP - end

To enable the MQTT connection for the RTP use case some manual adjustments needs to be done in the Agent code;
the use case can be enabled by setting the variable IOT_AGENT_MQTT_ENABLE to 1 in the file
``<SE05X_root_folder>/simw-top/nxp_iot_agent/inc/nxp_iot_agent_config.h``

The user has to setup some configuration parameters for the service to which he want to connect; this can be done
by changing some definitions in the file:
``<SE05X_root_folder>/simw-top/nxp_iot_agent/ex/inc/iot_agent_demo_config.h``

.. literalinclude:: ../ex/inc/iot_agent_demo_config.h
   :language: cpp
   :start-after: doc: MQTT required modification - start
   :end-before: doc: MQTT required modification - end

Depending on the service type the Service Descriptor should be set to include the correct connection data
and object IDs of the Key Pair and X.509 device leaf certificate associated with the service. The following
functions should be modified in the file
``<SE05X_root_folder>/simw-top/nxp_iot_agent/ex/src/iot_agent_demo.c``

.. literalinclude:: ../ex/src/iot_agent_demo.c
   :language: cpp
   :start-after: doc: configure service descriptor - start
   :end-before: doc: configure service descriptor - end

In the case of AWS auto-registration the Intermediate certificate used to sign the device leaf certificate needs to be presented
to the cloud when doing the registration; EdgeLock 2GO offers the possibility to provision the intermediate CA together
with the leaf certificate in one combined object.
The MQTT Client on Embedded Linux devices is able to automatically load the combined object and execute the auto-registration.
On FreeRTOS devices the dynamic loading is not implemented and the intermediate certificate must be provided in the code; to achieve this,
the value of the #define keyJITR_DEVICE_CERTIFICATE_AUTHORITY_PEM in file ``<SE05X_root_folder>/simw-top/demos/ksdk/common/aws_clientcredential_keys.h``
must be filled with the value of the intermediate certificate in PEM format.
