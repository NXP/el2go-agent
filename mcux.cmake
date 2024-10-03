# Copyright 2024 NXP
# SPDX-License-Identifier: Apache-2.0

if(CONFIG_MCUX_COMPONENT_middleware.nxp_iot_agent.lwip_enet)
    mcux_add_source(
        SOURCES ex/src/network/iot_agent_network_lwip.c
        BASE_PATH ${SdkRootDirPath}/middleware/nxp_iot_agent/
    )
endif()

if(CONFIG_MCUX_COMPONENT_middleware.nxp_iot_agent.lwip_wifi)
    mcux_add_source(
        SOURCES ex/src/network/iot_agent_network_lwip_wifi.c
        BASE_PATH ${SdkRootDirPath}/middleware/nxp_iot_agent/
    )
endif()

if(CONFIG_MCUX_COMPONENT_middleware.nxp_iot_agent.sss)
    mcux_add_source(
        SOURCES ex/inc/iot_agent_claimcode_inject.h
                ex/src/utils/iot_agent_claimcode_inject.c
        BASE_PATH ${SdkRootDirPath}/middleware/nxp_iot_agent/
    )
    mcux_add_include(
        INCLUDES ex/inc
        BASE_PATH ${SdkRootDirPath}/middleware/nxp_iot_agent/
    )
endif()

if(CONFIG_MCUX_COMPONENT_middleware.nxp_iot_agent.psa)
    mcux_add_source(
        SOURCES ex/inc/iot_agent_claimcode_import.h
                ex/inc/mbedtls_psa/iot_agent_psa_sign_test.h
                ex/src/utils/iot_agent_claimcode_import.c
                ex/src/utils/mbedtls_psa/iot_agent_psa_sign_test.c
        BASE_PATH ${SdkRootDirPath}/middleware/nxp_iot_agent/
    )
    mcux_add_include(
        INCLUDES ex/inc
                 ex/inc/mbedtls_psa
        BASE_PATH ${SdkRootDirPath}/middleware/nxp_iot_agent/
    )
endif()

if(CONFIG_MCUX_COMPONENT_middleware.nxp_iot_agent)
    mcux_add_macro(
        CC "PB_FIELD_32BIT"
    )
    mcux_add_source(
        SOURCES inc/*.h
                ex/inc/iot_agent_demo_config.h
                ex/inc/iot_agent_mqtt_freertos.h
                ex/inc/iot_agent_network.h
                ex/src/osal/iot_agent_osal_freertos.c
                ex/src/utils/iot_agent_mqtt_freertos.c
                platform/network.h
                platform/mbedtls/network_mbedtls.h
                platform/mbedtls/network_mbedtls.c
                platform/mbedtls/net_lwip.c
                src/*.c
                src/common/*.c
                src/protobuf/*.h
                src/protobuf/*.c
        BASE_PATH ${SdkRootDirPath}/middleware/nxp_iot_agent/
    )
    mcux_add_include(
        INCLUDES inc
                 ex/inc
                 platform
                 platform/mbedtls
                 src/protobuf
        BASE_PATH ${SdkRootDirPath}/middleware/nxp_iot_agent/
    )
endif()

if(CONFIG_MCUX_COMPONENT_middleware.nxp_iot_agent.mqtt)
    mcux_add_macro(
        CC "PB_FIELD_32BIT IOT_AGENT_MQTT_ENABLE=1"
    )
    mcux_add_source(
        SOURCES inc/*.h
                ex/inc/iot_agent_demo_config.h
                ex/inc/iot_agent_mqtt_freertos.h
                ex/inc/iot_agent_network.h
                ex/src/utils/iot_agent_mqtt_freertos.c
                src/protobuf/*.h
                src/protobuf/pb_common.c
                src/protobuf/pb_decode.c
                src/protobuf/ServiceDescriptor.pb.c
        BASE_PATH ${SdkRootDirPath}/middleware/nxp_iot_agent/
    )
    mcux_add_include(
        INCLUDES inc
                 ex/inc
                 src/protobuf
        BASE_PATH ${SdkRootDirPath}/middleware/nxp_iot_agent/
    )
endif()

if(CONFIG_MCUX_COMPONENT_middleware.nxp_iot_agent.claimcode)
    mcux_add_source(
        SOURCES inc/*.h
                ex/inc/iot_agent_claimcode_encrypt.h
                ex/inc/iot_agent_demo_config.h
                ex/src/utils/iot_agent_claimcode_encrypt_els.c
        BASE_PATH ${SdkRootDirPath}/middleware/nxp_iot_agent/
    )
    mcux_add_include(
        INCLUDES inc
                 ex/inc
        BASE_PATH ${SdkRootDirPath}/middleware/nxp_iot_agent/
    )
endif()