# Copyright 2019-2021, 2024 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

IF(CONFIG_MCUX_NXP_IOT_AGENT)

add_subdirectory_ifdef(CONFIG_EL2GO_BLOB_TEST ex/src/apps/psa_examples/el2go_blob_test)

add_subdirectory_ifdef(CONFIG_EL2GO_IMPORT_BLOB ex/src/apps/psa_examples/el2go_import_blob)

if(CONFIG_EL2GO_AGENT_DEMO_WIFI)
    target_compile_definitions(app PRIVATE
        PB_FIELD_32BIT
        EXTERNAL_CUSTOMER_BUILD_CONFIGURATION=1
        AX_EMBEDDED=1
        USE_RTOS=1
        SSS_USE_FTR_FILE
        NXP_IOT_AGENT_HAVE_PSA_IMPL_TFM=1
    )

    target_sources(app PRIVATE
        ex/src/iot_agent_demo.c
    )

    target_sources(app PRIVATE
        ex/src/utils/iot_agent_claimcode_import.c
        ex/src/utils/mbedtls_psa/iot_agent_psa_sign_test.c
    )

    target_sources(app PRIVATE
        ex/src/network/iot_agent_network_zephyr_wifi.c
        ex/src/utils/iot_agent_mqtt_zephyr.c
        platform/mbedtls/net_zephyr.c
        platform/mbedtls/network_mbedtls.c
    )

    FILE(GLOB main_sources src/*.c)
    target_sources(app PRIVATE ${main_sources})
    FILE(GLOB common_sources src/common/*.c)
    target_sources(app PRIVATE ${common_sources})
    FILE(GLOB protobuf_sources src/protobuf/*.c)
    target_sources(app PRIVATE ${protobuf_sources})

    zephyr_include_directories(inc)
    zephyr_include_directories(ex/inc)
    zephyr_include_directories(ex/inc/mbedtls_psa)
    zephyr_include_directories(platform)
    zephyr_include_directories(platform/mbedtls)
    zephyr_include_directories(platform/tfm)
    zephyr_include_directories(src/protobuf)
endif()

if(CONFIG_EL2GO_CLAIMCODE_APP)
    target_compile_definitions(app PRIVATE
        EXTERNAL_CUSTOMER_BUILD_CONFIGURATION=1
        SSS_USE_FTR_FILE
    )

    target_sources(app PRIVATE
        ex/src/apps/el2go_claimcode_encryption.c
        ex/src/utils/iot_agent_claimcode_encrypt_els.c
    )

    zephyr_include_directories(inc)
    zephyr_include_directories(ex/inc)
endif()

ELSE() # IF(CONFIG_MCUX_NXP_IOT_AGENT)

cmake_minimum_required(VERSION 3.5)

PROJECT(nxp_iot_agent LANGUAGES C)

IF(NOT COMMAND CREATE_BINARY)
    MACRO(CREATE_BINARY PROJECT_NAME)
    ENDMACRO()
ENDIF()

IF(NXP_IOT_AGENT_HAVE_PSA_IMPL_SMW)
    add_definitions(-DNXP_IOT_AGENT_HAVE_PSA_IMPL_SMW)
ENDIF()

FILE(
    GLOB
    NXP_IOT_AGENT_FILES
    inc/*.h
    inc/*.h.in
    src/*.c
    src/protobuf/*.h
    src/protobuf/*.c
)

IF(SSS_HAVE_APPLET_A71CH)
    MESSAGE(FATAL_ERROR "A71CH is not supported anymore for nxp_iot_agent!!!")
ENDIF()

IF(SSS_HAVE_HOST_PCWINDOWS)
    FILE(
    GLOB
        NXP_IOT_AGENT_WINDOWS_FILES
        platform/windows/*.h
        platform/windows/*.h.in
        platform/windows/*.c
    )

    set(NXP_IOT_AGENT_FILES ${NXP_IOT_AGENT_FILES} ${NXP_IOT_AGENT_WINDOWS_FILES})
ENDIF()


IF(SSS_HAVE_HOSTCRYPTO_OPENSSL)
    FILE(
    GLOB
        NXP_IOT_AGENT_OPENSSL_FILES
        platform/openssl/*.h
        platform/openssl/*.h.in
        platform/openssl/*.c
    )

    set(NXP_IOT_AGENT_FILES ${NXP_IOT_AGENT_FILES} ${NXP_IOT_AGENT_OPENSSL_FILES})
ENDIF()

IF(SSS_HAVE_HOSTCRYPTO_MBEDTLS)
    FILE(
    GLOB
        NXP_IOT_AGENT_MBEDTLS_FILES
        platform/mbedtls/network_mbedtls.h
        platform/mbedtls/network_mbedtls.c
    )

    set(NXP_IOT_AGENT_FILES ${NXP_IOT_AGENT_FILES} ${NXP_IOT_AGENT_MBEDTLS_FILES})
ENDIF()

IF(SSS_HAVE_HOST_FRDMK64F OR SSS_HAVE_HOST_EVKMIMXRT1060 OR SSS_HAVE_HOST_EVKMIMXRT1170)
    FILE(
    GLOB
    NXP_IOT_AGENT_PORT_FILES
    platform/mbedtls/net_lwip.c
    )

    SET(NXP_IOT_AGENT_FILES ${NXP_IOT_AGENT_FILES} ${NXP_IOT_AGENT_PORT_FILES})
ENDIF()

IF(SSS_HAVE_HOST_LPCXPRESSO55S)
    FILE(
    GLOB
    NXP_IOT_AGENT_PORT_FILES
    platform/mbedtls/net_lpc_mwm.c
    )

    SET(NXP_IOT_AGENT_FILES ${NXP_IOT_AGENT_FILES} ${NXP_IOT_AGENT_PORT_FILES})
ENDIF()

IF(SSS_HAVE_MBEDTLS_ALT_PSA AND NOT NXP_IOT_AGENT_HAVE_PSA_IMPL_SMW)
    # TODO: remove this once the unwrapping is part of mbedtls.
    set(NXP_IOT_AGENT_FILES ${NXP_IOT_AGENT_FILES} ex/src/utils/mbedtls_psa/psa_crypto_wrapper.c)
ENDIF()

IF(NXP_IOT_AGENT_HAVE_PSA_IMPL_SMW)
    set(NXP_IOT_AGENT_FILES ${NXP_IOT_AGENT_FILES} platform/smw/device_mgr.c)
ENDIF()

ADD_LIBRARY(nxp_iot_agent ${NXP_IOT_AGENT_FILES})

IF(SSS_HAVE_MBEDTLS_ALT_PSA AND NOT NXP_IOT_AGENT_HAVE_PSA_IMPL_SMW)
    # TODO: remove this once the unwrapping is part of mbedtls.
    TARGET_INCLUDE_DIRECTORIES(nxp_iot_agent PUBLIC ex/inc/mbedtls_psa)
ENDIF()

IF(
    CMAKE_CXX_COMPILER
    MATCHES
    ".*clang"
    OR CMAKE_CXX_COMPILER_ID
       STREQUAL
       "AppleClang"
)
    TARGET_COMPILE_OPTIONS(
    ${PROJECT_NAME}
    PUBLIC -Wno-format
    PUBLIC -Wno-error=format)
ENDIF()

TARGET_INCLUDE_DIRECTORIES(
    nxp_iot_agent
    PUBLIC inc
    PUBLIC platform
    PUBLIC src/protobuf
)

IF(SSS_HAVE_KSDK)
    TARGET_INCLUDE_DIRECTORIES(
    nxp_iot_agent
    PUBLIC port/ksdk
    )
ELSE()
    TARGET_INCLUDE_DIRECTORIES(
    nxp_iot_agent
    PUBLIC port/default
    )
ENDIF()

IF(SSS_HAVE_HOSTCRYPTO_MBEDTLS AND NOT NXP_IOT_AGENT_HAVE_PSA_IMPL_SMW)
    IF (SSS_HAVE_MBEDTLS_ALT_PSA)
        TARGET_LINK_LIBRARIES(
            nxp_iot_agent
            mbedtls_psa
        )
    ELSE()
    TARGET_LINK_LIBRARIES(
    nxp_iot_agent
    mbedtls
    )
    ENDIF()
ENDIF()

IF(NXP_IOT_AGENT_HAVE_PSA_IMPL_SMW)
    TARGET_INCLUDE_DIRECTORIES(${PROJECT_NAME}
    PUBLIC platform/smw
    )

    FIND_PACKAGE(NXP_SMW CONFIG REQUIRED)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} NXP_SMW::smw)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} pthread)

    FIND_PACKAGE(MbedTLS CONFIG REQUIRED)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} MbedTLS::mbedtls)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} MbedTLS::mbedx509)

    ADD_SUBDIRECTORY(src/common)
ENDIF()


IF(SSS_HAVE_HOST_PCWINDOWS OR SSS_HAVE_HOST_WIN10IOT)
    TARGET_INCLUDE_DIRECTORIES(
    nxp_iot_agent
    PUBLIC platform/windows
    )
ENDIF()


IF(SSS_HAVE_HOSTCRYPTO_OPENSSL)
    TARGET_LINK_LIBRARIES(
    nxp_iot_agent
    ${OPENSSL_LIBRARIES}
    )

    IF(SSS_HAVE_HOST_PCWINDOWS)
    TARGET_LINK_LIBRARIES(
        nxp_iot_agent
        crypt32
    )
    ENDIF()

    TARGET_INCLUDE_DIRECTORIES(
    nxp_iot_agent
    PUBLIC platform/openssl
    )

    TARGET_COMPILE_DEFINITIONS(nxp_iot_agent PRIVATE OPENSSL_LOAD_CONF)

ENDIF()

IF(SSS_HAVE_HOSTCRYPTO_MBEDTLS)
    TARGET_LINK_LIBRARIES(
    nxp_iot_agent
    )

    TARGET_INCLUDE_DIRECTORIES(
    nxp_iot_agent
    PUBLIC platform/mbedtls
    )

ENDIF()

IF(SSS_HAVE_APPLET_SE05X_IOT)
    TARGET_LINK_LIBRARIES(
    nxp_iot_agent
    smCom
    ex_common
    SSS_APIs
    se05x
    )
ENDIF()


TARGET_COMPILE_DEFINITIONS(nxp_iot_agent PRIVATE PB_FIELD_32BIT)

IF (WIN32)
    SET(LIBS_SYSTEM ws2_32)
ENDIF()

TARGET_LINK_LIBRARIES(
    nxp_iot_agent
    nxp_iot_agent_common
    ${LIBS_SYSTEM}
)

ADD_SUBDIRECTORY(ex)

IF(SSS_HAVE_RTOS_DEFAULT AND NXPInternal)
    ADD_SUBDIRECTORY(tst)
ENDIF()

IF(SSS_HAVE_HOST_PCLINUX OR SSS_HAVE_HOST_IMXLINUX)
    INSTALL(TARGETS nxp_iot_agent DESTINATION lib)
ENDIF()

IF("${CMAKE_CXX_COMPILER_ID}" MATCHES "MSVC")
    TARGET_COMPILE_OPTIONS(
    ${PROJECT_NAME}
    PUBLIC
        /wd4267 # '=': conversion from 'size_t' to 'int', possible loss of data
    PUBLIC
        /wd4477 #  'printf' : format string '%d' requires an argument of type 'int', but variadic argument 1 has type 'size_t'
        PUBLIC
        /wd4127 # conditional expression is constant
    )
ENDIF()

# TODO: Get rid of -Wno-format -Wno-format-security

IF("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
  TARGET_COMPILE_OPTIONS(
    ${PROJECT_NAME}
    PRIVATE -Wno-error=format
    PRIVATE -Wno-format
    PRIVATE -Wno-error=format-security
    PRIVATE -Wno-format-security
    PRIVATE -Wno-address-of-packed-member
    PRIVATE -Wno-incompatible-pointer-types
    )
ENDIF()
ENDIF() # IF(CONFIG_MCUX_NXP_IOT_AGENT)
