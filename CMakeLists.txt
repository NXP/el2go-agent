# Copyright 2019-2021, 2024-2025 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

cmake_minimum_required(VERSION 3.5)

PROJECT(nxp_iot_agent LANGUAGES C VERSION 6.2.0)

#define some variables which will be used in different places
set(exported_targets el2go_agent-targets)
set(config_install_dir lib/cmake/el2go_agent)
set(input_config_file ${CMAKE_CURRENT_SOURCE_DIR}/el2go_agent-config.cmake.in)
set(config_file ${CMAKE_CURRENT_BINARY_DIR}/el2go_agent-config.cmake)
set(version_config_file ${CMAKE_CURRENT_BINARY_DIR}/el2go_agent-config-version.cmake)
set(agent_include_build_dir ${CMAKE_CURRENT_SOURCE_DIR}/inc)
set(agent_include_install_dir include/el2go-agent/nxp-iot-agent/)
set(protobuf_include_build_dir ${CMAKE_CURRENT_SOURCE_DIR}/src/protobuf)
set(protobuf_include_install_dir include/el2go-agent/protobuf/)

IF(NOT COMMAND CREATE_BINARY)
    MACRO(CREATE_BINARY PROJECT_NAME)
    ENDMACRO()
ENDIF()


IF(SSS_HAVE_HOSTCRYPTO_OPENSSL)
    add_definitions(-DNXP_IOT_AGENT_HAVE_HOSTCRYPTO_OPENSSL=1 -DNXP_IOT_AGENT_HAVE_SSS=1)
ENDIF()

IF(SSS_HAVE_HOSTCRYPTO_MBEDTLS)
    add_definitions(-DNXP_IOT_AGENT_HAVE_HOSTCRYPTO_MBEDTLS=1)
    IF(SSS_HAVE_MBEDTLS_ALT_SSS)
        add_definitions(-DNXP_IOT_AGENT_HAVE_SSS=1)
    ELSEIF(SSS_HAVE_MBEDTLS_ALT_PSA)
        add_definitions(-DNXP_IOT_AGENT_HAVE_PSA=1)
        IF(NXP_IOT_AGENT_HAVE_PSA_IMPL_SMW)
            add_definitions(-DNXP_IOT_AGENT_HAVE_PSA_IMPL_SMW=1)
        ELSE()
            add_definitions(-DNXP_IOT_AGENT_HAVE_PSA_IMPL_SIMUL=1)
        ENDIF()
    ENDIF()
ENDIF()

IF(NXP_IOT_AGENT_ENABLE_SANDBOX_TEST)
    add_definitions(-DNXP_IOT_AGENT_ENABLE_SANDBOX_TEST=1)
ENDIF()

FILE(
    GLOB
    NXP_IOT_AGENT_FILES
    inc/*.h
    inc/*.h.in
    src/*.c
    src/*.h
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
        src/osal/win/*.h
        src/osal/win/*.h.in
        src/osal/win/*.c
    )

    set(NXP_IOT_AGENT_FILES ${NXP_IOT_AGENT_FILES} ${NXP_IOT_AGENT_WINDOWS_FILES})
ENDIF()


IF(SSS_HAVE_HOSTCRYPTO_OPENSSL)
    FILE(
    GLOB
        NXP_IOT_AGENT_OPENSSL_FILES
        net_crypto/openssl/*.h
        net_crypto/openssl/*.h.in
        net_crypto/openssl/*.c
    )

    set(NXP_IOT_AGENT_FILES ${NXP_IOT_AGENT_FILES} ${NXP_IOT_AGENT_OPENSSL_FILES})
ENDIF()

IF(SSS_HAVE_HOSTCRYPTO_MBEDTLS)
    FILE(
    GLOB
        NXP_IOT_AGENT_MBEDTLS_FILES
        net_crypto/mbedtls/network_mbedtls.h
        net_crypto/mbedtls/network_mbedtls.c
    )

    set(NXP_IOT_AGENT_FILES ${NXP_IOT_AGENT_FILES} ${NXP_IOT_AGENT_MBEDTLS_FILES})
ENDIF()

IF(SSS_HAVE_HOST_FRDMK64F OR SSS_HAVE_HOST_EVKMIMXRT1060 OR SSS_HAVE_HOST_EVKMIMXRT1170)
    FILE(
    GLOB
    NXP_IOT_AGENT_PORT_FILES
    net_crypto/mbedtls/net_lwip.c
    )

    SET(NXP_IOT_AGENT_FILES ${NXP_IOT_AGENT_FILES} ${NXP_IOT_AGENT_PORT_FILES})
ENDIF()

IF(SSS_HAVE_HOST_LPCXPRESSO55S)
    FILE(
    GLOB
    NXP_IOT_AGENT_PORT_FILES
    net_crypto/mbedtls/net_lpc_mwm.c
    )

    SET(NXP_IOT_AGENT_FILES ${NXP_IOT_AGENT_FILES} ${NXP_IOT_AGENT_PORT_FILES})
ENDIF()

IF(SSS_HAVE_HOSTCRYPTO_OPENSSL OR (SSS_HAVE_HOSTCRYPTO_MBEDTLS AND SSS_HAVE_MBEDTLS_ALT_SSS))
    set(NXP_IOT_AGENT_FILES ${NXP_IOT_AGENT_FILES} platform/se05x/nxp_iot_agent_platform_se05x.c)
    set(NXP_IOT_AGENT_FILES ${NXP_IOT_AGENT_FILES} platform/se05x/nxp_iot_agent_time_se05x.c)
    set(NXP_IOT_AGENT_FILES ${NXP_IOT_AGENT_FILES} platform/se05x/nxp_iot_agent_session.c)
    set(NXP_IOT_AGENT_FILES ${NXP_IOT_AGENT_FILES} platform/se05x/nxp_iot_agent_session.h)
    set(NXP_IOT_AGENT_FILES ${NXP_IOT_AGENT_FILES} src/keystore/sss/nxp_iot_agent_keystore_sss_se05x.c)
    set(NXP_IOT_AGENT_FILES ${NXP_IOT_AGENT_FILES} src/keystore/sss/nxp_iot_agent_keystore_sss_se05x.h)
    set(NXP_IOT_AGENT_FILES ${NXP_IOT_AGENT_FILES} src/keystore/sss/nxp_iot_agent_macros_sss.h)
ENDIF()

IF(SSS_HAVE_HOSTCRYPTO_MBEDTLS AND SSS_HAVE_MBEDTLS_ALT_PSA)
    set(NXP_IOT_AGENT_FILES ${NXP_IOT_AGENT_FILES} src/keystore/psa/nxp_iot_agent_keystore_psa.c)
    set(NXP_IOT_AGENT_FILES ${NXP_IOT_AGENT_FILES} src/keystore/psa/nxp_iot_agent_keystore_psa.h)
    set(NXP_IOT_AGENT_FILES ${NXP_IOT_AGENT_FILES} src/keystore/psa/nxp_iot_agent_macros_psa.h)
    IF(NOT NXP_IOT_AGENT_HAVE_PSA_IMPL_SMW)
        set(NXP_IOT_AGENT_FILES ${NXP_IOT_AGENT_FILES} ex/src/utils/mbedtls_psa/psa_crypto_wrapper.c)
        IF(SSS_HAVE_HOST_PCWINDOWS OR SSS_HAVE_HOST_PCLINUX)
            # PSA simulators
            add_definitions(-DIOT_AGENT_TIME_MEASUREMENT_ENABLE=0)
            set(NXP_IOT_AGENT_FILES ${NXP_IOT_AGENT_FILES} platform/psa_simul/nxp_iot_agent_platform_psa_simul.c)
            set(NXP_IOT_AGENT_FILES ${NXP_IOT_AGENT_FILES} platform/psa_simul/nxp_iot_agent_time_psa_simul.c)
        ELSE()
            set(NXP_IOT_AGENT_FILES ${NXP_IOT_AGENT_FILES} platform/tfm/nxp_iot_agent_platform_tfm.c)
            set(NXP_IOT_AGENT_FILES ${NXP_IOT_AGENT_FILES} platform/tfm/nxp_iot_agent_time_tfm.c)
        ENDIF()
    ENDIF()
ENDIF()

IF(NXP_IOT_AGENT_HAVE_PSA_IMPL_SMW)
    add_definitions(-DIOT_AGENT_TIME_MEASUREMENT_ENABLE=0)
    set(NXP_IOT_AGENT_FILES ${NXP_IOT_AGENT_FILES} platform/smw/nxp_iot_agent_platform_smw.c)
    set(NXP_IOT_AGENT_FILES ${NXP_IOT_AGENT_FILES} platform/smw/nxp_iot_agent_time_smw.c)
    set(NXP_IOT_AGENT_FILES ${NXP_IOT_AGENT_FILES} platform/smw/device_mgr.c)
    set(NXP_IOT_AGENT_FILES ${NXP_IOT_AGENT_FILES} src/datastore/fs/nxp_iot_agent_datastore_fs.c)
    set(NXP_IOT_AGENT_FILES ${NXP_IOT_AGENT_FILES} src/datastore/fs/nxp_iot_agent_datastore_fs.h)
ENDIF()

IF(SSS_HAVE_HOST_PCWINDOWS OR SSS_HAVE_HOST_PCLINUX OR SSS_HAVE_HOST_IMXLINUX OR SSS_HAVE_HOST_RASPBIAN)
    set(NXP_IOT_AGENT_FILES ${NXP_IOT_AGENT_FILES} src/datastore/fs/nxp_iot_agent_datastore_fs.c)
    set(NXP_IOT_AGENT_FILES ${NXP_IOT_AGENT_FILES} src/datastore/fs/nxp_iot_agent_datastore_fs.h)
ENDIF()

IF(SSS_HAVE_HOST_FRDMK64F OR SSS_HAVE_HOST_EVKMIMXRT1060 OR SSS_HAVE_HOST_EVKMIMXRT1170 OR SSS_HAVE_HOST_LPCXPRESSO55S)
    set(NXP_IOT_AGENT_FILES ${NXP_IOT_AGENT_FILES} src/datastore/plain/nxp_iot_agent_datastore_plain.c)
    set(NXP_IOT_AGENT_FILES ${NXP_IOT_AGENT_FILES} src/datastore/plain/nxp_iot_agent_datastore_plain.h)
ENDIF()

IF (NXP_IOT_AGENT_HAVE_PSA_IMPL_SMW)
    ADD_LIBRARY(nxp_iot_agent SHARED ${NXP_IOT_AGENT_FILES})
    set_target_properties(${PROJECT_NAME} PROPERTIES
        C_STANDARD 99
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR})
ELSE()
    ADD_LIBRARY(${PROJECT_NAME} ${NXP_IOT_AGENT_FILES})
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

# For public interfaces, distinguish between the build and install paths
TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PUBLIC
    $<BUILD_INTERFACE:${agent_include_build_dir}>
    $<INSTALL_INTERFACE:${agent_include_install_dir}>
)

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PUBLIC
    $<BUILD_INTERFACE:${protobuf_include_build_dir}>
    $<INSTALL_INTERFACE:${protobuf_include_install_dir}>
)

# Private include directories doesn't need a install interface
TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/platform>
)

IF(SSS_HAVE_KSDK)
    TARGET_INCLUDE_DIRECTORIES(${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/port/ksdk>)
ELSE()
    TARGET_INCLUDE_DIRECTORIES(${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/port/default>)
ENDIF()


IF(SSS_HAVE_HOSTCRYPTO_OPENSSL OR (SSS_HAVE_HOSTCRYPTO_MBEDTLS AND SSS_HAVE_MBEDTLS_ALT_SSS))
    TARGET_INCLUDE_DIRECTORIES(
        ${PROJECT_NAME}
        PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/keystore/sss/>
        PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/platform/se05x/>
    )
ENDIF()

IF(SSS_HAVE_HOSTCRYPTO_MBEDTLS AND SSS_HAVE_MBEDTLS_ALT_PSA)
    TARGET_INCLUDE_DIRECTORIES(${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/keystore/psa/>)
    IF(NOT NXP_IOT_AGENT_HAVE_PSA_IMPL_SMW)
        TARGET_INCLUDE_DIRECTORIES(${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/ex/inc/mbedtls_psa>)
    ENDIF()
ENDIF()

IF(NXP_IOT_AGENT_HAVE_PSA_IMPL_SMW)
    TARGET_INCLUDE_DIRECTORIES(${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/datastore/fs/>)
	TARGET_INCLUDE_DIRECTORIES(${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/platform/smw>)

    FIND_PACKAGE(NXP_SMW CONFIG REQUIRED)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} $<BUILD_INTERFACE:NXP_SMW::smw>)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} $<BUILD_INTERFACE:pthread>)

    FIND_PACKAGE(MbedTLS CONFIG REQUIRED)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} $<BUILD_INTERFACE:MbedTLS::mbedtls>)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} $<BUILD_INTERFACE:MbedTLS::mbedx509>)

    ADD_SUBDIRECTORY(src/common)
ENDIF()


IF(SSS_HAVE_HOST_PCWINDOWS OR SSS_HAVE_HOST_PCLINUX OR SSS_HAVE_HOST_IMXLINUX OR SSS_HAVE_HOST_RASPBIAN)
    TARGET_INCLUDE_DIRECTORIES(${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/datastore/fs/>)
ENDIF()

IF(SSS_HAVE_HOST_FRDMK64F OR SSS_HAVE_HOST_EVKMIMXRT1060 OR SSS_HAVE_HOST_EVKMIMXRT1170 OR SSS_HAVE_HOST_LPCXPRESSO55S)
    TARGET_INCLUDE_DIRECTORIES(${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/datastore/plain/>)
ENDIF()

IF(SSS_HAVE_HOSTCRYPTO_MBEDTLS AND NOT NXP_IOT_AGENT_HAVE_PSA_IMPL_SMW)
    IF (SSS_HAVE_MBEDTLS_ALT_PSA)
        TARGET_LINK_LIBRARIES(${PROJECT_NAME} $<BUILD_INTERFACE:mbedtls_psa>)
    ELSE()
        TARGET_LINK_LIBRARIES(${PROJECT_NAME} $<BUILD_INTERFACE:mbedtls>)
    ENDIF()
ENDIF()

IF(SSS_HAVE_HOST_PCWINDOWS OR SSS_HAVE_HOST_WIN10IOT)
    TARGET_INCLUDE_DIRECTORIES(${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/osal/win>
    )
ENDIF()


IF(SSS_HAVE_HOSTCRYPTO_OPENSSL)

    FIND_PACKAGE(OpenSSL REQUIRED)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME}
        $<BUILD_INTERFACE:OpenSSL::SSL>
        $<BUILD_INTERFACE:OpenSSL::Crypto>
    )

    IF(SSS_HAVE_OPENSSL_3_0)
        TARGET_LINK_LIBRARIES(${PROJECT_NAME} $<BUILD_INTERFACE:sssProvider>)
        TARGET_INCLUDE_DIRECTORIES(${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:${SIMW_TOP_DIR}/sss/plugin/openssl_provider/provider>)
    ENDIF()

    IF(SSS_HAVE_HOST_PCWINDOWS)
        TARGET_LINK_LIBRARIES(${PROJECT_NAME} $<BUILD_INTERFACE:crypt32>)
    ENDIF()

    TARGET_INCLUDE_DIRECTORIES(${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/net_crypto/openssl>)

    TARGET_COMPILE_DEFINITIONS(${PROJECT_NAME} PRIVATE OPENSSL_LOAD_CONF)

ENDIF()

IF(SSS_HAVE_HOSTCRYPTO_MBEDTLS)
    TARGET_INCLUDE_DIRECTORIES(${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/net_crypto/mbedtls>)
ENDIF()

IF(SSS_HAVE_APPLET_SE05X_IOT)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME}
        $<BUILD_INTERFACE:smCom>
        $<BUILD_INTERFACE:ex_common>
        $<BUILD_INTERFACE:SSS_APIs>
        $<BUILD_INTERFACE:se05x>
    )
ENDIF()

TARGET_COMPILE_DEFINITIONS(${PROJECT_NAME} PRIVATE PB_FIELD_32BIT)

IF (WIN32)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} $<BUILD_INTERFACE:ws2_32>)
ENDIF()

TARGET_LINK_LIBRARIES(${PROJECT_NAME} nxp_iot_agent_common)

ADD_SUBDIRECTORY(ex)

IF(SSS_HAVE_RTOS_DEFAULT AND NXPInternal)
    ADD_SUBDIRECTORY(tst)
ENDIF()

IF(SSS_HAVE_HOST_LINUX_LIKE OR NXP_IOT_AGENT_HAVE_PSA_IMPL_SMW)
    FILE(GLOB
        NXP_IOT_AGENT_PUBLIC_FILES
        inc/*.h)

    FILE(GLOB
        NXP_IOT_AGENT_COMMON_PROTOBUF_HEADERS
        src/protobuf/*.h)

    # Create the agent config and version files and install them
    include(CMakePackageConfigHelpers)
    configure_package_config_file(
        ${input_config_file}
        ${config_file}
        INSTALL_DESTINATION "${config_install_dir}"
    )

    write_basic_package_version_file(
        ${version_config_file}
        COMPATIBILITY AnyNewerVersion
    )

    INSTALL(
        TARGETS ${PROJECT_NAME}
        EXPORT ${exported_targets}
        DESTINATION lib
    )

    INSTALL(FILES ${NXP_IOT_AGENT_PUBLIC_FILES} DESTINATION ${agent_include_install_dir})
    INSTALL(FILES ${NXP_IOT_AGENT_COMMON_PROTOBUF_HEADERS} DESTINATION ${protobuf_include_install_dir})
    INSTALL(FILES ${config_file} ${version_config_file} DESTINATION "${config_install_dir}")
    INSTALL(EXPORT ${exported_targets} NAMESPACE el2go_agent:: DESTINATION "${config_install_dir}")

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
