# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

include(add_target_sources)

set(EL2GO_OTA_CRED_PROVIDER "psa" CACHE STRING
    "OTA mTLS credential provider: psa")

set(EL2GO_OTA_TRANSPORT_BACKEND "grpc" CACHE STRING
    "OTA message transport backend: grpc")

if(EL2GO_OTA_CRED_PROVIDER STREQUAL "psa")
    set(EL2GO_OTA_CRED_SOURCE src/cred/el2go_ota_cred_psa.c)
else()
    message(FATAL_ERROR
        "Unknown EL2GO_OTA_CRED_PROVIDER '${EL2GO_OTA_CRED_PROVIDER}'. "
        "Valid values: psa. See src/cred/el2go_ota_cred.h to add a new provider.")
endif()

if(EL2GO_OTA_TRANSPORT_BACKEND STREQUAL "grpc")
    set(EL2GO_OTA_TRANSPORT_SOURCE
        src/transport/grpc/el2go_ota_grpc.c
        src/transport/el2go_ota_transport_init.c)
else()
    message(FATAL_ERROR
        "Unknown EL2GO_OTA_TRANSPORT_BACKEND '${EL2GO_OTA_TRANSPORT_BACKEND}'. "
        "Valid values: grpc. See src/transport/ to add a new backend.")
endif()

# Fallback implementation always compiled; Zephyr adds the strong NVS override.
set(EL2GO_OTA_KVS_FALLBACK src/osal/el2go_ota_kvs.c)
if(BUILD_ZEPHYR)
    set(EL2GO_OTA_KVS_SOURCE src/osal/zephyr/el2go_ota_kvs_zephyr.c)
else()
    set(EL2GO_OTA_KVS_SOURCE "")
endif()

message(STATUS "EL2GO OTA credential provider:  ${EL2GO_OTA_CRED_PROVIDER}")
message(STATUS "EL2GO OTA transport backend:    ${EL2GO_OTA_TRANSPORT_BACKEND}")

# ---------------------------------------------------------------------------
# Linux-only: create the full shared/static library target with versioning
# and install rules. In Zephyr the target is managed by the Zephyr build
# system; only sources and include dirs are contributed below.
# ---------------------------------------------------------------------------
if(NOT BUILD_ZEPHYR)
    project(el2go_ota_lib VERSION ${CMAKE_PROJECT_VERSION} LANGUAGES C)

    add_library(${PROJECT_NAME}
        el2go_ota_lib.c
        src/el2go_ota_tls.c
        src/el2go_ota_request_builder.c
        src/el2go_ota_response_handler.c
        src/el2go_ota_status_reporting.c
        src/download/el2go_ota_download_engine.c
        ${EL2GO_OTA_TRANSPORT_SOURCE}
        ${EL2GO_OTA_KVS_FALLBACK}
        ${EL2GO_OTA_KVS_SOURCE}
        ${CMAKE_CURRENT_SOURCE_DIR}/../protobuf/ota/ota_delivery.pb.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../protobuf/nanopb/pb_common.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../protobuf/nanopb/pb_decode.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../protobuf/nanopb/pb_encode.c
        ${EL2GO_OTA_CRED_SOURCE}
    )

    set_target_properties(${PROJECT_NAME} PROPERTIES
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
        C_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN ON
    )

    target_include_directories(${PROJECT_NAME}
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
            $<INSTALL_INTERFACE:include>
    )

    install(TARGETS ${PROJECT_NAME}
        EXPORT ${PROJECT_NAME}-targets
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )

    install(FILES
        ${CMAKE_SOURCE_DIR}/include/ota/el2go_ota_lib.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/ota
    )

    install(EXPORT ${PROJECT_NAME}-targets
        FILE ${PROJECT_NAME}-targets.cmake
        NAMESPACE el2go::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
    )

    include(CMakePackageConfigHelpers)

    configure_package_config_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/${PROJECT_NAME}-config.cmake.in
        ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config.cmake
        INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
    )

    write_basic_package_version_file(
        ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config-version.cmake
        VERSION ${PROJECT_VERSION}
        COMPATIBILITY SameMajorVersion
    )

    install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config-version.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/el2go_ota_lib
    )
else()
    add_private_sources(el2go_ota_lib
        el2go_ota_lib.c
        src/el2go_ota_tls.c
        src/el2go_ota_request_builder.c
        src/el2go_ota_response_handler.c
        src/el2go_ota_status_reporting.c
        src/download/el2go_ota_download_engine.c
        ${EL2GO_OTA_TRANSPORT_SOURCE}
        ${EL2GO_OTA_KVS_FALLBACK}
        ${EL2GO_OTA_KVS_SOURCE}
        ${EL2GO_OTA_CRED_SOURCE}
    )
endif()

# ---------------------------------------------------------------------------
# Private include directories and link libraries — shared by both build
# systems via the add_target_sources.cmake macros.
# ---------------------------------------------------------------------------
add_private_directories(el2go_ota_lib
    ${CMAKE_CURRENT_SOURCE_DIR}/../../priv
    ${CMAKE_CURRENT_SOURCE_DIR}/../osal/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../net_crypto
    ${CMAKE_CURRENT_SOURCE_DIR}/../platforms
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cred
    ${CMAKE_CURRENT_SOURCE_DIR}/src/transport
    ${CMAKE_CURRENT_SOURCE_DIR}/src/osal
    ${CMAKE_CURRENT_SOURCE_DIR}/src/download
    ${CMAKE_CURRENT_SOURCE_DIR}/../protobuf/ota
    ${CMAKE_CURRENT_SOURCE_DIR}/../protobuf/nanopb
)

add_link_libraries(el2go_ota_lib
    PRIVATE
        net_crypto
        el2go_platform
        osal
        ota_protobuf
        $<TARGET_PROPERTY:el2go_platform,INTERFACE_LINK_LIBRARIES>
)
