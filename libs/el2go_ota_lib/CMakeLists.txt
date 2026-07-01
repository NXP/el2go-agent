# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

include(add_target_sources)

set(EL2GO_OTA_CRED_PROVIDER "psa" CACHE STRING
    "OTA mTLS credential provider: psa")

if(EL2GO_OTA_CRED_PROVIDER STREQUAL "psa")
    set(EL2GO_OTA_CRED_SOURCE src/cred/el2go_ota_cred_psa.c)
else()
    message(FATAL_ERROR
        "Unknown EL2GO_OTA_CRED_PROVIDER '${EL2GO_OTA_CRED_PROVIDER}'. "
        "Valid values: psa. See src/cred/el2go_ota_cred.h to add a new provider.")
endif()

message(STATUS "EL2GO OTA credential provider: ${EL2GO_OTA_CRED_PROVIDER}")

set(EL2GO_OTA_LIB_SOURCES
    el2go_ota_lib.c
    src/el2go_ota_tls.c
    ${EL2GO_OTA_CRED_SOURCE}
)

if(NOT BUILD_ZEPHYR)
    project(el2go_ota_lib VERSION ${CMAKE_PROJECT_VERSION} LANGUAGES C)

    add_library(${PROJECT_NAME} ${EL2GO_OTA_LIB_SOURCES})

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
        PRIVATE
            ${CMAKE_SOURCE_DIR}/priv
            ${CMAKE_SOURCE_DIR}/libs/osal/include
            ${CMAKE_SOURCE_DIR}/libs/net_crypto
            ${CMAKE_SOURCE_DIR}/libs/platforms
            ${CMAKE_SOURCE_DIR}/libs/platforms/${PLATFORM}
            ${CMAKE_CURRENT_SOURCE_DIR}/src
            ${CMAKE_CURRENT_SOURCE_DIR}/src/cred
    )

    target_link_libraries(${PROJECT_NAME}
        PRIVATE
            net_crypto
            el2go_platform
            osal
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
    add_private_sources(el2go_ota_lib ${EL2GO_OTA_LIB_SOURCES})

    add_private_directories(el2go_ota_lib
        ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/priv
        ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/osal/include
        ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/net_crypto
        ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/platforms
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/src/cred
    )
endif()
