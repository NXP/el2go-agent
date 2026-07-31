# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

include(add_target_sources)


# Credential provider and transport backend selection

if(BUILD_ZEPHYR)
    if(CONFIG_EL2GO_OTA_CRED_PSA)
        set(EL2GO_OTA_CRED "psa")
    endif()

    if(CONFIG_EL2GO_OTA_TRANSPORT_GRPC)
        set(EL2GO_OTA_TRANSPORT "grpc")
    endif()
else()
    set(EL2GO_OTA_CRED_PROVIDER "psa" CACHE STRING
        "OTA mTLS credential provider")
    set_property(CACHE EL2GO_OTA_CRED_PROVIDER PROPERTY STRINGS psa)

    set(EL2GO_OTA_TRANSPORT_BACKEND "grpc" CACHE STRING
        "OTA message transport backend")
    set_property(CACHE EL2GO_OTA_TRANSPORT_BACKEND PROPERTY STRINGS grpc)

    set(EL2GO_OTA_CRED      "${EL2GO_OTA_CRED_PROVIDER}")
    set(EL2GO_OTA_TRANSPORT "${EL2GO_OTA_TRANSPORT_BACKEND}")
endif()

message(STATUS "EL2GO OTA credential provider: ${EL2GO_OTA_CRED}")
message(STATUS "EL2GO OTA transport backend: ${EL2GO_OTA_TRANSPORT}")

if(NOT BUILD_ZEPHYR)
    project(el2go_ota_lib VERSION ${CMAKE_PROJECT_VERSION} LANGUAGES C)

    add_library(${PROJECT_NAME}
        el2go_ota_lib.c
    )

    add_subdirectory(src)

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
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
    )
else()
    add_private_sources(el2go_ota_lib
        el2go_ota_lib.c
    )

    add_subdirectory(src)
endif()

# Private include directories and link libraries — shared by both build
# systems via the add_target_sources.cmake macros.

add_private_directories(el2go_ota_lib
    ${PROJECT_ROOT}/priv
    ${PROJECT_ROOT}/include
    ${PROJECT_ROOT}/libs/osal/include
)

add_link_libraries(el2go_ota_lib
    PRIVATE
        el2go_ota_src
        el2go_ota_cred
        el2go_ota_download
        el2go_ota_osal
        el2go_ota_transport
        net_crypto
        el2go_platform
        osal
        ota_protobuf
        $<TARGET_PROPERTY:el2go_platform,INTERFACE_LINK_LIBRARIES>
)
