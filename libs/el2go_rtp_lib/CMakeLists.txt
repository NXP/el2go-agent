# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

cmake_minimum_required(VERSION ${CMAKE_MINIMUM_REQUIRED_VERSION})
project(el2go_rtp VERSION ${CMAKE_PROJECT_VERSION} LANGUAGES C)

include(add_target_sources)

if(BUILD_ZEPHYR)
    # ========================================================================
    # ZEPHYR BUILD -- use the standard zephyr_library model so objects are
    # compiled with the correct MCU flags and linked into the Zephyr image.
    # ========================================================================
    zephyr_library_named(el2go_rtp)

    zephyr_library_sources(
        el2go_rtp.c
        el2go_rtp_dispatcher.c
        el2go_agent_endpoint.c
        el2go_rtp_status_report.c
    )

    zephyr_library_include_directories(
        ${PROJECT_ROOT}/priv
        ${PROJECT_ROOT}/libs/osal/include
        ${PROJECT_ROOT}/libs/protobuf/nanopb
        ${PROJECT_ROOT}/libs/protobuf/el2go
        ${PROJECT_ROOT}/libs/net_crypto
        ${PROJECT_ROOT}/libs/platforms
        ${PROJECT_ROOT}/libs/protobuf/utils
        ${PROJECT_ROOT}/libs/common
        ${PROJECT_ROOT}/libs/keystores
        ${PROJECT_ROOT}/libs/datastores
        ${CMAKE_CURRENT_SOURCE_DIR}
    )

    # Public include root so consumers can do #include <rtp/el2go_rtp.h>
    zephyr_include_directories(${PROJECT_ROOT}/include)

else()
    # ========================================================================
    # NON-ZEPHYR BUILD -- plain CMake STATIC library exported via install().
    # ========================================================================
    add_library(${PROJECT_NAME}
        el2go_rtp.c
        el2go_rtp_dispatcher.c
        el2go_agent_endpoint.c
        el2go_rtp_status_report.c
    )

    set_target_properties(${PROJECT_NAME} PROPERTIES
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
        C_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN ON
    )

    target_include_directories(${PROJECT_NAME} PUBLIC
        $<BUILD_INTERFACE:${PROJECT_ROOT}/include>
        $<INSTALL_INTERFACE:include>
    )

    target_include_directories(${PROJECT_NAME} PRIVATE
        ${PROJECT_ROOT}/priv
        ${PROJECT_ROOT}/libs/osal/include
        ${PROJECT_ROOT}/libs/protobuf/nanopb
        ${PROJECT_ROOT}/libs/protobuf/el2go
        ${PROJECT_ROOT}/libs/net_crypto
        ${PROJECT_ROOT}/libs/platforms
        ${PROJECT_ROOT}/libs/protobuf/utils
        ${PROJECT_ROOT}/libs/common
        ${PROJECT_ROOT}/libs/keystores
        ${PROJECT_ROOT}/libs/datastores
        ${CMAKE_CURRENT_SOURCE_DIR}
    )

    target_link_libraries(${PROJECT_NAME}
        PRIVATE
            el2go_platform
            el2go_keystore
            el2go_datastore
            osal
            el2go_protobuf
            pb_utils
            net_crypto
            el2go_common
            $<TARGET_PROPERTY:el2go_platform,INTERFACE_LINK_LIBRARIES>
    )

    # ========================================================================
    # INSTALLATION
    # ========================================================================
    install(TARGETS ${PROJECT_NAME}
        EXPORT ${PROJECT_NAME}-targets
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )

    install(FILES
        ${CMAKE_SOURCE_DIR}/include/common/el2go_datastore.h
        ${CMAKE_SOURCE_DIR}/include/common/el2go_keystore.h
        ${CMAKE_SOURCE_DIR}/include/common/el2go_platform.h
        ${CMAKE_SOURCE_DIR}/include/common/el2go_status.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/common
    )

    install(FILES
        ${CMAKE_SOURCE_DIR}/include/rtp/el2go_rtp_config.h
        ${CMAKE_SOURCE_DIR}/include/rtp/el2go_rtp.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/rtp
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
endif()
