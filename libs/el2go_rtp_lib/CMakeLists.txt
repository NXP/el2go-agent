# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

include(add_target_sources)

cmake_minimum_required(VERSION ${CMAKE_MINIMUM_REQUIRED_VERSION})

if(NOT BUILD_ZEPHYR)
    # ========================================================================
    # NON-ZEPHYR BUILD -- plain CMake STATIC library exported via install().
    # ========================================================================
    project(el2go_rtp VERSION ${CMAKE_PROJECT_VERSION} LANGUAGES C)

    add_library(${PROJECT_NAME})

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

else()
    # ========================================================================
    # ZEPHYR BUILD -- named Zephyr library linked into the Zephyr image.
    # ========================================================================
    zephyr_library_named(el2go_rtp)

    # Public include root so consumers can do #include <rtp/el2go_rtp.h>
    zephyr_include_directories(${PROJECT_ROOT}/include)
endif()

# ============================================================================
# SHARED -- sources, private includes, and link libraries.
# Expressed once via add_target_sources.cmake wrappers so they apply to
# both the Linux STATIC library and the Zephyr named library.
# Note: on Linux these private dirs are already transitive via link libraries
# but listing them is harmless. On Zephyr add_link_libraries is a no-op so
# all needed include dirs must be listed explicitly here.
# ============================================================================

add_private_sources(el2go_rtp
    el2go_rtp.c
    el2go_rtp_dispatcher.c
    el2go_agent_endpoint.c
    el2go_rtp_status_report.c
)

add_private_directories(el2go_rtp
    ${PROJECT_ROOT}/priv
)

add_link_libraries(el2go_rtp
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
