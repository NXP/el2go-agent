# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

cmake_minimum_required(VERSION ${CMAKE_MINIMUM_REQUIRED_VERSION})
project(el2go_rtp VERSION ${CMAKE_PROJECT_VERSION} LANGUAGES C)

# ============================================================================
# PUBLIC LIBRARY - THIS IS EXPORTED
# ============================================================================
add_library(${PROJECT_NAME}
    el2go_rtp.c
)

# Set library version
set_target_properties(${PROJECT_NAME} PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    C_VISIBILITY_PRESET hidden           # ← Hide all symbols by default
    VISIBILITY_INLINES_HIDDEN ON
)

# Public include directories
target_include_directories(${PROJECT_NAME} PUBLIC
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
# Private include directories
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_SOURCE_DIR}/priv
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Link to internal object libraries
target_link_libraries(${PROJECT_NAME}
    PRIVATE
        el2go_platform
        el2go_keystore
        el2go_datastore
        osal
        el2go_protobuf
        net_crypto
        el2go_common
        $<TARGET_PROPERTY:el2go_platform,INTERFACE_LINK_LIBRARIES>
)

# ============================================================================
# INSTALLATION
# ============================================================================

# Install and EXPORT only the public library
install(TARGETS ${PROJECT_NAME}
    EXPORT ${PROJECT_NAME}-targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
# Install public headers - common
install(FILES
    ${CMAKE_SOURCE_DIR}/include/common/el2go_datastore.h
    ${CMAKE_SOURCE_DIR}/include/common/el2go_keystore.h
    ${CMAKE_SOURCE_DIR}/include/common/el2go_platform.h
    ${CMAKE_SOURCE_DIR}/include/common/el2go_status.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/common
)

# Install public headers - rtp
install(FILES
    ${CMAKE_SOURCE_DIR}/include/rtp/el2go_rtp_config.h
    ${CMAKE_SOURCE_DIR}/include/rtp/el2go_rtp.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/rtp
)

# Export ONLY the public library target
install(EXPORT ${PROJECT_NAME}-targets
    FILE ${PROJECT_NAME}-targets.cmake
    NAMESPACE el2go::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
)

# Generate and install package config file
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