cmake_minimum_required(VERSION ${CMAKE_MINIMUM_REQUIRED_VERSION})
project(el2go_agent_lib VERSION ${CMAKE_PROJECT_VERSION} LANGUAGES C)

# Add subdirectories in dependency order
add_subdirectory(platforms)
add_subdirectory(keystores)
add_subdirectory(datastores)
add_subdirectory(agent)
add_subdirectory(osal/${OS})

# ============================================================================
# INTERNAL STATIC LIBRARY - FOR TESTING ONLY (NOT EXPORTED)
# ============================================================================
# This is a STATIC library that contains all object files
# This library is NEVER installed or exported
# All symbols are visible for testing purposes
# ============================================================================
if(BUILD_TESTING)
    add_library(_el2go_agent_internal STATIC
        $<TARGET_OBJECTS:el2go_agent_platform>
        $<TARGET_OBJECTS:el2go_agent_keystore>
        $<TARGET_OBJECTS:el2go_agent_datastore>
        $<TARGET_OBJECTS:el2go_agent_core>
        $<TARGET_OBJECTS:osal>
    )

    # Provide both public and private headers to tests
    target_include_directories(_el2go_agent_internal PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/priv>
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/lib/osal/include>
    )

    # All symbols visible in static library (no hiding)
    set_target_properties(_el2go_agent_internal PROPERTIES
        C_VISIBILITY_PRESET default
    )
endif()

# ============================================================================
# PUBLIC LIBRARY - THIS IS EXPORTED
# ============================================================================
add_library(${PROJECT_NAME}
    $<TARGET_OBJECTS:el2go_agent_platform>
    $<TARGET_OBJECTS:el2go_agent_keystore>
    $<TARGET_OBJECTS:el2go_agent_datastore>
    $<TARGET_OBJECTS:el2go_agent_core>
    $<TARGET_OBJECTS:osal>
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
    ${CMAKE_SOURCE_DIR}/lib/osal/include
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

# Install public headers
install(FILES
    ${CMAKE_SOURCE_DIR}/include/el2go_agent.h
    ${CMAKE_SOURCE_DIR}/include/el2go_agent_status.h
    ${CMAKE_SOURCE_DIR}/include/el2go_agent_platform.h
    ${CMAKE_SOURCE_DIR}/include/el2go_agent_datastore.h
    ${CMAKE_SOURCE_DIR}/include/el2go_agent_keystore.h
    ${CMAKE_SOURCE_DIR}/include/el2go_agent_config.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

# Export ONLY the public library target
install(EXPORT ${PROJECT_NAME}-targets
    FILE ${PROJECT_NAME}-targets.cmake
    NAMESPACE ${PROJECT_NAME}::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
)

# Generate and install package config file
include(CMakePackageConfigHelpers)

configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/el2go_agent_lib-config.cmake.in
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
