cmake_minimum_required(VERSION ${CMAKE_MINIMUM_REQUIRED_VERSION})
project(el2go_agent_lib VERSION ${CMAKE_PROJECT_VERSION} LANGUAGES C)

# Add subdirectories in dependency order
add_subdirectory(platforms)
add_subdirectory(keystores)
add_subdirectory(datastores)
add_subdirectory(agent)
add_subdirectory(osal/${OS})

# Create main library combining all components
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

# Installation rules
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
# Export targets
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
