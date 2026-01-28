cmake_minimum_required(VERSION 3.15)
project(nxp_iot_agent VERSION 1.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Collect all source files
set(IOT_AGENT_SOURCES
    iot_agent.c
    iot_agent_datastore.c
    iot_agent_keystore.c
    iot_agent_utils.c
)
# Create library (respects BUILD_SHARED_LIBS from root)
add_library(${PROJECT_NAME} ${IOT_AGENT_SOURCES})
# Set library version
set_target_properties(${PROJECT_NAME} PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)

# Public include directories
target_include_directories(${PROJECT_NAME} PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>
    $<INSTALL_INTERFACE:include>
)

# Private include directories (for internal headers)
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/internal
)

# Installation rules
install(TARGETS ${PROJECT_NAME}
    EXPORT ${PROJECT_NAME}-targets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)

# Install public headers
install(FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/../include/iot_agent.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../include/iot_agent_status.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../include/iot_agent_datastore.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../include/iot_agent_keystore.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../include/iot_agent_utils.h
    DESTINATION include
)

# Export targets
install(EXPORT ${PROJECT_NAME}-targets
    FILE ${PROJECT_NAME}-targets.cmake
    NAMESPACE ${PROJECT_NAME}::
    DESTINATION lib/cmake/${PROJECT_NAME}
)

# Generate and install package config file
include(CMakePackageConfigHelpers)

configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/${PROJECT_NAME}-config.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config.cmake
    INSTALL_DESTINATION lib/cmake/${PROJECT_NAME}
)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config-version.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config-version.cmake
    DESTINATION lib/cmake/${PROJECT_NAME}
)
