# Enable position-independent code for all targets
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Add common component subdirectories (shared between agent and future OTA)
add_subdirectory(protobuf)
add_subdirectory(platforms)
add_subdirectory(keystores)
add_subdirectory(datastores)

# Add library subdirectories
add_subdirectory(agent)
add_subdirectory(osal/${OS})
