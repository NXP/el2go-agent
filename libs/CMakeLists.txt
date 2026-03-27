# Add common component subdirectories (shared between main libraries)
add_subdirectory(protobuf)
add_subdirectory(platforms)
add_subdirectory(keystores)
add_subdirectory(datastores)
add_subdirectory(osal/${OS})

# Add EL2GO RTP library subdirectories
add_subdirectory(el2go_rtp_lib)
