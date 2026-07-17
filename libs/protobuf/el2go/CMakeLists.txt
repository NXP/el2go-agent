# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

include(add_target_sources)

# EdgeLock 2GO protobuf definitions.
# declare_library creates an OBJECT library in non-Zephyr builds; in Zephyr
# builds it is a no-op because sources are contributed to the Zephyr library
# directly via the add_private_sources / add_public_directories macros below.

declare_library(el2go_protobuf)

add_private_sources(el2go_protobuf
    Agent.pb.c
    Apdu.pb.c
    Datastore.pb.c
    Dispatcher.pb.c
    Hostcmd.pb.c
    Proxy.pb.c
    PSA.pb.c
    RPC.pb.c
    Types.pb.c
    ServiceDescriptor.pb.c
)

add_public_directories(el2go_protobuf
    ${CMAKE_CURRENT_SOURCE_DIR}
)

add_link_libraries(el2go_protobuf
    PUBLIC
        nanopb
)
