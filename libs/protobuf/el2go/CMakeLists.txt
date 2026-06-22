# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

# EdgeLock 2GO protobuf definitions
add_library(el2go_protobuf OBJECT
    Agent.pb.c
    Apdu.pb.c
    Datastore.pb.c
    Dispatcher.pb.c
    Hostcmd.pb.c
    Proxy.pb.c
    PSA.pb.c
    RPC.pb.c
    Types.pb.c
)

target_include_directories(el2go_protobuf PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(el2go_protobuf PUBLIC
    nanopb
)

