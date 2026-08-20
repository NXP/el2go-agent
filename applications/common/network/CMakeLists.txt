# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

include(add_target_sources)

declare_library(el2go_app_net)

add_public_directories(el2go_app_net ${CMAKE_CURRENT_LIST_DIR})
add_private_directories(el2go_app_net
    ${PROJECT_ROOT}/applications/common/compiler
    ${PROJECT_ROOT}/include
)

# Weak default always compiled; backend strong symbol wins at link time.
add_private_sources(el2go_app_net ${CMAKE_CURRENT_LIST_DIR}/el2go_app_net.c)

if(EXISTS ${CMAKE_CURRENT_LIST_DIR}/${OS}/${NET_BACKEND})
    add_subdirectory(${OS}/${NET_BACKEND})
endif()
