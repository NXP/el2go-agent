# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

include(add_target_sources)

add_private_sources(el2go_platform
    els_pkc_platform.c
    els_pkc_crypto_params.c
)

add_private_directories(el2go_platform
    ${CMAKE_CURRENT_SOURCE_DIR}
)
