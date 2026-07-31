# Copyright 2026 NXP
# SPDX-License-Identifier: Apache-2.0

include(add_target_sources)

add_private_sources(el2go_ota_osal
    ${CMAKE_CURRENT_SOURCE_DIR}/el2go_ota_kvs_zephyr.c
)

add_private_directories(el2go_ota_osal
    ${PROJECT_ROOT}/priv
)
