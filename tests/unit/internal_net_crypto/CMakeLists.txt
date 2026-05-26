# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NXP

# Collect internal net_crypto test sources
set(INTERNAL_TEST_SOURCES
    ${INTERNAL_TEST_SOURCES}
    ${CMAKE_CURRENT_SOURCE_DIR}/test_net_crypto_internal.c
    PARENT_SCOPE
)