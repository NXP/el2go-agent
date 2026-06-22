# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

# Public API test sources
set(PUBLIC_TEST_SOURCES
        ${PUBLIC_TEST_SOURCES}
        ${CMAKE_CURRENT_SOURCE_DIR}/test_el2go_datastore_common.c
        ${CMAKE_CURRENT_SOURCE_DIR}/test_el2go_datastore_sanity.c
        ${CMAKE_CURRENT_SOURCE_DIR}/test_el2go_datastore_fs.c
        ${CMAKE_CURRENT_SOURCE_DIR}/test_el2go_datastore_plain.c
        ${CMAKE_CURRENT_SOURCE_DIR}/test_el2go_datastore_custom.c
        PARENT_SCOPE
)
