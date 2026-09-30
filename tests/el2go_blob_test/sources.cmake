# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

# Sources shared between all builds of el2go_blob_test.
set(EL2GO_BLOB_TEST_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/src/el2go_blob_test.c
    ${CMAKE_CURRENT_LIST_DIR}/src/el2go_blob_test_executor_psa.c
    ${CMAKE_CURRENT_LIST_DIR}/src/el2go_blob_test_parser_psa.c
    ${CMAKE_CURRENT_LIST_DIR}/src/el2go_blob_test_reader_inline.c
    ${CMAKE_CURRENT_LIST_DIR}/src/el2go_blob_test_suite_generic.c
    # Weak default platform stubs (overridden by platform-specific implementations)
    ${CMAKE_CURRENT_LIST_DIR}/platform/el2go_blob_test_platform.c
)

set(EL2GO_BLOB_TEST_INCLUDE_DIRS
    ${CMAKE_CURRENT_LIST_DIR}/inc
    ${CMAKE_CURRENT_LIST_DIR}/../../priv
)
