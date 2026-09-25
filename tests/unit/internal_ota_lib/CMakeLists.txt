# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

set(INTERNAL_TEST_SOURCES
    ${INTERNAL_TEST_SOURCES}
    ${CMAKE_CURRENT_SOURCE_DIR}/test_el2go_ota_lib_internal.c
    ${CMAKE_CURRENT_SOURCE_DIR}/test_el2go_ota_lib_internal_all.c
    ${CMAKE_CURRENT_SOURCE_DIR}/test_el2go_ota_grpc_internal.c
    ${CMAKE_CURRENT_SOURCE_DIR}/test_el2go_ota_fixtures.c
    ${CMAKE_CURRENT_SOURCE_DIR}/test_el2go_ota_request_builder.c
    ${CMAKE_CURRENT_SOURCE_DIR}/test_el2go_ota_response_handler.c
    ${CMAKE_CURRENT_SOURCE_DIR}/test_el2go_ota_status_reporting.c
    ${CMAKE_CURRENT_SOURCE_DIR}/test_el2go_ota_download_engine.c
    ${CMAKE_CURRENT_SOURCE_DIR}/test_el2go_ota_kvs.c
    ${CMAKE_CURRENT_SOURCE_DIR}/test_el2go_ota_tls.c
    ${CMAKE_CURRENT_SOURCE_DIR}/test_el2go_ota_cred_psa.c
    ${CMAKE_CURRENT_SOURCE_DIR}/test_el2go_ota_lib_core.c
    PARENT_SCOPE
)
