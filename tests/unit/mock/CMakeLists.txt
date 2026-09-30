# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

set(FWUAL_MOCK_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/fwual_storage_fault_stub.c
    PARENT_SCOPE
)

set(NET_CRYPTO_MOCK_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/wrap_net_crypto_stub.c
    PARENT_SCOPE
)

set(OTA_AGENT_MOCK_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/el2go_ota_lib_mock.c
    ${CMAKE_CURRENT_SOURCE_DIR}/fwual_mock.c
    ${CMAKE_CURRENT_SOURCE_DIR}/wrap_app_sys.c
    ${CMAKE_CURRENT_SOURCE_DIR}/agent_test_fixtures.c
    PARENT_SCOPE
)
