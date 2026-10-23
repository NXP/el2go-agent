# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(native_sim_unit)

add_compile_definitions(ENABLE_TRACE)

target_sources(app PRIVATE
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/unit/framework/test_framework.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/unit/framework/test_utils.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/common/canned_protobuf.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/unit/public_ota_lib/test_el2go_ota_lib_public.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/unit/internal_ota_lib/test_el2go_ota_lib_internal.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/unit/internal_ota_lib/test_el2go_ota_grpc_internal.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/unit/internal_ota_lib/test_el2go_ota_fixtures.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/unit/internal_ota_lib/test_el2go_ota_request_builder.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/unit/internal_ota_lib/test_el2go_ota_response_handler.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/unit/internal_ota_lib/test_el2go_ota_status_reporting.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/unit/internal_ota_lib/test_el2go_ota_download_engine.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/unit/internal_ota_lib/test_el2go_ota_kvs.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/unit/internal_ota_lib/test_el2go_ota_tls.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/unit/internal_ota_lib/test_el2go_ota_cred_psa.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/unit/internal_ota_lib/test_el2go_ota_lib_core.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ztest_unit_main.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/zephyr/tests/common/ztest_bridge.c
    ${CMAKE_CURRENT_SOURCE_DIR}/mock/platform_stubs.c
    ${CMAKE_CURRENT_SOURCE_DIR}/mock/wrap_net_crypto.c
)

set_source_files_properties(
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/unit/internal_ota_lib/test_el2go_ota_lib_internal.c
    PROPERTIES COMPILE_DEFINITIONS "register_ota_lib_tests=register_ota_lib_internal_tests"
)

# wrap flags so el2go_ota_tls.c, el2go_ota_cred_psa.c, and el2go_ota_grpc.c
# execute their real code paths while net_crypto_*/psa_its_* are stubbed.
zephyr_ld_options(
    -Wl,--wrap=net_crypto_new
    -Wl,--wrap=net_crypto_configure
    -Wl,--wrap=net_crypto_set_server_cert
    -Wl,--wrap=net_crypto_set_cli_cert
    -Wl,--wrap=net_crypto_set_cipher_suites
    -Wl,--wrap=net_crypto_set_curves
    -Wl,--wrap=net_crypto_set_alpn
    -Wl,--wrap=net_crypto_associate_key
    -Wl,--wrap=net_crypto_connect
    -Wl,--wrap=net_crypto_disconnect
    -Wl,--wrap=net_crypto_write
    -Wl,--wrap=net_crypto_read
    -Wl,--wrap=net_crypto_free
    -Wl,--wrap=secure_storage_its_get_info
    -Wl,--wrap=secure_storage_its_get
    -Wl,--wrap=psa_get_key_attributes
    -Wl,--wrap=psa_export_key
)

zephyr_compile_definitions(EL2GO_OTA_GRPC_HAVE_NET_WRAP)

zephyr_include_directories(
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/zephyr/tests/common
    ${CMAKE_CURRENT_SOURCE_DIR}/mock
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/unit/mock
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/common
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/unit/framework
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/unit/internal_ota_lib
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/unit
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/include
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/priv
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/protobuf/nanopb
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/el2go_ota_lib/src
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/el2go_ota_lib/src/cred
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/el2go_ota_lib/src/osal
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/el2go_ota_lib/src/download
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/el2go_ota_lib/src/transport
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/protobuf/ota
)

# psa-crypto public headers for the mock.
zephyr_include_directories(
    ${ZEPHYR_BASE}/../modules/crypto/tf-psa-crypto/include
    ${ZEPHYR_BASE}/../modules/crypto/tf-psa-crypto/drivers/builtin/include
    ${ZEPHYR_BASE}/../modules/crypto/mbedtls/include
    ${ZEPHYR_BASE}/subsys/secure_storage/include
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/net_crypto
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/platforms
)

# secure_storage_its_caller_id_t type declaration for wrap_net_crypto mocks
zephyr_include_directories(
    ${ZEPHYR_BASE}/subsys/secure_storage/include/internal
)
