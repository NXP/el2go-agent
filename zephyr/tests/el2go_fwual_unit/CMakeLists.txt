# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(el2go_fwual_unit)

add_compile_definitions(ENABLE_TRACE)

target_sources(app PRIVATE
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/unit/framework/test_framework.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/unit/framework/test_utils.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/unit/public_fwual/test_fwual_public.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/unit/internal_fwual/test_fwual_internal.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ztest_fwual_unit_main.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/zephyr/tests/common/ztest_bridge.c
    ${CMAKE_CURRENT_SOURCE_DIR}/mocks/fwual_storage_mocks.c
    ${CMAKE_CURRENT_SOURCE_DIR}/mocks/fwual_storage_fault_zephyr.c
    # Real FWUAL backend under test, linked against the RAM fakes above.
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/fwual/mcuboot/fwual_mcuboot.c
    # fwual.c supplies weak defaults for the public API not overridden above.
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/fwual/fwual.c
    # Real SHA-256/ct-memcmp for fwual_verify_image(), see net_crypto_sha256_psa_shim.c.
    ${CMAKE_CURRENT_SOURCE_DIR}/common/net_crypto_sha256_psa_shim.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/osal/zephyr/alloc.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/osal/zephyr/print.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/osal/zephyr/osal.c
)

zephyr_include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/common
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/zephyr/tests/common
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/unit/framework
    ${CMAKE_CURRENT_SOURCE_DIR}/mocks
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/unit/mock
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/unit/public_fwual
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/unit/internal_fwual
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/unit
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/include
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/priv
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/net_crypto
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/net_crypto/mbedtls
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/net_crypto/mbedtls/compat
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/platforms
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/fwual/src
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/osal/include
)

set_source_files_properties(
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/unit/internal_fwual/test_fwual_internal.c
    PROPERTIES COMPILE_DEFINITIONS "register_fwual_tests=register_fwual_internal_tests"
)

# psa-crypto public headers for real SHA-256 in fwual_verify_image().
zephyr_include_directories(
    ${ZEPHYR_BASE}/../modules/crypto/tf-psa-crypto/include
    ${ZEPHYR_BASE}/../modules/crypto/tf-psa-crypto/drivers/builtin/include
    ${ZEPHYR_BASE}/../modules/crypto/mbedtls/include
)

# MCUboot public headers -- fwual_mcuboot.c includes <bootutil/bootutil_public.h> directly.
zephyr_include_directories(
    ${ZEPHYR_MCUBOOT_MODULE_DIR}/boot/bootutil/include
    ${ZEPHYR_MCUBOOT_MODULE_DIR}/boot/zephyr/include
)
