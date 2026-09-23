# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(el2go_fwual_component)

add_compile_definitions(ENABLE_TRACE)

set(CT_ROOT ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/component)

target_sources(app PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ztest_fwual_component_main.c
    ${CT_ROOT}/internal_fwual_zephyr/test_fwual_internal.c
    ${CT_ROOT}/public_fwual_zephyr/test_fwual_public.c
    # fwual.c supplies weak defaults not overridden by fwual_mcuboot.c (per-board below).
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/fwual/fwual.c
    # Real SHA-256 + constant-time compare for fwual_verify_image().
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/net_crypto/net_crypto.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/net_crypto/mbedtls/net_crypto_mbedtls_crypto.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/net_crypto/mbedtls/compat/crypto/mbedtls_compat_crypto_v4.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/osal/zephyr/alloc.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/osal/zephyr/print.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/osal/zephyr/osal.c
)

if(CONFIG_BOARD_NATIVE_SIM)
    target_sources(app PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/boards/native_sim/test_backend.c
        ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/fwual/mcuboot/fwual_mcuboot.c
        ${CMAKE_CURRENT_SOURCE_DIR}/boards/native_sim/fwual_mcuboot_stubs.c
        ${CMAKE_CURRENT_SOURCE_DIR}/boards/native_sim/flash_fault_inject.c
        # No ELS PKC hardware on native_sim; shared with el2go_ota_component.
        ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/zephyr/tests/common/platform_stubs.c
    )
else()
    target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/boards/rw612/test_backend.c)
endif()

zephyr_include_directories(
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/common
    ${CT_ROOT}/framework
    ${CT_ROOT}/common
    ${CT_ROOT}/internal_fwual_zephyr
    ${CT_ROOT}/public_fwual_zephyr
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/include
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/priv
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/net_crypto
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/net_crypto/mbedtls
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/net_crypto/mbedtls/compat
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/platforms
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/fwual/src
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/osal/include
)

# psa-crypto public headers for real SHA-256 in fwual_verify_image().
zephyr_include_directories(
    ${ZEPHYR_BASE}/../modules/crypto/tf-psa-crypto/include
    ${ZEPHYR_BASE}/../modules/crypto/tf-psa-crypto/drivers/builtin/include
    ${ZEPHYR_BASE}/../modules/crypto/mbedtls/include
)

if(CONFIG_BOARD_NATIVE_SIM)
    zephyr_include_directories(
        ${ZEPHYR_MCUBOOT_MODULE_DIR}/boot/bootutil/include
        ${ZEPHYR_MCUBOOT_MODULE_DIR}/boot/zephyr/include
    )
endif()
