# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(el2go_ota_component)

set(CT_ROOT ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/component)

target_sources(app PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ztest_component_main.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/common/canned_protobuf.c
    ${CT_ROOT}/common/mock_transport.c
    ${CT_ROOT}/internal_ota_lib/test_el2go_ota_lib_internal.c
    ${CT_ROOT}/public_ota_lib/test_el2go_ota_lib_public.c
    ${CT_ROOT}/internal_fwual_zephyr/test_fwual_internal.c
    ${CT_ROOT}/public_fwual_zephyr/test_fwual_public.c
    ${CT_ROOT}/internal_ota_agent_core/test_el2go_ota_agent_core_internal.c
    ${CT_ROOT}/public_ota_agent_core/test_el2go_ota_agent_core_public.c
    ${CT_ROOT}/internal_ota_agent_advanced/test_el2go_ota_agent_advanced_internal.c
    ${CT_ROOT}/public_ota_agent_advanced/test_el2go_ota_agent_advanced_public.c
)
if(CONFIG_BOARD_NATIVE_SIM)
    target_sources(app PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/boards/native_sim/test_backend.c
        ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/fwual/mcuboot/fwual_mcuboot.c
        ${CMAKE_CURRENT_SOURCE_DIR}/boards/native_sim/fwual_mcuboot_stubs.c
        # native_sim has no ELS PKC hardware, so the real platform backend
        # (libs/platforms/els_pkc/psa) is disabled via boards/native_sim.conf.
        ${CMAKE_CURRENT_SOURCE_DIR}/boards/native_sim/platform_stubs.c
    )
else()
    target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/boards/rw612/test_backend.c)
endif()

zephyr_include_directories(
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/common
    ${CT_ROOT}/framework
    ${CT_ROOT}/common
    ${CT_ROOT}/internal_ota_lib
    ${CT_ROOT}/public_ota_lib
    ${CT_ROOT}/internal_fwual_zephyr
    ${CT_ROOT}/public_fwual_zephyr
    ${CT_ROOT}/internal_ota_agent_core
    ${CT_ROOT}/public_ota_agent_core
    ${CT_ROOT}/internal_ota_agent_advanced
    ${CT_ROOT}/public_ota_agent_advanced

    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/include
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/priv
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/protobuf/nanopb
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/protobuf/ota
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/el2go_ota_lib/src
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/el2go_ota_lib/src/download
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/el2go_ota_lib/src/transport
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/net_crypto
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/platforms
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/fwual/src
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/osal/include
)

if(CONFIG_BOARD_NATIVE_SIM)
    zephyr_include_directories(
        ${ZEPHYR_MCUBOOT_MODULE_DIR}/boot/bootutil/include
        ${ZEPHYR_MCUBOOT_MODULE_DIR}/boot/zephyr/include
    )
endif()
