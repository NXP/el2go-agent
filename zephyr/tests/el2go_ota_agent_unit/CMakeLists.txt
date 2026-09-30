# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(native_sim_agent_unit)

add_compile_definitions(ENABLE_TRACE)

set(ADV_AGENT_MAIN ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/applications/ota_agents/el2go_ota_agent_advanced/src/main.c)

target_sources(app PRIVATE
    ${ADV_AGENT_MAIN}
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/applications/ota_agents/el2go_ota_agent_advanced/src/updater.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/applications/ota_agents/el2go_ota_agent_advanced/src/scheduler.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/applications/ota_agents/el2go_ota_agent_advanced/src/policy.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/unit/mock/el2go_ota_lib_mock.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/unit/mock/fwual_mock.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/unit/mock/wrap_app_sys.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/unit/mock/agent_test_fixtures.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/unit/framework/test_framework.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/unit/framework/test_utils.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/unit/framework/ztest_bridge.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/unit/internal_ota_agent_core/test_el2go_ota_agent_core_internal.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/unit/public_ota_agent_core/test_el2go_ota_agent_core_public.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/unit/internal_ota_agent_advanced/test_el2go_ota_agent_advanced_internal.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/unit/public_ota_agent_advanced/test_el2go_ota_agent_advanced_public.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ztest_agent_unit_main.c
)

target_compile_definitions(app PRIVATE OTA_FW_VERSION="0.0.0-test")

set_source_files_properties(
    ${ADV_AGENT_MAIN}
    PROPERTIES COMPILE_DEFINITIONS "main=el2go_ota_agent_advanced_main_unused"
)

zephyr_ld_options(
    -Wl,--wrap=el2go_ota_init
    -Wl,--wrap=el2go_ota_connect
    -Wl,--wrap=el2go_ota_disconnect
    -Wl,--wrap=el2go_ota_cleanup
    -Wl,--wrap=el2go_ota_is_connected
    -Wl,--wrap=el2go_ota_get_error_string
    -Wl,--wrap=el2go_ota_check_for_updates
    -Wl,--wrap=el2go_ota_download_package
    -Wl,--wrap=el2go_ota_report_status
    -Wl,--wrap=el2go_ota_schedule_status_report
    -Wl,--wrap=el2go_ota_get_pending_status
    -Wl,--wrap=el2go_ota_report_pending_status
    -Wl,--wrap=el2go_app_sys_activate_update
    -Wl,--wrap=el2go_app_sys_sleep_ms
    -Wl,--wrap=el2go_app_sys_uptime_ms
    -Wl,--wrap=el2go_app_sys_wait
    -Wl,--wrap=el2go_app_sys_signal
    -Wl,--wrap=el2go_app_time_get_hour_of_day
    -Wl,--wrap=el2go_app_time_sync
)

zephyr_include_directories(
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/unit/mock
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/unit/framework
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/unit
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/applications/ota_agents
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/applications/ota_agents/el2go_ota_agent_advanced/include
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/applications/ota_agents/common/diag
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/applications/ota_agents/common/persist
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/applications/ota_agents/common/event
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/applications/common/system
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/applications/common/time
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/applications/common/network
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/include
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/priv
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/protobuf/nanopb
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/el2go_ota_lib/src
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
