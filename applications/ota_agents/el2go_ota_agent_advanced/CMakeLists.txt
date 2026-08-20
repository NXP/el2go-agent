# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

cmake_minimum_required(VERSION ${CMAKE_MINIMUM_REQUIRED_VERSION})
project(el2go_ota_agent_advanced VERSION ${CMAKE_PROJECT_VERSION} LANGUAGES C)

include(add_target_sources)
include(sources.cmake)

add_executable(${PROJECT_NAME} ${EL2GO_OTA_AGENT_ADVANCED_SOURCES})

target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

add_link_libraries(${PROJECT_NAME} PRIVATE
    fwual el2go_ota_lib
    el2go_app_net el2go_app_sys el2go_app_time
    el2go_ota_diag el2go_ota_persist el2go_ota_event)

# Kconfig provides these symbols on Zephyr via prj.conf.
# On Linux there is no equivalent mechanism so defaults are set here.
if(NOT BUILD_ZEPHYR)
    target_compile_definitions(${PROJECT_NAME} PRIVATE
        CONFIG_EL2GO_OTA_SERVER_HOST=""
        CONFIG_EL2GO_OTA_SERVER_PORT=50051
        CONFIG_EL2GO_OTA_CLIENT_KEY_OBJECT_ID=0x3010
        CONFIG_EL2GO_OTA_CLIENT_CERT_OBJECT_ID=0x3021
        CONFIG_EL2GO_OTA_ADV_POLL_INTERVAL_S=3600
        CONFIG_EL2GO_OTA_ADV_RETRY_INITIAL_BACKOFF_S=60
        CONFIG_EL2GO_OTA_ADV_RETRY_MAX_BACKOFF_S=3600
        CONFIG_EL2GO_OTA_ADV_DOWNLOAD_MAX_RETRIES=3
        CONFIG_EL2GO_OTA_ADV_REPORT_MAX_RETRIES=5
        CONFIG_EL2GO_OTA_ADV_BLACKOUT_START_HOUR=0
        CONFIG_EL2GO_OTA_ADV_BLACKOUT_END_HOUR=0
        CONFIG_EL2GO_OTA_ADV_DEFER_WINDOW_S=0
        OTA_FW_VERSION="0.0.0"
    )
endif()

install(TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)