# Copyright 2024-2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(el2go_import_blob)

if(CONFIG_VALIDATE_PSA_IMPORT_MASTER_KEY)
    set(VALIDATE_PSA_IMPORT_MASTER_KEY 1)
endif()
if(CONFIG_VALIDATE_PSA_IMPORT_KEY_PAIR)
    set(VALIDATE_PSA_IMPORT_KEY_PAIR 1)
endif()
if(CONFIG_VALIDATE_PSA_IMPORT_CERT)
    set(VALIDATE_PSA_IMPORT_CERT 1)
endif()

include(${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/applications/el2go_import_blob/sources.cmake)
target_sources(app PRIVATE ${EL2GO_IMPORT_BLOB_SOURCES})

target_include_directories(app PRIVATE
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/applications/el2go_import_blob/src
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/applications/el2go_import_blob/osal/inc
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/applications/el2go_import_blob/osal/zephyr/inc
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/applications/common/utils
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/include
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/priv
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/net_crypto
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/platforms
)

# Enable EL2GO debug tracing so that EL2GO_DBG_PRINTF outputs are active.
target_compile_definitions(app PRIVATE ENABLE_TRACE)

if(CONFIG_VALIDATE_PSA_IMPORT_MASTER_KEY)
    target_compile_definitions(app PRIVATE VALIDATE_PSA_IMPORT_MASTER_KEY=1)
endif()
if(CONFIG_VALIDATE_PSA_IMPORT_KEY_PAIR)
    target_compile_definitions(app PRIVATE VALIDATE_PSA_IMPORT_KEY_PAIR=1)
endif()
if(CONFIG_VALIDATE_PSA_IMPORT_CERT)
    target_compile_definitions(app PRIVATE VALIDATE_PSA_IMPORT_CERT=1)
endif()
if(CONFIG_BLOB_AREA)
    target_compile_definitions(app PRIVATE BLOB_AREA=${CONFIG_BLOB_AREA})
endif()
if(CONFIG_BLOB_AREA_SIZE)
    target_compile_definitions(app PRIVATE BLOB_AREA_SIZE=${CONFIG_BLOB_AREA_SIZE})
endif()
