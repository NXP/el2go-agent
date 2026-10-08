# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(el2go_claimcode_encryption)

set(BUILD_ZEPHYR TRUE)
include(${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/applications/el2go_claimcode_encryption/sources.cmake)
target_sources(app PRIVATE ${EL2GO_CLAIMCODE_ENCRYPTION_SOURCES})

# OSAL Zephyr implementation sources (no RTP agent, so uuid.c is used)
set(OSAL_DIR ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/osal/zephyr)
target_sources(app PRIVATE
    ${OSAL_DIR}/alloc.c
    ${OSAL_DIR}/osal.c
    ${OSAL_DIR}/print.c
    ${OSAL_DIR}/file.c
    ${OSAL_DIR}/uuid.c
)
# Private OSAL headers (local.h etc.) needed by the implementation files above
zephyr_include_directories(${OSAL_DIR})

zephyr_include_directories(
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/include
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/priv
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/osal/include
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/applications/el2go_claimcode_encryption/inc
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/applications/el2go_claimcode_encryption/flash_config
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/applications/common/config
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/include/rtp
)


# FIXME: Add ROMAPI as a proper Zephyr component when available.
# Until then, pull the ROM API drivers directly from hal_nxp.
target_sources(app PRIVATE
    ${ZEPHYR_HAL_NXP_MODULE_DIR}/mcux/mcux-sdk-ng/devices/Wireless/RW/RW612/drivers/romapi/iap/fsl_romapi_iap.c
    ${ZEPHYR_HAL_NXP_MODULE_DIR}/mcux/mcux-sdk-ng/devices/Wireless/RW/RW612/drivers/romapi/flexspi/fsl_romapi_flexspi.c
    ${ZEPHYR_HAL_NXP_MODULE_DIR}/mcux/mcux-sdk-ng/devices/Wireless/RW/RW612/drivers/romapi/bootloader/fsl_romapi.c
)

zephyr_include_directories(
    ${ZEPHYR_HAL_NXP_MODULE_DIR}/mcux/mcux-sdk-ng/devices/Wireless/RW/RW612/drivers/romapi/iap
    ${ZEPHYR_HAL_NXP_MODULE_DIR}/mcux/mcux-sdk-ng/devices/Wireless/RW/RW612/drivers/romapi/flexspi
    ${ZEPHYR_HAL_NXP_MODULE_DIR}/mcux/mcux-sdk-ng/devices/Wireless/RW/RW612/drivers/romapi/nboot
    ${ZEPHYR_HAL_NXP_MODULE_DIR}/mcux/mcux-sdk-ng/devices/Wireless/RW/RW612/drivers/romapi/bootloader
    ${ZEPHYR_HAL_NXP_MODULE_DIR}/mcux/mcux-sdk-ng/devices/Wireless/RW/RW612/drivers/romapi/otp
)

if(CONFIG_CLAIM_CODE_INFO_ADDRESS)
    target_compile_definitions(app PRIVATE
        CLAIM_CODE_INFO_ADDRESS=${CONFIG_CLAIM_CODE_INFO_ADDRESS}
    )
endif()
