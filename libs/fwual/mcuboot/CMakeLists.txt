# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0

# Zephyr device build: full MCUBoot + NVS implementation.
# Only compiled when MCUBoot is configured as the bootloader.
if(CONFIG_BOOTLOADER_MCUBOOT)
    add_private_sources(fwual
        ${CMAKE_CURRENT_SOURCE_DIR}/fwual_mcuboot.c
    )

    add_private_directories(fwual
        ${CMAKE_CURRENT_SOURCE_DIR}/../src
        ${ZEPHYR_MCUBOOT_MODULE_DIR}/boot/bootutil/include
        ${ZEPHYR_MCUBOOT_MODULE_DIR}/boot/zephyr/include
    )
endif()