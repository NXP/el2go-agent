# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0

# Zephyr device build: full MCUBoot + NVS implementation.
# Only compiled when MCUBoot is configured as the bootloader.
if(CONFIG_BOOTLOADER_MCUBOOT)
    if(CONFIG_MBEDTLS_VERSION_4_x)
        set(FWUAL_MBEDTLS_COMPAT_SOURCE
            ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/fwual_mbedtls_compat_v4.c
        )
    else()
        set(FWUAL_MBEDTLS_COMPAT_SOURCE
            ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/fwual_mbedtls_compat_v2_v3.c
        )
    endif()

    add_private_sources(fwual
        ${CMAKE_CURRENT_SOURCE_DIR}/fwual_mcuboot.c
        ${FWUAL_MBEDTLS_COMPAT_SOURCE}
    )

    add_private_directories(fwual
        ${CMAKE_CURRENT_SOURCE_DIR}/../src
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls
        ${ZEPHYR_MCUBOOT_MODULE_DIR}/boot/bootutil/include
        ${ZEPHYR_MCUBOOT_MODULE_DIR}/boot/zephyr/include
        ${ZEPHYR_MBEDTLS_MODULE_DIR}/include
    )

endif()