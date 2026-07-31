/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @brief No-op stub for register_ota_lib_tests.
 *
 * The public OTA lib tests are not compiled into the internal test executable.
 * This stub satisfies the linker when linux_main.c calls
 * register_ota_lib_tests() in the internal executable.
 */
void register_ota_lib_tests(void)
{
}
