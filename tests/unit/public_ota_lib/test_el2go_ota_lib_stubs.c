/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @brief No-op stub for register_ota_lib_internal_tests.
 *
 * The internal OTA lib tests are not compiled into the public test executable.
 * This stub satisfies the linker when linux_main.c calls
 * register_ota_lib_internal_tests() in the public executable.
 */
void register_ota_lib_internal_tests(void)
{
}
