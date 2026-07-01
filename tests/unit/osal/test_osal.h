/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/**
 * @brief Get the value of an environment variable.
 *
 * On platforms that do not support environment variables (e.g. Zephyr),
 * this function always returns NULL.
 *
 * @param name  Name of the environment variable to retrieve.
 *
 * @return Pointer to the value string, or NULL if not set or not supported.
 */
const char *test_osal_getenv(const char *name);