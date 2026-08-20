/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/* Weak stub fallback, compiled when no backend exists for the current OS.
 * All log output is silently discarded.
 * Add applications/ota_agents/common/diag/${OS}/${DIAG_BACKEND}/ to provide
 * a real implementation. */

#include "el2go_app_compiler.h"
#include "el2go_ota_diag.h"

/**
 * @copydoc el2go_ota_diag_emit
 *
 * Weak default. Discards the line; a backend overrides it to format and
 * emit or store the log line.
 */
__weak void el2go_ota_diag_emit(el2go_ota_diag_level_t level, const char *fmt, ...)
{
    (void)level;
    (void)fmt;
}

/**
 * @copydoc el2go_ota_diag_dump
 *
 * Weak default. No-op since the default backend does not store the log.
 */
__weak void el2go_ota_diag_dump(void)
{
}

/**
 * @copydoc el2go_ota_diag_boot_replay
 *
 * Weak default. No-op since the default backend has no persistent log to
 * replay.
 */
__weak void el2go_ota_diag_boot_replay(void)
{
}