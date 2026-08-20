/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/* Persistence weak default: RAM-only record that does not survive a reboot.
 * See the zephyr/ backend for the non-volatile implementation. */

#include "el2go_app_compiler.h"
#include "el2go_ota_persist.h"

#include <string.h>

static agent_persist_t s_ram_record;
static int s_ram_valid;

/**
 * @copydoc el2go_ota_persist_read
 *
 * Weak default. Reads from a RAM-only record that does not survive a reboot;
 * a backend overrides it to read non-volatile storage.
 */
__weak el2go_ota_persist_status_t el2go_ota_persist_read(agent_persist_t *out)
{
    if (out == NULL) {
        return EL2GO_OTA_PERSIST_ERR_ARG;
    }

    if (s_ram_valid) {
        memcpy(out, &s_ram_record, sizeof(*out));
    } else {
        memset(out, 0, sizeof(*out));
        out->valid = 0U;
    }

    return EL2GO_OTA_PERSIST_OK;
}

/**
 * @copydoc el2go_ota_persist_write
 *
 * Weak default. Stores into a RAM-only record that does not survive a reboot;
 * a backend overrides it to write non-volatile storage.
 */
__weak el2go_ota_persist_status_t el2go_ota_persist_write(const agent_persist_t *in)
{
    if (in == NULL) {
        return EL2GO_OTA_PERSIST_ERR_ARG;
    }

    memcpy(&s_ram_record, in, sizeof(s_ram_record));
    s_ram_valid = 1;
    return EL2GO_OTA_PERSIST_OK;
}

/**
 * @copydoc el2go_ota_persist_clear
 *
 * Weak default. Clears the RAM-only record; a backend overrides it to clear
 * non-volatile storage.
 */
__weak el2go_ota_persist_status_t el2go_ota_persist_clear(void)
{
    memset(&s_ram_record, 0, sizeof(s_ram_record));
    s_ram_valid = 0;
    return EL2GO_OTA_PERSIST_OK;
}
