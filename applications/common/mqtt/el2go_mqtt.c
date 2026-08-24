/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Weak default implementation of el2go_mqtt_verify().
 *
 * This file is compiled into the el2go_mqtt library for every build.
 * OS-specific backends (e.g. zephyr/el2go_mqtt_zephyr.c) provide a
 * non-weak override that performs the actual TLS credential verification.
 * When no backend is selected the default below is linked, which simply
 * logs a warning and returns 0 so the rest of the application can still
 * run without the MQTT verify step.
 */

#include "el2go_mqtt.h"

__attribute__((weak)) int el2go_mqtt_verify(el2go_keystore_t *keystore)
{
    (void)keystore;
    /* No MQTT backend selected - verification skipped. */
    return 0;
}
