/*
 * Copyright 2024-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * EL2GO MQTT demo entry point.
 *
 * Assumes that credentials (device key and certificate) have already been
 * provisioned into the PSA keystore by the EL2GO RTP agent.  This demo
 * verifies MQTT connectivity against the configured broker(s) using those
 * provisioned credentials.
 *
 * Supported backends (selected at build time via Kconfig):
 *   CONFIG_EL2GO_RTP_MQTT_AWS   - AWS IoT Core
 *   CONFIG_EL2GO_RTP_MQTT_AZURE - Azure IoT Hub via DPS
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include "el2go_app_net.h"
#include "el2go_mqtt.h"

LOG_MODULE_REGISTER(el2go_mqtt_demo, LOG_LEVEL_INF);

/* ========================================================================== */
/* MQTT demo thread stack                                                      */
/* ========================================================================== */

#define MQTT_DEMO_THREAD_STACK_SIZE (1024U * 32U)

K_THREAD_STACK_DEFINE(mqtt_demo_stack_area, MQTT_DEMO_THREAD_STACK_SIZE);

/* ========================================================================== */
/* Demo entry point                                                            */
/* ========================================================================== */

static void mqtt_demo_task(void *arg1, void *arg2, void *arg3)
{
    (void)arg1;
    (void)arg2;
    (void)arg3;

    int rc = 0;

    LOG_INF("EL2GO MQTT demo starting ...");

    rc = el2go_app_net_init();
    if (rc != 0) {
        LOG_ERR("Network initialization failed (%d)", rc);
        goto exit;
    }

    LOG_INF("Network ready. Starting MQTT credential verification ...");

    rc = el2go_mqtt_verify(NULL);
    if (rc != 0) {
        LOG_ERR("MQTT credential verification failed (%d)", rc);
        goto exit;
    }

    LOG_INF("EL2GO MQTT demo finished successfully.");

exit:
    if (rc != 0) {
        LOG_ERR("EL2GO MQTT demo failed (rc=%d)", rc);
    }

    for (;;) {
        k_sleep(K_FOREVER);
    }
}

/* ========================================================================== */
/* main                                                                        */
/* ========================================================================== */

int main(void)
{
    static struct k_thread mqtt_demo_thread_data;

    k_tid_t tid = k_thread_create(&mqtt_demo_thread_data, mqtt_demo_stack_area,
                                  K_THREAD_STACK_SIZEOF(mqtt_demo_stack_area), mqtt_demo_task, NULL,
                                  NULL, NULL, 0, 0, K_FOREVER);

    k_thread_name_set(tid, "el2go_mqtt_demo");
    k_thread_start(tid);

    return 0;
}
