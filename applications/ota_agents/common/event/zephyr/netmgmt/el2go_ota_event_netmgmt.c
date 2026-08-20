/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/* Event backend: bridges the Zephyr NET_EVENT_L4_CONNECTED net_mgmt event to
 * the registered net-up callback. */

#include "el2go_ota_event.h"

#include <zephyr/kernel.h>
#include <zephyr/net/net_mgmt.h>
#include <zephyr/net/net_event.h>

static struct net_mgmt_event_callback s_net_cb;
static el2go_app_net_up_cb_t s_user_cb;
static void *s_user_data;

/**
 * @brief net_mgmt event handler that forwards L4-connected to the user callback
 *
 * Invokes the registered net-up callback once NET_EVENT_L4_CONNECTED is
 * reported. Runs in net_mgmt context; the callback should keep its work short.
 *
 * @param[in] cb    net_mgmt callback structure (unused)
 * @param[in] event net_mgmt event identifier being reported
 * @param[in] iface Network interface the event relates to (unused)
 */
static void net_event_handler(struct net_mgmt_event_callback *cb, uint64_t event,
                              struct net_if *iface)
{
    ARG_UNUSED(cb);
    ARG_UNUSED(iface);

    if (event == NET_EVENT_L4_CONNECTED && s_user_cb != NULL) {
        s_user_cb(s_user_data);
    }
}

/**
 * @brief Registers a callback fired when the network reaches L4 connectivity
 *
 * Zephyr backend variant of el2go_ota_event_register_net_up(). Stores the
 * callback and user data, then subscribes to NET_EVENT_L4_CONNECTED via
 * net_mgmt. The callback is invoked from net_mgmt context on each such event.
 *
 * @param[in] cb        Callback to invoke on network up
 * @param[in] user_data Opaque pointer passed back to the callback
 *
 * @return 0 on success
 */
int el2go_ota_event_register_net_up(el2go_app_net_up_cb_t cb, void *user_data)
{
    s_user_cb = cb;
    s_user_data = user_data;

    net_mgmt_init_event_callback(&s_net_cb, net_event_handler, NET_EVENT_L4_CONNECTED);
    net_mgmt_add_event_callback(&s_net_cb);

    return 0;
}
