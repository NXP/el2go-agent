/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/**
 * @file el2go_ota_event.h
 * @brief Network-up event notification abstraction.
 *
 * Declares the interface used by the OTA agent to be notified when the network
 * comes up. This header defines the generic contract that every backend must
 * honor; the symbols carry weak defaults so a build links without a concrete
 * backend. A concrete backend overrides the weak definitions to deliver the
 * real notification.
 *
 * @defgroup el2go_ota_event Network-up Event Abstraction
 * @brief Network-up notification contract.
 * @{
 */

#ifndef __EL2GO_OTA_EVENT_H__
#define __EL2GO_OTA_EVENT_H__

/**
 * @brief Callback invoked when the network comes up.
 *
 * @param[in] user_data  Opaque user pointer passed at registration time.
 */
typedef void (*el2go_app_net_up_cb_t)(void *user_data);

/**
 * @brief Register a callback to be run when the network comes up.
 *
 * @param[in] cb         Callback to invoke on the network-up event. Must not
 *                       be NULL.
 * @param[in] user_data  Opaque pointer forwarded to cb. May be NULL.
 *
 * @return 0 on success, non-zero on failure.
 */
int el2go_ota_event_register_net_up(el2go_app_net_up_cb_t cb, void *user_data);

#endif /* __EL2GO_OTA_EVENT_H__ */

/** @} */ /* end of el2go_ota_event */
