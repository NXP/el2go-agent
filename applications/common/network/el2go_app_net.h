/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/**
 * @file el2go_app_net.h
 * @brief Network bring-up abstraction.
 *
 * Declares the interface used by the OTA agent to bring up the network
 * interface before connecting to the server. This header defines the generic
 * contract that every backend must honor; the symbols carry a weak default
 * (see el2go_app_net.c) so a build links without a concrete backend. Concrete
 * backends (see the zephyr/ Ethernet and Wi-Fi implementations) override the
 * weak definition to bring up a real interface.
 *
 * @defgroup el2go_app_net Network Bring-up Abstraction
 * @brief Network interface bring-up contract.
 * @{
 */

#ifndef __EL2GO_APP_NET_H__
#define __EL2GO_APP_NET_H__

/**
 * @brief Bring up the network interface.
 *
 * Configures and brings up the network interface, blocking until the
 * interface is connected before returning. Called once during agent startup
 * before the first server connection attempt. The weak default is a no-op
 * that reports success; a backend overrides it with the real bring-up.
 *
 * @return 0 on success, non-zero on failure.
 */
int el2go_app_net_init(void);

#endif /* __EL2GO_APP_NET_H__ */

/** @} */ /* end of el2go_app_net */
