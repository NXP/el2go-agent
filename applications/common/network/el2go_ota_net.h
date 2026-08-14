/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef APPLICATIONS_COMMON_NETWORK_EL2GO_OTA_NET_H_
#define APPLICATIONS_COMMON_NETWORK_EL2GO_OTA_NET_H_

/**
 * @brief Initialize the network interface.
 *
 * Brings up the configured network backend (WiFi or Ethernet), waits for
 * a DHCP lease, and returns once the interface is ready for TCP/IP use.
 *
 * @return 0 on success, negative errno on failure.
 */
int el2go_ota_net_init(void);

#endif /* APPLICATIONS_COMMON_NETWORK_EL2GO_OTA_NET_H_ */
