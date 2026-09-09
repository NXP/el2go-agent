/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/* Network backend: Wi-Fi. Connects using the SSID and PSK from Kconfig
 * (CONFIG_EL2GO_NET_WIFI_SSID / CONFIG_EL2GO_NET_WIFI_PSK) and blocks
 * until a DHCP IPv4 address is bound. */

#include <zephyr/kernel.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/wifi_mgmt.h>
#include <zephyr/net/net_event.h>
#include <zephyr/net/ethernet_mgmt.h>
#include <zephyr/logging/log.h>

#include <string.h>

#include "el2go_app_net.h"

LOG_MODULE_REGISTER(network, CONFIG_LOG_DEFAULT_LEVEL);

#define WIFI_CONNECT_TIMEOUT_S 60

static K_SEM_DEFINE(s_wifi_sem, 0, 1);
static K_SEM_DEFINE(s_ipv4_sem, 0, 1);

static struct net_mgmt_event_callback s_wifi_cb;
static struct net_mgmt_event_callback s_ipv4_cb;

/**
 * @brief net_mgmt event handler for Wi-Fi connect and DHCP address events
 *
 * Signals s_wifi_sem once the Wi-Fi association succeeds and s_ipv4_sem once a
 * DHCP-assigned IPv4 address is added to the interface. Invoked in net_mgmt
 * context; keep the work minimal.
 *
 * @param[in] cb    net_mgmt callback whose info field carries the event payload
 * @param[in] event net_mgmt event identifier being reported
 * @param[in] iface Network interface the event relates to
 */
static void event_handler(struct net_mgmt_event_callback *cb, uint64_t event, struct net_if *iface)
{
    switch (event) {
    case NET_EVENT_WIFI_CONNECT_RESULT:
        if (((const struct wifi_status *)cb->info)->status) {
            LOG_WRN("WiFi connection failed");
            break;
        }
        LOG_INF("WiFi connected");
        k_sem_give(&s_wifi_sem);
        break;

    case NET_EVENT_IPV4_ADDR_ADD:
        if (iface->config.ip.ipv4 == NULL)
            break;
        for (int i = 0; i < NET_IF_MAX_IPV4_ADDR; i++) {
            if (iface->config.ip.ipv4->unicast[i].ipv4.addr_type != NET_ADDR_DHCP) {
                continue;
            }
            char buf[NET_IPV4_ADDR_LEN];
            net_addr_ntop(AF_INET, &iface->config.ip.ipv4->unicast[i].ipv4.address.in_addr, buf,
                          sizeof(buf));
            LOG_INF("DHCP address: %s", buf);
            k_sem_give(&s_ipv4_sem);
            break;
        }
        break;

    default:
        break;
    }
}

/* Fixed MAC address used for bench testing. */
/* #define NET_WIFI_MAC { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }  */

/**
 * @brief Applies the fixed test MAC address to the interface
 *
 * When NET_WIFI_MAC is defined, the interface is brought down, the MAC address
 * is set, and the interface is brought back up. A short settle delay follows.
 * When NET_WIFI_MAC is not defined this is a no-op.
 *
 * @param[in] iface Wi-Fi station interface to configure
 *
 * @retval 0 on success
 * @retval negative errno if setting the MAC address fails
 */
static int set_mac_address(struct net_if *iface)
{
#ifdef NET_WIFI_MAC
    static const uint8_t mac[6] = NET_WIFI_MAC;
    struct ethernet_req_params p = { 0 };
    memcpy(p.mac_address.addr, mac, sizeof(mac));
    net_if_down(iface);
    int ret = net_mgmt(NET_REQUEST_ETHERNET_SET_MAC_ADDRESS, iface, &p, sizeof(p));
    net_if_up(iface);
    if (ret) {
        LOG_ERR("Failed to set MAC: %d", ret);
        return ret;
    }
    k_sleep(K_SECONDS(2));
#else
    (void)iface;
#endif
    return 0;
}

/**
 * @copydoc el2go_app_net_init
 *
 * Wi-Fi backend. Locates the Wi-Fi station interface, applies the test MAC
 * address, registers net_mgmt callbacks, and issues a connect request using
 * the SSID and PSK from Kconfig. Blocks until both association and DHCP IPv4
 * assignment complete, each bounded by WIFI_CONNECT_TIMEOUT_S.
 *
 * @retval 0 once the interface is connected and has an IPv4 address
 * @retval -ENODEV if no Wi-Fi station interface is present
 * @retval -ETIMEDOUT if association or DHCP does not complete in time
 * @retval negative errno if the MAC setup or connect request fails
 */
int el2go_app_net_init(void)
{
    int ret = -1;
    struct net_if *iface = NULL;
    struct wifi_connect_req_params params = { 0 };

    k_sleep(K_SECONDS(2));

    iface = net_if_get_wifi_sta();
    if (iface == NULL) {
        LOG_ERR("No WiFi interface found");
        return -ENODEV;
    }

    ret = set_mac_address(iface);
    if (ret) {
        return ret;
    }

    net_mgmt_init_event_callback(&s_wifi_cb, event_handler, NET_EVENT_WIFI_CONNECT_RESULT);
    net_mgmt_add_event_callback(&s_wifi_cb);

    net_mgmt_init_event_callback(&s_ipv4_cb, event_handler, NET_EVENT_IPV4_ADDR_ADD);
    net_mgmt_add_event_callback(&s_ipv4_cb);

    params.ssid = CONFIG_EL2GO_NET_WIFI_SSID;
    params.ssid_length = strlen(CONFIG_EL2GO_NET_WIFI_SSID);
    params.psk = CONFIG_EL2GO_NET_WIFI_PSK;
    params.psk_length = strlen(CONFIG_EL2GO_NET_WIFI_PSK);

    params.band = WIFI_FREQ_BAND_UNKNOWN;
    params.channel = WIFI_CHANNEL_ANY;
    params.security = WIFI_SECURITY_TYPE_WPA_AUTO_PERSONAL;
    params.mfp = WIFI_MFP_OPTIONAL;
    params.timeout = WIFI_CONNECT_TIMEOUT_S;

    LOG_INF("Connecting to '%s' ...", CONFIG_EL2GO_NET_WIFI_SSID);
    ret = net_mgmt(NET_REQUEST_WIFI_CONNECT, iface, &params, sizeof(params));
    if (ret) {
        LOG_ERR("WiFi connect request failed: %d", ret);
        return ret;
    }

    if (k_sem_take(&s_wifi_sem, K_SECONDS(WIFI_CONNECT_TIMEOUT_S)) != 0) {
        LOG_ERR("WiFi connect timeout");
        return -ETIMEDOUT;
    }

    if (k_sem_take(&s_ipv4_sem, K_SECONDS(WIFI_CONNECT_TIMEOUT_S)) != 0) {
        LOG_ERR("DHCP timeout");
        return -ETIMEDOUT;
    }

    LOG_INF("Network ready");
    return 0;
}
