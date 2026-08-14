/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
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

#include "el2go_ota_net.h"

LOG_MODULE_REGISTER(el2go_net_wifi, CONFIG_LOG_DEFAULT_LEVEL);

#define WIFI_CONNECT_TIMEOUT_S 60

static K_SEM_DEFINE(s_wifi_sem, 0, 1);
static K_SEM_DEFINE(s_ipv4_sem, 0, 1);

static struct net_mgmt_event_callback s_wifi_cb;
static struct net_mgmt_event_callback s_ipv4_cb;

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
            if (iface->config.ip.ipv4->unicast[i].ipv4.addr_type != NET_ADDR_DHCP)
                continue;
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

/* #define NET_WIFI_MAC { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } */

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

int el2go_ota_net_init(void)
{
    int ret;

    k_sleep(K_SECONDS(2));

    struct net_if *iface = net_if_get_wifi_sta();
    if (iface == NULL) {
        LOG_ERR("No WiFi interface found");
        return -ENODEV;
    }

    ret = set_mac_address(iface);
    if (ret)
        return ret;

    net_mgmt_init_event_callback(&s_wifi_cb, event_handler, NET_EVENT_WIFI_CONNECT_RESULT);
    net_mgmt_add_event_callback(&s_wifi_cb);

    net_mgmt_init_event_callback(&s_ipv4_cb, event_handler, NET_EVENT_IPV4_ADDR_ADD);
    net_mgmt_add_event_callback(&s_ipv4_cb);

    struct wifi_connect_req_params params = { 0 };
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
