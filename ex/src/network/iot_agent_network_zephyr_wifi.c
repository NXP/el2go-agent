/*
 * Copyright 2024 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <nxp_iot_agent_status.h>
#include <nxp_iot_agent_log.h>

#include <zephyr/kernel.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/wifi_mgmt.h>
#include <zephyr/net/net_event.h>

#ifndef AP_SSID
#define AP_SSID "WIFI SSID"
#endif

#ifndef AP_PASSWORD
#define AP_PASSWORD "WIFI Password"
#endif

#ifndef AP_CONNECT_TIMEOUT
#define AP_CONNECT_TIMEOUT 60
#endif

static K_SEM_DEFINE(connection, 0, 1);
static K_SEM_DEFINE(dhcp_address, 0, 1);

static struct net_mgmt_event_callback wifi_callback;
static struct net_mgmt_event_callback ipv4_callback;

static void net_mgmt_event_handler(struct net_mgmt_event_callback *callback, uint32_t event, struct net_if *interface)
{
    switch (event)
    {
        case NET_EVENT_WIFI_CONNECT_RESULT:
            if (((const struct wifi_status *)callback->info)->status)
            {
                IOT_AGENT_WARN("WIFI connection failed");
                break;
            }

            struct wifi_iface_status if_status = {0};
            if (net_mgmt(NET_REQUEST_WIFI_IFACE_STATUS, interface, &if_status, sizeof(if_status)))
            {
                IOT_AGENT_ERROR("WIFI status request failed");
                break;
            }

            IOT_AGENT_INFO("Using %s @ %s (Channel %d, %d dBm)", wifi_link_mode_txt(if_status.link_mode), wifi_band_txt(if_status.band), if_status.channel, if_status.rssi);

            k_sem_give(&connection);
            break;
        case NET_EVENT_IPV4_ADDR_ADD:
            for (int i = 0; i < NET_IF_MAX_IPV4_ADDR; i++)
            {
                if (interface->config.ip.ipv4->unicast[i].ipv4.addr_type != NET_ADDR_DHCP)
                {
                    continue;
                }

                char address_buffer[NET_IPV4_ADDR_LEN];
                net_addr_ntop(AF_INET, &interface->config.ip.ipv4->unicast[i].ipv4.address.in_addr, address_buffer, sizeof(address_buffer));

                char gw_buffer[NET_IPV4_ADDR_LEN];
                net_addr_ntop(AF_INET, &interface->config.ip.ipv4->gw, gw_buffer, sizeof(gw_buffer));

                IOT_AGENT_INFO("Using IPv4 address %s @ Gateway %s (DHCP)", address_buffer, gw_buffer);

                k_sem_give(&dhcp_address);
                break;
            }
            break;
        default:
            break;
    }
}

iot_agent_status_t network_init(void)
{
    // FIXME: Need to wait on Wi-FI driver, but waiting until IF is up does not work
    k_sleep(K_SECONDS(2));

    struct net_if *interface = net_if_get_wifi_sta();

    net_mgmt_init_event_callback(&wifi_callback, net_mgmt_event_handler, NET_EVENT_WIFI_CONNECT_RESULT);
    net_mgmt_add_event_callback(&wifi_callback);

    net_mgmt_init_event_callback(&ipv4_callback, net_mgmt_event_handler, NET_EVENT_IPV4_ADDR_ADD);
    net_mgmt_add_event_callback(&ipv4_callback);

    struct wifi_connect_req_params params = {0};

    params.ssid = AP_SSID;
    params.ssid_length = strlen(AP_SSID);
    params.psk = AP_PASSWORD;
    params.psk_length = strlen(AP_PASSWORD);
    params.band = WIFI_FREQ_BAND_UNKNOWN;
    params.channel = WIFI_CHANNEL_ANY;
    params.security = WIFI_SECURITY_TYPE_PSK;
    params.mfp = WIFI_MFP_OPTIONAL;
    params.timeout = AP_CONNECT_TIMEOUT;

    IOT_AGENT_INFO("Connecting to SSID '%s' ...", params.ssid);

    if (net_mgmt(NET_REQUEST_WIFI_CONNECT, interface, &params, sizeof(params)))
    {
        IOT_AGENT_ERROR("WIFI connection request failed");
        return IOT_AGENT_FAILURE;
    }

    if (k_sem_take(&connection, K_SECONDS(AP_CONNECT_TIMEOUT)) != 0) {
        IOT_AGENT_ERROR("WIFI connection timeout");
        return IOT_AGENT_FAILURE;
    }

    if (k_sem_take(&dhcp_address, K_SECONDS(AP_CONNECT_TIMEOUT)) != 0) {
        IOT_AGENT_ERROR("DHCP address timeout");
        return IOT_AGENT_FAILURE;
    }

    IOT_AGENT_INFO("Successfully connected to WIFI");

    return IOT_AGENT_SUCCESS;
}
